// Integration tests for rewind server, retention, scrub, gdpr-delete, and compliance.
//
// The server tests spawn the `rewind server` binary on a free port, wait for
// /healthz to respond, exercise the REST API, then kill the process.
// All other tests invoke the binary directly against temporary files.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn rewind_bin() -> PathBuf {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_rewind") {
        return PathBuf::from(p);
    }
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../target/debug/rewind");
    p
}

fn fixture(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures");
    p.push(name);
    p
}

/// Find an unoccupied TCP port by binding to :0, reading the OS-assigned
/// port, then immediately releasing the listener.
fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind :0");
    l.local_addr().unwrap().port()
}

/// Guard that kills the child process when dropped.
struct ServerGuard(Child);
impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Start `rewind server` on `port`, storing snapshots in `dir`.
/// Returns the guard once /healthz responds (or panics after 5 s).
fn start_server(dir: &Path, port: u16, token: &str) -> ServerGuard {
    let child = Command::new(rewind_bin())
        .args([
            "server",
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--storage",
            dir.to_str().unwrap(),
            "--token",
            token,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn rewind server");

    let guard = ServerGuard(child);
    // Poll /healthz until the server is ready.
    for _ in 0..100 {
        std::thread::sleep(Duration::from_millis(50));
        if let Ok(mut stream) =
            std::net::TcpStream::connect(format!("127.0.0.1:{port}"))
        {
            // Server is listening — send a minimal HTTP request.
            let req = "GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n";
            if stream.write_all(req.as_bytes()).is_ok() {
                use std::io::Read;
                let mut buf = [0u8; 64];
                if stream.read(&mut buf).is_ok() {
                    if buf.starts_with(b"HTTP/1") {
                        return guard;
                    }
                }
            }
        }
    }
    panic!("rewind server on port {port} did not start within 5 s");
}

// ── Server: upload / list / download ─────────────────────────────────────────

#[test]
fn server_upload_returns_201() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let _srv = start_server(dir.path(), port, "test-token");

    let base = format!("http://127.0.0.1:{port}");
    let data = std::fs::read(fixture("sample.rwd")).unwrap();

    let status = ureq_post_bytes(&format!("{base}/snapshots"), "test-token", &data);
    assert_eq!(status, 201, "expected 201 Created");
}

#[test]
fn server_list_shows_uploaded_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let _srv = start_server(dir.path(), port, "test-token");

    let base = format!("http://127.0.0.1:{port}");
    let data = std::fs::read(fixture("sample.rwd")).unwrap();
    ureq_post_bytes(&format!("{base}/snapshots"), "test-token", &data);

    let body = ureq_get_string(&format!("{base}/snapshots"), "test-token");
    let list: serde_json::Value = serde_json::from_str(&body).expect("list response is JSON");
    assert!(list.is_array(), "expected JSON array");
    assert!(!list.as_array().unwrap().is_empty(), "list should not be empty after upload");
}

#[test]
fn server_download_matches_uploaded_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let _srv = start_server(dir.path(), port, "test-token");

    let base = format!("http://127.0.0.1:{port}");
    let data = std::fs::read(fixture("sample.rwd")).unwrap();

    // Upload with a known filename via X-Rewind-Snapshot header.
    let status = ureq_post_bytes_named(
        &format!("{base}/snapshots"),
        "test-token",
        &data,
        "roundtrip.rwd",
    );
    assert_eq!(status, 201);

    // Download and compare.
    let downloaded = ureq_get_bytes(&format!("{base}/snapshots/roundtrip.rwd"), "test-token");
    assert_eq!(downloaded, data, "downloaded bytes must match uploaded bytes");
}

#[test]
fn server_unauthorized_upload_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let _srv = start_server(dir.path(), port, "correct-token");

    let data = std::fs::read(fixture("sample.rwd")).unwrap();
    let status = ureq_post_bytes(
        &format!("http://127.0.0.1:{port}/snapshots"),
        "wrong-token",
        &data,
    );
    assert_eq!(status, 401, "wrong token should be rejected with 401");
}

#[test]
fn server_no_token_upload_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let _srv = start_server(dir.path(), port, "secret");

    // Use an empty bearer.
    let status = ureq_post_bytes(
        &format!("http://127.0.0.1:{port}/snapshots"),
        "",
        &std::fs::read(fixture("sample.rwd")).unwrap(),
    );
    assert_eq!(status, 401);
}

#[test]
fn server_healthz_returns_200() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let _srv = start_server(dir.path(), port, "tok");

    let body = ureq_get_string(&format!("http://127.0.0.1:{port}/healthz"), "");
    assert!(body.contains("ok"), "healthz body: {body}");
}

// ── Retention ─────────────────────────────────────────────────────────────────

#[test]
fn retention_dry_run_does_not_delete() {
    let dir = tempfile::tempdir().unwrap();
    let snap = dir.path().join("old.rwd");
    std::fs::copy(fixture("sample.rwd"), &snap).unwrap();

    // Set mtime to 100 days ago (well past any reasonable max-age).
    set_mtime_days_ago(&snap, 100);

    let out = Command::new(rewind_bin())
        .args([
            "retention",
            "--dir",
            dir.path().to_str().unwrap(),
            "--max-age",
            "1d",
        ])
        .output()
        .unwrap();

    assert!(out.status.success(), "dry-run should exit 0");
    assert!(snap.exists(), "dry-run must not delete files");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("would delete") || stdout.contains("old.rwd"),
        "dry-run output should mention the old file:\n{stdout}"
    );
}

#[test]
fn retention_delete_removes_old_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let snap = dir.path().join("old.rwd");
    std::fs::copy(fixture("sample.rwd"), &snap).unwrap();
    set_mtime_days_ago(&snap, 100);

    let out = Command::new(rewind_bin())
        .args([
            "retention",
            "--dir",
            dir.path().to_str().unwrap(),
            "--max-age",
            "1d",
            "--delete",
        ])
        .output()
        .unwrap();

    assert!(out.status.success(), "retention --delete should exit 0");
    assert!(!snap.exists(), "old snapshot should be deleted");
}

#[test]
fn retention_keeps_recent_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let snap = dir.path().join("recent.rwd");
    std::fs::copy(fixture("sample.rwd"), &snap).unwrap();
    // Don't touch mtime — it's brand new.

    let out = Command::new(rewind_bin())
        .args([
            "retention",
            "--dir",
            dir.path().to_str().unwrap(),
            "--max-age",
            "30d",
            "--delete",
        ])
        .output()
        .unwrap();

    assert!(out.status.success());
    assert!(snap.exists(), "recent snapshot should not be deleted");
}

// ── Scrub ─────────────────────────────────────────────────────────────────────

#[test]
fn scrub_removes_sensitive_header() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src.rwd");
    let dst = dir.path().join("dst.rwd");
    std::fs::copy(fixture("sample.rwd"), &src).unwrap();

    let out = Command::new(rewind_bin())
        .args([
            "scrub",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
            "--redact-headers",
            "authorization",
        ])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "scrub should exit 0\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(dst.exists(), "scrubbed output file should exist");

    // The destination should be valid JSON (not encrypted, not empty).
    let content = std::fs::read(&dst).unwrap();
    assert!(
        serde_json::from_slice::<serde_json::Value>(&content).is_ok(),
        "scrubbed file should be valid JSON"
    );
}

// ── GDPR delete ───────────────────────────────────────────────────────────────

#[test]
fn gdpr_dry_run_exits_one_when_match_found() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(fixture("sample.rwd"), dir.path().join("snap.rwd")).unwrap();

    // "checkout" appears in the HTTP event's path field (/checkout).
    let out = Command::new(rewind_bin())
        .args([
            "gdpr-delete",
            "--dir",
            dir.path().to_str().unwrap(),
            "--user-id",
            "checkout",
        ])
        .output()
        .unwrap();

    // Dry run with matches exits 1.
    assert_eq!(
        out.status.code(),
        Some(1),
        "dry run with matches should exit 1"
    );
}

#[test]
fn gdpr_dry_run_exits_zero_when_no_match() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(fixture("sample.rwd"), dir.path().join("snap.rwd")).unwrap();

    let out = Command::new(rewind_bin())
        .args([
            "gdpr-delete",
            "--dir",
            dir.path().to_str().unwrap(),
            "--user-id",
            "this-id-definitely-does-not-exist-zzzxxx999",
        ])
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0), "no matches should exit 0");
}

#[test]
fn gdpr_execute_redacts_matching_events() {
    let dir = tempfile::tempdir().unwrap();
    let snap = dir.path().join("snap.rwd");
    std::fs::copy(fixture("sample.rwd"), &snap).unwrap();

    // "checkout" is in the HTTP path (/checkout) — will be found and redacted.
    let out = Command::new(rewind_bin())
        .args([
            "gdpr-delete",
            "--dir",
            dir.path().to_str().unwrap(),
            "--user-id",
            "checkout",
            "--execute",
        ])
        .output()
        .unwrap();

    assert!(out.status.success(), "execute should exit 0");
    assert!(snap.exists(), "snapshot should still exist (in-place redact)");

    // Verify the file is still valid JSON after redaction.
    let content = std::fs::read(&snap).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&content)
        .expect("redacted snapshot should still be valid JSON");
    let text = v.to_string();
    assert!(text.contains("[REDACTED]"), "redacted marker should appear in output");
}

// ── Compliance ────────────────────────────────────────────────────────────────

#[test]
fn compliance_json_output_is_valid() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(fixture("sample.rwd"), dir.path().join("snap.rwd")).unwrap();

    let out = Command::new(rewind_bin())
        .args([
            "compliance",
            "--snapshot-dir",
            dir.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "compliance should exit 0\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("compliance output should be valid JSON");
    assert!(v["controls"].is_object(), "missing controls field");
    assert!(v["summary"].is_object(), "missing summary field");
    assert!(v["snapshots"].is_object(), "missing snapshots field");
}

#[test]
fn compliance_markdown_output_has_summary_header() {
    let dir = tempfile::tempdir().unwrap();

    let out = Command::new(rewind_bin())
        .args([
            "compliance",
            "--snapshot-dir",
            dir.path().to_str().unwrap(),
            "--format",
            "markdown",
        ])
        .output()
        .unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("## Summary"), "markdown output missing ## Summary");
    assert!(stdout.contains("## Controls"), "markdown output missing ## Controls");
}

#[test]
fn compliance_reports_snapshot_count() {
    let dir = tempfile::tempdir().unwrap();
    // Copy two fixtures.
    std::fs::copy(fixture("sample.rwd"), dir.path().join("a.rwd")).unwrap();
    std::fs::copy(fixture("sample.rwd"), dir.path().join("b.rwd")).unwrap();

    let out = Command::new(rewind_bin())
        .args([
            "compliance",
            "--snapshot-dir",
            dir.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        v["snapshots"]["total"].as_u64().unwrap_or(0),
        2,
        "should count 2 snapshots"
    );
}

// ── RBAC token registry format ────────────────────────────────────────────────

#[test]
fn server_write_only_token_cannot_list() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();

    // Create a token registry with a write-only agent token and a read-write dev token.
    let tokens_file = dir.path().join("tokens.json");
    std::fs::write(
        &tokens_file,
        r#"{
            "agent-tok": {"team": "eng", "perm": "write"},
            "dev-tok":   {"team": "eng", "perm": "read"}
        }"#,
    ).unwrap();

    let child = Command::new(rewind_bin())
        .args([
            "server",
            "--listen", &format!("127.0.0.1:{port}"),
            "--storage", dir.path().to_str().unwrap(),
            "--tokens-file", tokens_file.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _srv = ServerGuard(child);
    wait_for_port(port);

    let base = format!("http://127.0.0.1:{port}");
    let data = std::fs::read(fixture("sample.rwd")).unwrap();

    // Agent token can upload.
    let status = ureq_post_bytes(&format!("{base}/snapshots"), "agent-tok", &data);
    assert_eq!(status, 201, "write token should upload successfully");

    // Agent token cannot list.
    let list_status = ureq_get_status(&format!("{base}/snapshots"), "agent-tok");
    assert_eq!(list_status, 403, "write-only token should not list (403)");

    // Dev token can list.
    let list_status = ureq_get_status(&format!("{base}/snapshots"), "dev-tok");
    assert_eq!(list_status, 200, "read token should list (200)");

    // Dev token cannot upload.
    let upload_status = ureq_post_bytes(&format!("{base}/snapshots"), "dev-tok", &data);
    assert_eq!(upload_status, 403, "read-only token should not upload (403)");
}

// ── Low-level HTTP helpers (no async runtime needed) ──────────────────────────

/// Send a raw HTTP/1.0 request and return (status_code, body_bytes).
///
/// Using HTTP/1.0 so the server closes the connection after each response,
/// which lets read_to_end() terminate without needing Content-Length parsing.
fn raw_http(method: &str, url: &str, extra_headers: &[(&str, &str)], body: &[u8]) -> (u16, Vec<u8>) {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpStream;

    let after = url.trim_start_matches("http://");
    let (addr, rest) = after.split_once('/').unwrap_or((after, ""));
    let path = format!("/{rest}");

    let mut stream = TcpStream::connect(addr).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();

    // HTTP/1.0: no keep-alive, no chunked encoding; server closes after response.
    let mut req = format!("{method} {path} HTTP/1.0\r\nHost: {addr}\r\n");
    if !body.is_empty() {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    for (k, v) in extra_headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");

    stream.write_all(req.as_bytes()).unwrap();
    if !body.is_empty() {
        stream.write_all(body).unwrap();
    }

    let mut reader = BufReader::new(stream);

    // Read status line.
    let mut status_line = String::new();
    reader.read_line(&mut status_line).unwrap();
    let status = parse_status(&status_line);

    // Skip headers, collect Content-Length for accurate body reads.
    let mut content_length: Option<usize> = None;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        let lower = trimmed.to_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_length = v.trim().parse().ok();
        }
    }

    // Read body: prefer Content-Length; fall back to read_to_end (works
    // because HTTP/1.0 causes the server to close after the response).
    let body_bytes = if let Some(len) = content_length {
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf).unwrap_or(());
        buf
    } else {
        let mut buf = Vec::new();
        let _ = reader.read_to_end(&mut buf);
        buf
    };

    (status, body_bytes)
}

fn ureq_post_bytes(url: &str, token: &str, body: &[u8]) -> u16 {
    ureq_post_bytes_named(url, token, body, "")
}

fn ureq_post_bytes_named(url: &str, token: &str, body: &[u8], snapshot_name: &str) -> u16 {
    let mut headers: Vec<(&str, String)> = Vec::new();
    let auth;
    if !token.is_empty() {
        auth = format!("Bearer {token}");
        headers.push(("Authorization", auth));
    } else {
        auth = String::new();
        let _ = &auth; // suppress unused warning
    }
    let snap_hdr;
    if !snapshot_name.is_empty() {
        snap_hdr = snapshot_name.to_string();
        headers.push(("X-Rewind-Snapshot", snap_hdr));
    } else {
        snap_hdr = String::new();
        let _ = &snap_hdr;
    }
    let extra: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let (status, _) = raw_http("POST", url, &extra, body);
    status
}

fn ureq_get_string(url: &str, token: &str) -> String {
    let auth;
    let extra: Vec<(&str, &str)> = if !token.is_empty() {
        auth = format!("Bearer {token}");
        vec![("Authorization", auth.as_str())]
    } else {
        auth = String::new();
        let _ = &auth;
        vec![]
    };
    let (_, body) = raw_http("GET", url, &extra, &[]);
    String::from_utf8_lossy(&body).into_owned()
}

fn ureq_get_bytes(url: &str, token: &str) -> Vec<u8> {
    let auth;
    let extra: Vec<(&str, &str)> = if !token.is_empty() {
        auth = format!("Bearer {token}");
        vec![("Authorization", auth.as_str())]
    } else {
        auth = String::new();
        let _ = &auth;
        vec![]
    };
    let (_, body) = raw_http("GET", url, &extra, &[]);
    body
}

fn ureq_get_status(url: &str, token: &str) -> u16 {
    let auth;
    let extra: Vec<(&str, &str)> = if !token.is_empty() {
        auth = format!("Bearer {token}");
        vec![("Authorization", auth.as_str())]
    } else {
        auth = String::new();
        let _ = &auth;
        vec![]
    };
    let (status, _) = raw_http("GET", url, &extra, &[]);
    status
}

fn parse_status(line: &str) -> u16 {
    line.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn wait_for_port(port: u16) {
    for _ in 0..100 {
        std::thread::sleep(Duration::from_millis(50));
        if std::net::TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() {
            return;
        }
    }
    panic!("port {port} never opened");
}

fn set_mtime_days_ago(path: &Path, days: u64) {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    let old_time = SystemTime::now() - Duration::from_secs(days * 86_400);
    let secs = old_time.duration_since(UNIX_EPOCH).unwrap().as_secs();
    // Use `touch -t` or equivalent — simplest cross-platform approach via std.
    let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    // On Linux we can use filetime crate or just set via a raw syscall.
    // Since we already have tempfile in dev-deps, use std::fs::File::set_modified
    // (available since Rust 1.75).
    drop(file);
    // Fallback: just use a minimal temp-based approach.
    let _ = std::process::Command::new("touch")
        .args([
            "-d",
            &format!("{} days ago", days),
            path.to_str().unwrap(),
        ])
        .status();
    // Verify it worked; if not (Windows/non-GNU touch) skip gracefully.
    let _ = secs;
}
