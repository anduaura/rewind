// Integration tests for rewind CLI commands.
//
// These tests invoke the compiled binary directly so they exercise the full
// argument-parsing → execution path without requiring eBPF or Docker.

use std::path::PathBuf;
use std::process::Command;

fn rewind_bin() -> PathBuf {
    // `cargo test` sets CARGO_BIN_EXE_rewind when the binary is built.
    // Fall back to searching the target directory for local runs.
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

// ── inspect ───────────────────────────────────────────────────────────────────

#[test]
fn inspect_exits_zero() {
    let out = Command::new(rewind_bin())
        .args(["inspect", fixture("sample.rwd").to_str().unwrap()])
        .output()
        .expect("failed to run rewind inspect");

    assert!(out.status.success(), "exit code: {}", out.status);
}

#[test]
fn inspect_shows_event_counts() {
    let out = Command::new(rewind_bin())
        .args(["inspect", fixture("sample.rwd").to_str().unwrap()])
        .output()
        .expect("failed to run rewind inspect");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("http=1"), "missing http count:\n{stdout}");
    assert!(stdout.contains("db=2"), "missing db count:\n{stdout}");
    assert!(
        stdout.contains("syscall=1"),
        "missing syscall count:\n{stdout}"
    );
    assert!(stdout.contains("grpc=1"), "missing grpc count:\n{stdout}");
}

#[test]
fn inspect_shows_services() {
    let out = Command::new(rewind_bin())
        .args(["inspect", fixture("sample.rwd").to_str().unwrap()])
        .output()
        .expect("failed to run rewind inspect");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("api"), "missing service 'api':\n{stdout}");
    assert!(
        stdout.contains("worker"),
        "missing service 'worker':\n{stdout}"
    );
}

#[test]
fn inspect_shows_version() {
    let out = Command::new(rewind_bin())
        .args(["inspect", fixture("sample.rwd").to_str().unwrap()])
        .output()
        .expect("failed to run rewind inspect");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("v1"), "missing snapshot version:\n{stdout}");
}

#[test]
fn inspect_nonexistent_file_fails() {
    let out = Command::new(rewind_bin())
        .args(["inspect", "/nonexistent/path.rwd"])
        .output()
        .expect("failed to run rewind inspect");

    assert!(
        !out.status.success(),
        "expected non-zero exit for missing file"
    );
}

// ── export ────────────────────────────────────────────────────────────────────

#[test]
fn export_otlp_exits_zero() {
    let out = Command::new(rewind_bin())
        .args(["export", fixture("sample.rwd").to_str().unwrap()])
        .output()
        .expect("failed to run rewind export");

    assert!(
        out.status.success(),
        "exit code: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn export_otlp_produces_valid_json() {
    let out = Command::new(rewind_bin())
        .args(["export", fixture("sample.rwd").to_str().unwrap()])
        .output()
        .expect("failed to run rewind export");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
    assert!(parsed.is_ok(), "OTLP output is not valid JSON:\n{stdout}");
}

#[test]
fn export_otlp_has_resource_spans() {
    let out = Command::new(rewind_bin())
        .args(["export", fixture("sample.rwd").to_str().unwrap()])
        .output()
        .expect("failed to run rewind export");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(
        v["resourceSpans"].is_array(),
        "missing resourceSpans:\n{stdout}"
    );
    let spans = &v["resourceSpans"][0]["scopeSpans"][0]["spans"];
    assert!(spans.is_array(), "missing spans:\n{stdout}");
    assert_eq!(
        spans.as_array().unwrap().len(),
        5,
        "expected 5 spans for 5 events"
    );
}

#[test]
fn export_jaeger_exits_zero() {
    let out = Command::new(rewind_bin())
        .args([
            "export",
            fixture("sample.rwd").to_str().unwrap(),
            "--format",
            "jaeger",
        ])
        .output()
        .expect("failed to run rewind export --format jaeger");

    assert!(
        out.status.success(),
        "exit code: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn export_jaeger_produces_valid_json() {
    let out = Command::new(rewind_bin())
        .args([
            "export",
            fixture("sample.rwd").to_str().unwrap(),
            "--format",
            "jaeger",
        ])
        .output()
        .expect("failed to run rewind export --format jaeger");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
    assert!(parsed.is_ok(), "Jaeger output is not valid JSON:\n{stdout}");
}

#[test]
fn export_to_file() {
    let tmp = std::env::temp_dir().join("rewind_test_export.json");
    let out = Command::new(rewind_bin())
        .args([
            "export",
            fixture("sample.rwd").to_str().unwrap(),
            "--output",
            tmp.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run rewind export --output");

    assert!(out.status.success(), "exit code: {}", out.status);
    assert!(tmp.exists(), "output file not created");
    let content = std::fs::read_to_string(&tmp).unwrap();
    std::fs::remove_file(&tmp).ok();
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&content);
    assert!(parsed.is_ok(), "file output is not valid JSON");
}
