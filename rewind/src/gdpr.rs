//! GDPR / data-subject deletion — `rewind gdpr-delete`.
//!
//! Scans a directory of `.rwd` snapshots and redacts or deletes all events
//! that contain a matching user identifier.  Matching is performed against
//! every text field in each event:
//!
//!   HTTP events  — URL path, query string, headers (names + values), body
//!   DB events    — query string, response text
//!   gRPC events  — RPC path
//!
//! By default the command performs a **dry run** and prints what it would
//! change without touching disk.  Pass `--delete-snapshots` to remove entire
//! snapshots that contain matches; omit it to redact in place.
//!
//! # Example
//!   rewind gdpr-delete --dir /var/rewind/snapshots --user-id user-42
//!   rewind gdpr-delete --dir /var/rewind/snapshots --user-id user-42 --execute

use anyhow::{Context, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};

use crate::cli::GdprDeleteArgs;
use crate::crypto;
use crate::store::snapshot::{DbRecord, Event, GrpcRecord, HttpRecord, Snapshot};

// ── Report types ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct GdprReport {
    pub dry_run: bool,
    pub user_id: String,
    pub snapshots_scanned: usize,
    pub snapshots_matched: usize,
    pub snapshots_modified: usize,
    pub snapshots_deleted: usize,
    pub events_redacted: usize,
    pub files: Vec<FileResult>,
}

#[derive(Debug, Serialize)]
pub struct FileResult {
    pub path: String,
    pub matched: bool,
    pub events_redacted: usize,
    pub action: FileAction,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FileAction {
    NoMatch,
    Redacted,
    Deleted,
    DryRunWouldRedact,
    DryRunWouldDelete,
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn run(args: GdprDeleteArgs) -> Result<()> {
    let report = scan(&args).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_report(&report);
    }

    // Exit 1 if any matches found in dry-run mode so CI can detect leaks.
    if report.dry_run && report.snapshots_matched > 0 {
        std::process::exit(1);
    }
    Ok(())
}

async fn scan(args: &GdprDeleteArgs) -> Result<GdprReport> {
    let mut files: Vec<FileResult> = Vec::new();
    let mut total_matched = 0usize;
    let mut total_modified = 0usize;
    let mut total_deleted = 0usize;
    let mut total_redacted = 0usize;
    let key = crypto::resolve_key(args.key.clone());

    let rwd_files = collect_rwd_files(&args.dir).await?;

    for path in rwd_files {
        let result = process_file(
            &path,
            &args.user_id,
            key.as_deref(),
            args.execute,
            args.delete_snapshots,
        )
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("skipping {}: {e}", path.display());
            FileResult {
                path: path.display().to_string(),
                matched: false,
                events_redacted: 0,
                action: FileAction::NoMatch,
            }
        });

        if result.matched {
            total_matched += 1;
        }
        total_redacted += result.events_redacted;
        match &result.action {
            FileAction::Redacted | FileAction::DryRunWouldRedact => {
                if result.action == FileAction::Redacted {
                    total_modified += 1;
                }
            }
            FileAction::Deleted | FileAction::DryRunWouldDelete => {
                if result.action == FileAction::Deleted {
                    total_deleted += 1;
                }
            }
            FileAction::NoMatch => {}
        }
        files.push(result);
    }

    Ok(GdprReport {
        dry_run: !args.execute,
        user_id: args.user_id.clone(),
        snapshots_scanned: files.len(),
        snapshots_matched: total_matched,
        snapshots_modified: total_modified,
        snapshots_deleted: total_deleted,
        events_redacted: total_redacted,
        files,
    })
}

// ── Per-file processing ───────────────────────────────────────────────────────

async fn process_file(
    path: &Path,
    user_id: &str,
    key: Option<&str>,
    execute: bool,
    delete_snapshots: bool,
) -> Result<FileResult> {
    let mut snapshot =
        Snapshot::read(path, key).with_context(|| format!("reading {}", path.display()))?;

    let (matched_events, redacted) = redact_snapshot(&mut snapshot, user_id);

    if matched_events == 0 {
        return Ok(FileResult {
            path: path.display().to_string(),
            matched: false,
            events_redacted: 0,
            action: FileAction::NoMatch,
        });
    }

    let action = if delete_snapshots {
        if execute {
            tokio::fs::remove_file(path)
                .await
                .with_context(|| format!("deleting {}", path.display()))?;
            // Also remove manifest if present.
            let manifest = path.with_extension("rwd.sha256");
            let _ = tokio::fs::remove_file(&manifest).await;
            FileAction::Deleted
        } else {
            FileAction::DryRunWouldDelete
        }
    } else if execute {
        snapshot
            .write(path, key)
            .with_context(|| format!("writing {}", path.display()))?;
        // Invalidate any existing manifest (redacted content changes the hash).
        let manifest = path.with_extension("rwd.sha256");
        let _ = tokio::fs::remove_file(&manifest).await;
        FileAction::Redacted
    } else {
        FileAction::DryRunWouldRedact
    };

    Ok(FileResult {
        path: path.display().to_string(),
        matched: true,
        events_redacted: redacted,
        action,
    })
}

// ── Redaction logic ───────────────────────────────────────────────────────────

/// Mutates all text fields in `snapshot` that contain `user_id`, replacing
/// exact occurrences with `[REDACTED]`.
/// Returns (events that contained a match, total field substitutions).
fn redact_snapshot(snapshot: &mut Snapshot, user_id: &str) -> (usize, usize) {
    let mut matched_events = 0usize;
    let mut total_replacements = 0usize;

    for event in &mut snapshot.events {
        let (hit, subs) = redact_event(event, user_id);
        if hit {
            matched_events += 1;
            total_replacements += subs;
        }
    }
    (matched_events, total_replacements)
}

fn redact_event(event: &mut Event, user_id: &str) -> (bool, usize) {
    match event {
        Event::Http(r) => redact_http(r, user_id),
        Event::Db(r) => redact_db(r, user_id),
        Event::Grpc(r) => redact_grpc(r, user_id),
        Event::Syscall(_) => (false, 0),
    }
}

fn redact_http(r: &mut HttpRecord, user_id: &str) -> (bool, usize) {
    let mut subs = 0usize;
    subs += replace_in(&mut r.path, user_id);
    subs += replace_in(&mut r.method, user_id);
    if let Some(trace) = &mut r.trace_id {
        subs += replace_in(trace, user_id);
    }
    if let Some(body) = &mut r.body {
        subs += replace_in(body, user_id);
    }
    for (name, value) in &mut r.headers {
        subs += replace_in(name, user_id);
        subs += replace_in(value, user_id);
    }
    (subs > 0, subs)
}

fn redact_db(r: &mut DbRecord, user_id: &str) -> (bool, usize) {
    let mut subs = 0usize;
    subs += replace_in(&mut r.query, user_id);
    if let Some(resp) = &mut r.response {
        subs += replace_in(resp, user_id);
    }
    (subs > 0, subs)
}

fn redact_grpc(r: &mut GrpcRecord, user_id: &str) -> (bool, usize) {
    let subs = replace_in(&mut r.path, user_id);
    (subs > 0, subs)
}

fn replace_in(s: &mut String, needle: &str) -> usize {
    if !s.contains(needle) {
        return 0;
    }
    let count = s.matches(needle).count();
    *s = s.replace(needle, "[REDACTED]");
    count
}

// ── Filesystem helpers ────────────────────────────────────────────────────────

async fn collect_rwd_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_recursive(dir, &mut files).await;
    files.sort();
    Ok(files)
}

async fn collect_recursive(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(d) => d,
        Err(_) => return,
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path.is_dir() {
            Box::pin(collect_recursive(&path, out)).await;
        } else if path.extension().map(|e| e == "rwd").unwrap_or(false) {
            out.push(path);
        }
    }
}

// ── Console output ────────────────────────────────────────────────────────────

fn print_report(r: &GdprReport) {
    let mode = if r.dry_run { "dry run" } else { "execute" };
    println!("rewind gdpr-delete [{mode}]");
    println!("  user-id:  {}", r.user_id);
    println!("  scanned:  {} snapshots", r.snapshots_scanned);
    println!("  matched:  {} snapshots", r.snapshots_matched);
    if r.dry_run {
        if r.snapshots_matched > 0 {
            println!("  action:   would redact {} event(s) across {} snapshot(s)",
                r.events_redacted, r.snapshots_matched);
        } else {
            println!("  action:   no matches found");
        }
    } else {
        println!("  redacted: {} snapshots ({} events)", r.snapshots_modified, r.events_redacted);
        println!("  deleted:  {} snapshots", r.snapshots_deleted);
    }
    if r.snapshots_matched > 0 {
        println!();
        for f in &r.files {
            if f.matched {
                println!("  {:?}  {} ({} substitutions)", f.action, f.path, f.events_redacted);
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::snapshot::{HttpRecord, SyscallRecord};

    fn http_event(path: &str, body: Option<&str>) -> Event {
        Event::Http(HttpRecord {
            timestamp_ns: 0,
            direction: "inbound".to_string(),
            method: "GET".to_string(),
            path: path.to_string(),
            status_code: Some(200),
            service: "api".to_string(),
            trace_id: None,
            body: body.map(|s| s.to_string()),
            headers: vec![("x-user-id".to_string(), "user-42".to_string())],
        })
    }

    fn db_event(query: &str) -> Event {
        Event::Db(DbRecord {
            timestamp_ns: 0,
            protocol: "postgres".to_string(),
            query: query.to_string(),
            response: None,
            service: "api".to_string(),
            pid: 1,
        })
    }

    fn syscall_event() -> Event {
        Event::Syscall(SyscallRecord {
            timestamp_ns: 0,
            kind: "clock_gettime".to_string(),
            return_value: 0,
            pid: 1,
        })
    }

    #[test]
    fn replace_in_substitutes_all_occurrences() {
        let mut s = "user-42 accessed /users/user-42/profile".to_string();
        let count = replace_in(&mut s, "user-42");
        assert_eq!(count, 2);
        assert_eq!(s, "[REDACTED] accessed /users/[REDACTED]/profile");
    }

    #[test]
    fn replace_in_no_match_returns_zero() {
        let mut s = "no match here".to_string();
        let count = replace_in(&mut s, "user-42");
        assert_eq!(count, 0);
    }

    #[test]
    fn redact_http_event_matches_path_and_headers() {
        let mut event = http_event("/users/user-42/orders", None);
        let (hit, subs) = redact_event(&mut event, "user-42");
        assert!(hit);
        assert!(subs >= 2); // path + header value
        if let Event::Http(r) = &event {
            assert!(r.path.contains("[REDACTED]"));
            assert!(r.headers[0].1.contains("[REDACTED]"));
        }
    }

    #[test]
    fn redact_http_event_no_match() {
        let mut event = http_event("/health", None);
        let (hit, subs) = redact_event(&mut event, "user-99");
        // header still has "user-42" which != "user-99"
        assert!(!hit || subs == 0 || !hit);
        // more precisely: user-99 not in path, not in header value "user-42"
        let (h, s) = redact_event(&mut event, "user-99");
        let _ = (h, s); // just ensure it compiles
    }

    #[test]
    fn redact_db_event() {
        let mut event = db_event("SELECT * FROM orders WHERE user_id = 'user-42'");
        let (hit, subs) = redact_event(&mut event, "user-42");
        assert!(hit);
        assert_eq!(subs, 1);
        if let Event::Db(r) = &event {
            assert!(r.query.contains("[REDACTED]"));
        }
    }

    #[test]
    fn syscall_events_never_match() {
        let mut event = syscall_event();
        let (hit, _) = redact_event(&mut event, "user-42");
        assert!(!hit);
    }

    #[test]
    fn snapshot_redaction_counts_correctly() {
        let mut snap = Snapshot::new(vec!["api".to_string()]);
        snap.events.push(http_event("/users/user-42", None));
        snap.events.push(db_event("SELECT 1"));
        snap.events.push(http_event("/health", None));

        let (matched, subs) = redact_snapshot(&mut snap, "user-42");
        assert_eq!(matched, 2); // http + header in first; header in third
        assert!(subs >= 2);
    }

    #[test]
    fn report_serialises_to_json() {
        let report = GdprReport {
            dry_run: true,
            user_id: "user-42".to_string(),
            snapshots_scanned: 5,
            snapshots_matched: 2,
            snapshots_modified: 0,
            snapshots_deleted: 0,
            events_redacted: 3,
            files: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"dry_run\":true"));
        assert!(json.contains("\"user_id\":\"user-42\""));
    }
}
