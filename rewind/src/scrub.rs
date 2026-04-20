// Copyright 2026 The rewind Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! PII scrubbing for captured traffic and stored snapshots.
//!
//! `ScrubConfig` is applied in two places:
//!   1. During capture (eBPF drain) — before events enter the ring buffer.
//!   2. Post-hoc via `rewind scrub src.rwd dst.rwd` — sanitize a stored snapshot
//!      before sharing, uploading, or archiving.
//!
//! Options:
//!   - `redact_headers`: header names replaced with `[REDACTED]`
//!   - `allow_paths`: HTTP/gRPC events not matching any prefix are dropped
//!   - `redact_body`: clear all request/response bodies
//!
//! Usage:
//!   rewind scrub incident.rwd clean.rwd
//!   rewind scrub incident.rwd clean.rwd --redact-body --allow-paths /api

use anyhow::Result;
use serde::Serialize;

use crate::cli::ScrubArgs;
use crate::store::snapshot::{Event, Snapshot};

/// Header names that carry credentials or session tokens by default.
pub const DEFAULT_REDACT_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
];

#[derive(Clone, Debug)]
pub struct ScrubConfig {
    redact_headers: Vec<String>, // all lowercase
    allow_paths: Vec<String>,
}

impl Default for ScrubConfig {
    fn default() -> Self {
        Self::new(&[], &[])
    }
}

impl ScrubConfig {
    /// Build a config from CLI-supplied lists.
    ///
    /// An empty `redact_headers` slice applies `DEFAULT_REDACT_HEADERS`.
    /// An empty `allow_paths` slice means all paths are kept.
    pub fn new(redact_headers: &[String], allow_paths: &[String]) -> Self {
        let redact_headers = if redact_headers.is_empty() {
            DEFAULT_REDACT_HEADERS
                .iter()
                .map(|s| s.to_string())
                .collect()
        } else {
            redact_headers
                .iter()
                .map(|h| h.to_ascii_lowercase())
                .collect()
        };
        Self {
            redact_headers,
            allow_paths: allow_paths.to_vec(),
        }
    }

    /// Returns `false` when a non-empty allow-list is configured and `path`
    /// doesn't start with any listed prefix.  Always returns `true` otherwise.
    pub fn path_allowed(&self, path: &str) -> bool {
        self.allow_paths.is_empty()
            || self
                .allow_paths
                .iter()
                .any(|prefix| path.starts_with(prefix.as_str()))
    }

    /// Replace the value of each matching header with `"[REDACTED]"`.
    pub fn scrub_headers(&self, headers: &mut [(String, String)]) {
        for (name, value) in headers.iter_mut() {
            if self.redact_headers.contains(&name.to_ascii_lowercase()) {
                *value = "[REDACTED]".to_string();
            }
        }
    }
}

// ── Post-hoc scrub command ────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ScrubReport {
    pub source: String,
    pub output: String,
    pub events_before: usize,
    pub events_after: usize,
    pub events_dropped: usize,
    pub headers_redacted: usize,
    pub bodies_cleared: usize,
}

pub async fn run(args: ScrubArgs) -> Result<()> {
    let key = crate::crypto::resolve_key(args.key);
    let mut snapshot = Snapshot::read(&args.snapshot, key.as_deref())?;

    let config = ScrubConfig::new(&args.redact_headers, &args.allow_paths);
    let report = apply_scrub(&mut snapshot, &config, args.redact_body);

    snapshot.write(&args.output, key.as_deref())?;

    let report = ScrubReport {
        source: args.snapshot.to_string_lossy().to_string(),
        output: args.output.to_string_lossy().to_string(),
        ..report
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_report(&report);
    }

    Ok(())
}

/// Apply scrubbing in-place to a snapshot's events.  Returns counts for reporting.
pub fn apply_scrub(
    snapshot: &mut Snapshot,
    config: &ScrubConfig,
    redact_body: bool,
) -> ScrubReport {
    let events_before = snapshot.events.len();
    let mut headers_redacted = 0usize;
    let mut bodies_cleared = 0usize;

    for event in snapshot.events.iter_mut() {
        if let Event::Http(h) = event {
            let before = h.headers.iter().filter(|(_, v)| v != "[REDACTED]").count();
            config.scrub_headers(&mut h.headers);
            let after = h.headers.iter().filter(|(_, v)| v != "[REDACTED]").count();
            headers_redacted += before - after;

            if redact_body && h.body.is_some() {
                h.body = None;
                bodies_cleared += 1;
            }
        }
    }

    // Drop HTTP/gRPC events whose paths are outside the allow-list.
    if !config.allow_paths.is_empty() {
        snapshot.events.retain(|e| match e {
            Event::Http(h) => config.path_allowed(&h.path),
            Event::Grpc(g) => config.path_allowed(&g.path),
            _ => true,
        });
    }

    let events_after = snapshot.events.len();
    ScrubReport {
        source: String::new(),
        output: String::new(),
        events_before,
        events_after,
        events_dropped: events_before - events_after,
        headers_redacted,
        bodies_cleared,
    }
}

fn print_report(r: &ScrubReport) {
    println!("rewind scrub");
    println!("  source: {}", r.source);
    println!("  output: {}", r.output);
    println!();
    println!("  events before:    {}", r.events_before);
    println!("  events after:     {}", r.events_after);
    if r.events_dropped > 0 {
        println!("  events dropped:   {} (path filter)", r.events_dropped);
    }
    if r.headers_redacted > 0 {
        println!("  headers redacted: {}", r.headers_redacted);
    }
    if r.bodies_cleared > 0 {
        println!("  bodies cleared:   {}", r.bodies_cleared);
    }
    println!();
    println!("✓ scrubbed snapshot written to {}", r.output);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::snapshot::{
        DbRecord, Event, GrpcRecord, HttpRecord, Snapshot, SyscallRecord,
    };

    fn make_snapshot(events: Vec<Event>) -> Snapshot {
        let mut s = Snapshot::new(vec!["api".to_string()]);
        s.events = events;
        s
    }

    fn http_ev(path: &str, headers: Vec<(String, String)>, body: Option<&str>) -> Event {
        Event::Http(HttpRecord {
            timestamp_ns: 1_000_000,
            direction: "inbound".to_string(),
            method: "GET".to_string(),
            path: path.to_string(),
            status_code: Some(200),
            service: "api".to_string(),
            trace_id: None,
            body: body.map(|s| s.to_string()),
            headers,
        })
    }

    fn grpc_ev(path: &str) -> Event {
        Event::Grpc(GrpcRecord {
            timestamp_ns: 1_000_000,
            path: path.to_string(),
            service: "api".to_string(),
            pid: 42,
        })
    }

    fn db_ev() -> Event {
        Event::Db(DbRecord {
            timestamp_ns: 1_001_000,
            protocol: "postgres".to_string(),
            query: "SELECT 1".to_string(),
            response: None,
            service: "api".to_string(),
            pid: 42,
        })
    }

    #[test]
    fn default_redacts_authorization() {
        let cfg = ScrubConfig::default();
        let mut headers = vec![
            ("Authorization".to_string(), "Bearer secret".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];
        cfg.scrub_headers(&mut headers);
        assert_eq!(headers[0].1, "[REDACTED]");
        assert_eq!(headers[1].1, "application/json");
    }

    #[test]
    fn default_redacts_cookie() {
        let cfg = ScrubConfig::default();
        let mut headers = vec![("Cookie".to_string(), "session=abc123".to_string())];
        cfg.scrub_headers(&mut headers);
        assert_eq!(headers[0].1, "[REDACTED]");
    }

    #[test]
    fn custom_list_overrides_defaults() {
        let cfg = ScrubConfig::new(&["x-custom".to_string()], &[]);
        let mut headers = vec![
            ("Authorization".to_string(), "Bearer secret".to_string()),
            ("x-custom".to_string(), "private".to_string()),
        ];
        cfg.scrub_headers(&mut headers);
        assert_eq!(headers[0].1, "Bearer secret");
        assert_eq!(headers[1].1, "[REDACTED]");
    }

    #[test]
    fn header_matching_is_case_insensitive() {
        let cfg = ScrubConfig::default();
        let mut headers = vec![("COOKIE".to_string(), "session=abc".to_string())];
        cfg.scrub_headers(&mut headers);
        assert_eq!(headers[0].1, "[REDACTED]");
    }

    #[test]
    fn allow_paths_empty_permits_all() {
        let cfg = ScrubConfig::default();
        assert!(cfg.path_allowed("/api/v1/users"));
        assert!(cfg.path_allowed("/internal/debug"));
    }

    #[test]
    fn allow_paths_filters_unmatched() {
        let cfg = ScrubConfig::new(&[], &["/api".to_string()]);
        assert!(cfg.path_allowed("/api/v1/users"));
        assert!(!cfg.path_allowed("/internal/debug"));
    }

    #[test]
    fn allow_paths_multi_prefix() {
        let cfg = ScrubConfig::new(&[], &["/api".to_string(), "/health".to_string()]);
        assert!(cfg.path_allowed("/health"));
        assert!(!cfg.path_allowed("/metrics"));
    }

    #[test]
    fn apply_scrub_redacts_auth_header() {
        let mut snap = make_snapshot(vec![http_ev(
            "/api",
            vec![("Authorization".to_string(), "Bearer tok".to_string())],
            None,
        )]);
        let cfg = ScrubConfig::default();
        let report = apply_scrub(&mut snap, &cfg, false);
        assert_eq!(report.headers_redacted, 1);
        if let Event::Http(h) = &snap.events[0] {
            assert_eq!(h.headers[0].1, "[REDACTED]");
        }
    }

    #[test]
    fn apply_scrub_clears_body_when_requested() {
        let mut snap = make_snapshot(vec![http_ev("/api", vec![], Some("sensitive"))]);
        let cfg = ScrubConfig::default();
        let report = apply_scrub(&mut snap, &cfg, true);
        assert_eq!(report.bodies_cleared, 1);
        if let Event::Http(h) = &snap.events[0] {
            assert!(h.body.is_none());
        }
    }

    #[test]
    fn apply_scrub_drops_http_outside_allow_paths() {
        let mut snap = make_snapshot(vec![
            http_ev("/api/users", vec![], None),
            http_ev("/internal/debug", vec![], None),
            db_ev(),
        ]);
        let cfg = ScrubConfig::new(&[], &["/api".to_string()]);
        let report = apply_scrub(&mut snap, &cfg, false);
        assert_eq!(report.events_dropped, 1);
        assert_eq!(snap.events.len(), 2); // /api/users + db event kept
    }

    #[test]
    fn apply_scrub_drops_grpc_outside_allow_paths() {
        let mut snap = make_snapshot(vec![
            grpc_ev("/pkg.Svc/PublicMethod"),
            grpc_ev("/internal.Debug/Dump"),
        ]);
        let cfg = ScrubConfig::new(&[], &["/pkg".to_string()]);
        let report = apply_scrub(&mut snap, &cfg, false);
        assert_eq!(report.events_dropped, 1);
    }

    #[test]
    fn apply_scrub_keeps_db_and_syscall_regardless_of_allow_paths() {
        let mut snap = make_snapshot(vec![
            db_ev(),
            Event::Syscall(SyscallRecord {
                timestamp_ns: 0,
                kind: "clock_gettime".to_string(),
                return_value: 123,
                pid: 1,
            }),
        ]);
        let cfg = ScrubConfig::new(&[], &["/api".to_string()]);
        let report = apply_scrub(&mut snap, &cfg, false);
        assert_eq!(report.events_dropped, 0);
        assert_eq!(snap.events.len(), 2);
    }

    #[test]
    fn apply_scrub_no_op_on_clean_snapshot() {
        let mut snap = make_snapshot(vec![http_ev("/api", vec![], None)]);
        let cfg = ScrubConfig::default();
        let report = apply_scrub(&mut snap, &cfg, false);
        assert_eq!(report.headers_redacted, 0);
        assert_eq!(report.bodies_cleared, 0);
        assert_eq!(report.events_dropped, 0);
    }
}
