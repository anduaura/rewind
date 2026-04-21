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

//! Incident report generation — converts a .rwd snapshot to a Markdown or
//! HTML document suitable for attaching to a post-mortem or sharing with
//! team members who don't have rewind installed.
//!
//! Usage:
//!   rewind report incident.rwd                     # Markdown to stdout
//!   rewind report incident.rwd --output report.md
//!   rewind report incident.rwd --format html --output report.html

use anyhow::Result;
use std::fmt::Write as FmtWrite;

use crate::cli::ReportArgs;
use crate::crypto;
use crate::store::snapshot::{Event, Snapshot};

pub async fn run(args: ReportArgs) -> Result<()> {
    let snapshot = Snapshot::read(&args.snapshot, crypto::resolve_key(args.key).as_deref())?;

    let report = match args.format.as_str() {
        "html" => to_html(&snapshot, &args.snapshot.to_string_lossy()),
        _ => to_markdown(&snapshot, &args.snapshot.to_string_lossy()),
    };

    match &args.output {
        Some(path) => {
            std::fs::write(path, &report)?;
            tracing::info!(
                path = %path.display(),
                format = args.format,
                "report written"
            );
        }
        None => print!("{}", report),
    }
    Ok(())
}

// ── Markdown ──────────────────────────────────────────────────────────────────

fn to_markdown(snap: &Snapshot, filename: &str) -> String {
    let mut out = String::new();
    let stats = Stats::from(snap);

    // Header
    writeln!(out, "# Incident Report: {filename}").unwrap();
    writeln!(out).unwrap();

    // Summary table
    writeln!(out, "## Summary").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "| Field | Value |").unwrap();
    writeln!(out, "|---|---|").unwrap();
    writeln!(out, "| Snapshot version | {} |", snap.version).unwrap();
    writeln!(
        out,
        "| Recorded at | {} |",
        format_ts_ns(snap.recorded_at_ns)
    )
    .unwrap();
    writeln!(out, "| Services | {} |", snap.services.join(", ")).unwrap();
    writeln!(out, "| Total events | {} |", stats.total).unwrap();
    writeln!(out, "| HTTP events | {} |", stats.http).unwrap();
    writeln!(out, "| DB events | {} |", stats.db).unwrap();
    writeln!(out, "| gRPC events | {} |", stats.grpc).unwrap();
    writeln!(out, "| Syscall events | {} |", stats.syscalls).unwrap();
    if let Some((first, last)) = stats.time_range_ns {
        let duration_ms = (last.saturating_sub(first)) / 1_000_000;
        writeln!(out, "| Time span | {}ms |", duration_ms).unwrap();
    }
    writeln!(out).unwrap();

    // HTTP section
    let http_events: Vec<_> = snap
        .events
        .iter()
        .filter_map(|e| if let Event::Http(h) = e { Some(h) } else { None })
        .collect();

    if !http_events.is_empty() {
        writeln!(out, "## HTTP Traffic").unwrap();
        writeln!(out).unwrap();
        writeln!(
            out,
            "| Time (ns) | Direction | Method | Path | Status | Service |"
        )
        .unwrap();
        writeln!(out, "|---|---|---|---|---|---|").unwrap();
        for h in &http_events {
            let status = h
                .status_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "—".to_string());
            writeln!(
                out,
                "| {} | {} | `{}` | `{}` | {} | {} |",
                h.timestamp_ns, h.direction, h.method, h.path, status, h.service
            )
            .unwrap();
        }
        writeln!(out).unwrap();

        // Error responses
        let errors: Vec<_> = http_events
            .iter()
            .filter(|h| h.status_code.map(|s| s >= 400).unwrap_or(false))
            .collect();
        if !errors.is_empty() {
            writeln!(out, "### Error Responses").unwrap();
            writeln!(out).unwrap();
            for h in errors {
                writeln!(
                    out,
                    "- **{}** `{} {}` from `{}`",
                    h.status_code.unwrap_or(0),
                    h.method,
                    h.path,
                    h.service
                )
                .unwrap();
            }
            writeln!(out).unwrap();
        }
    }

    // DB section
    let db_events: Vec<_> = snap
        .events
        .iter()
        .filter_map(|e| if let Event::Db(d) = e { Some(d) } else { None })
        .collect();

    if !db_events.is_empty() {
        writeln!(out, "## Database Queries").unwrap();
        writeln!(out).unwrap();
        writeln!(out, "| Time (ns) | Protocol | Query | Service |").unwrap();
        writeln!(out, "|---|---|---|---|").unwrap();
        for d in &db_events {
            let query = truncate(&d.query, 80);
            writeln!(
                out,
                "| {} | {} | `{}` | {} |",
                d.timestamp_ns, d.protocol, query, d.service
            )
            .unwrap();
        }
        writeln!(out).unwrap();
    }

    // gRPC section
    let grpc_events: Vec<_> = snap
        .events
        .iter()
        .filter_map(|e| {
            if let Event::Grpc(g) = e {
                Some(g)
            } else {
                None
            }
        })
        .collect();

    if !grpc_events.is_empty() {
        writeln!(out, "## gRPC Calls").unwrap();
        writeln!(out).unwrap();
        writeln!(out, "| Time (ns) | Path | Service |").unwrap();
        writeln!(out, "|---|---|---|").unwrap();
        for g in &grpc_events {
            writeln!(out, "| {} | `{}` | {} |", g.timestamp_ns, g.path, g.service).unwrap();
        }
        writeln!(out).unwrap();
    }

    // Syscall section
    let syscall_events: Vec<_> = snap
        .events
        .iter()
        .filter_map(|e| {
            if let Event::Syscall(s) = e {
                Some(s)
            } else {
                None
            }
        })
        .collect();

    if !syscall_events.is_empty() {
        writeln!(out, "## Syscalls").unwrap();
        writeln!(out).unwrap();

        // Count by kind
        let mut counts: std::collections::BTreeMap<&str, usize> = Default::default();
        for s in &syscall_events {
            *counts.entry(s.kind.as_str()).or_default() += 1;
        }
        writeln!(out, "| Syscall | Count |").unwrap();
        writeln!(out, "|---|---|").unwrap();
        for (kind, count) in &counts {
            writeln!(out, "| `{}` | {} |", kind, count).unwrap();
        }
        writeln!(out).unwrap();
    }

    // Footer
    writeln!(out, "---").unwrap();
    writeln!(out, "*Generated by [rewind](https://github.com/anduaura/rewind)*")
        .unwrap();

    out
}

// ── HTML ──────────────────────────────────────────────────────────────────────

fn to_html(snap: &Snapshot, filename: &str) -> String {
    let md = to_markdown(snap, filename);
    // Wrap the markdown in a minimal HTML shell with inline CSS for readability.
    // We convert just the structural parts rather than pulling in a full MD parser.
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Incident Report: {filename}</title>
<style>
  body {{ font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
          max-width: 960px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }}
  h1,h2,h3 {{ border-bottom: 1px solid #e0e0e0; padding-bottom: .3em; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1em 0; font-size: .9em; }}
  th,td {{ border: 1px solid #d0d0d0; padding: .4em .7em; text-align: left; }}
  th {{ background: #f5f5f5; }}
  code {{ background: #f0f0f0; padding: .1em .3em; border-radius: 3px; font-size: .9em; }}
  pre {{ background: #f0f0f0; padding: 1em; overflow-x: auto; border-radius: 4px; }}
  hr {{ border: none; border-top: 1px solid #e0e0e0; }}
  .badge-4xx {{ color: #b00; font-weight: bold; }}
  .badge-5xx {{ color: #d00; font-weight: bold; }}
</style>
</head>
<body>
<pre>{}</pre>
</body>
</html>"#,
        html_escape(&md)
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ── Helpers ───────────────────────────────────────────────────────────────────

struct Stats {
    total: usize,
    http: usize,
    db: usize,
    grpc: usize,
    syscalls: usize,
    time_range_ns: Option<(u64, u64)>,
}

impl Stats {
    fn from(snap: &Snapshot) -> Self {
        let mut http = 0usize;
        let mut db = 0usize;
        let mut grpc = 0usize;
        let mut syscalls = 0usize;
        let mut min_ts = u64::MAX;
        let mut max_ts = 0u64;

        for ev in &snap.events {
            let ts = match ev {
                Event::Http(h) => {
                    http += 1;
                    h.timestamp_ns
                }
                Event::Db(d) => {
                    db += 1;
                    d.timestamp_ns
                }
                Event::Grpc(g) => {
                    grpc += 1;
                    g.timestamp_ns
                }
                Event::Syscall(s) => {
                    syscalls += 1;
                    s.timestamp_ns
                }
            };
            if ts < min_ts {
                min_ts = ts;
            }
            if ts > max_ts {
                max_ts = ts;
            }
        }

        let time_range_ns = if min_ts <= max_ts && !snap.events.is_empty() {
            Some((min_ts, max_ts))
        } else {
            None
        };

        Stats {
            total: snap.events.len(),
            http,
            db,
            grpc,
            syscalls,
            time_range_ns,
        }
    }
}

fn format_ts_ns(ns: u64) -> String {
    // Approximate ISO-8601 from nanoseconds since Unix epoch.
    let mut secs = ns / 1_000_000_000;
    let s = secs % 60;
    secs /= 60;
    let mi = secs % 60;
    secs /= 60;
    let h = secs % 24;
    secs /= 24;
    let year = 1970 + secs / 365;
    let doy = secs % 365;
    let mo = doy / 30 + 1;
    let d = doy % 30 + 1;
    format!("{year:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::snapshot::{DbRecord, GrpcRecord, HttpRecord, Snapshot, SyscallRecord};

    fn fixture_snapshot() -> Snapshot {
        Snapshot {
            version: 1,
            recorded_at_ns: 1_700_000_000_000_000_000,
            services: vec!["api".to_string(), "worker".to_string()],
            events: vec![
                Event::Http(HttpRecord {
                    timestamp_ns: 1_700_000_001_000_000_000,
                    direction: "inbound".to_string(),
                    method: "POST".to_string(),
                    path: "/api/orders".to_string(),
                    status_code: Some(500),
                    service: "api".to_string(),
                    trace_id: None,
                    body: None,
                    headers: vec![],
                }),
                Event::Db(DbRecord {
                    timestamp_ns: 1_700_000_001_100_000_000,
                    protocol: "postgres".to_string(),
                    query: "SELECT * FROM orders WHERE id = $1".to_string(),
                    response: Some("1 row".to_string()),
                    service: "api".to_string(),
                    pid: 42,
                }),
                Event::Grpc(GrpcRecord {
                    timestamp_ns: 1_700_000_001_200_000_000,
                    path: "/inventory.Service/Check".to_string(),
                    service: "worker".to_string(),
                    pid: 43,
                }),
                Event::Syscall(SyscallRecord {
                    timestamp_ns: 1_700_000_001_300_000_000,
                    kind: "clock_gettime".to_string(),
                    return_value: 0,
                    pid: 42,
                }),
            ],
        }
    }

    #[test]
    fn markdown_contains_summary() {
        let snap = fixture_snapshot();
        let md = to_markdown(&snap, "test.rwd");
        assert!(md.contains("# Incident Report: test.rwd"));
        assert!(md.contains("## Summary"));
        assert!(md.contains("api, worker"));
        assert!(md.contains("Total events | 4"));
        assert!(md.contains("HTTP events | 1"));
        assert!(md.contains("DB events | 1"));
    }

    #[test]
    fn markdown_http_section() {
        let snap = fixture_snapshot();
        let md = to_markdown(&snap, "test.rwd");
        assert!(md.contains("## HTTP Traffic"));
        assert!(md.contains("POST"));
        assert!(md.contains("/api/orders"));
        assert!(md.contains("500"));
    }

    #[test]
    fn markdown_error_section() {
        let snap = fixture_snapshot();
        let md = to_markdown(&snap, "test.rwd");
        assert!(md.contains("### Error Responses"));
        assert!(md.contains("**500**"));
    }

    #[test]
    fn markdown_db_section() {
        let snap = fixture_snapshot();
        let md = to_markdown(&snap, "test.rwd");
        assert!(md.contains("## Database Queries"));
        assert!(md.contains("postgres"));
        assert!(md.contains("SELECT * FROM orders"));
    }

    #[test]
    fn markdown_grpc_section() {
        let snap = fixture_snapshot();
        let md = to_markdown(&snap, "test.rwd");
        assert!(md.contains("## gRPC Calls"));
        assert!(md.contains("/inventory.Service/Check"));
    }

    #[test]
    fn markdown_syscall_section() {
        let snap = fixture_snapshot();
        let md = to_markdown(&snap, "test.rwd");
        assert!(md.contains("## Syscalls"));
        assert!(md.contains("clock_gettime"));
    }

    #[test]
    fn html_wraps_markdown() {
        let snap = fixture_snapshot();
        let html = to_html(&snap, "test.rwd");
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("Incident Report: test.rwd"));
        assert!(html.contains("<pre>"));
        assert!(html.contains("</body>"));
    }

    #[test]
    fn truncate_long_string() {
        let s = "a".repeat(100);
        let t = truncate(&s, 10);
        assert!(t.len() < s.len());
        assert!(t.ends_with('…'));
    }

    #[test]
    fn truncate_short_string() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn format_ts_ns_epoch() {
        let s = format_ts_ns(0);
        assert!(s.starts_with("1970-"));
    }

    #[test]
    fn stats_empty_snapshot() {
        let snap = Snapshot {
            version: 1,
            recorded_at_ns: 0,
            services: vec![],
            events: vec![],
        };
        let stats = Stats::from(&snap);
        assert_eq!(stats.total, 0);
        assert!(stats.time_range_ns.is_none());
    }
}
