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

//! Timeline / sequence diagram generation.
//!
//! Converts a .rwd snapshot into a Mermaid sequence diagram or ASCII art,
//! showing the causal chain of inter-service calls during the incident.
//!
//! Usage:
//!   rewind timeline incident.rwd                     # Mermaid → stdout
//!   rewind timeline incident.rwd --format ascii
//!   rewind timeline incident.rwd --output flow.md
//!
//! Paste Mermaid output into any Markdown renderer (GitHub, Notion, Miro)
//! or preview at https://mermaid.live — no account required.

use anyhow::Result;
use std::collections::BTreeSet;
use std::fmt::Write as FmtWrite;

use crate::cli::TimelineArgs;
use crate::crypto;
use crate::store::snapshot::{Event, Snapshot};

pub async fn run(args: TimelineArgs) -> Result<()> {
    let snapshot = Snapshot::read(&args.snapshot, crypto::resolve_key(args.key).as_deref())?;

    let diagram = match args.format.as_str() {
        "ascii" => to_ascii(&snapshot),
        _ => to_mermaid(&snapshot),
    };

    match &args.output {
        Some(path) => {
            std::fs::write(path, &diagram)?;
            tracing::info!(path = %path.display(), format = args.format, "timeline written");
        }
        None => print!("{}", diagram),
    }
    Ok(())
}

// ── Mermaid ───────────────────────────────────────────────────────────────────

pub fn to_mermaid(snap: &Snapshot) -> String {
    let mut out = String::new();
    writeln!(out, "```mermaid").unwrap();
    out.push_str(&to_mermaid_inner(snap));
    writeln!(out, "```").unwrap();
    out
}

/// Returns the raw Mermaid `sequenceDiagram` block without markdown fences.
/// Use this for inline browser rendering via the Mermaid JS library.
pub fn to_mermaid_inner(snap: &Snapshot) -> String {
    let mut out = String::new();
    let messages = build_messages(snap);

    writeln!(out, "sequenceDiagram").unwrap();

    // Declare participants in encounter order so Mermaid renders them left→right.
    let mut seen: BTreeSet<String> = Default::default();
    for m in &messages {
        for actor in [&m.from, &m.to] {
            if seen.insert(actor.clone()) {
                writeln!(out, "    participant {}", sanitize_actor(actor)).unwrap();
            }
        }
    }

    if !messages.is_empty() {
        writeln!(out).unwrap();
    }

    for m in &messages {
        let arrow = if m.is_response { "-->>" } else { "->>" };
        let label = truncate(&m.label, 60);
        writeln!(
            out,
            "    {}{}{}: {}",
            sanitize_actor(&m.from),
            arrow,
            sanitize_actor(&m.to),
            label
        )
        .unwrap();
    }
    out
}

// ── ASCII ─────────────────────────────────────────────────────────────────────

pub fn to_ascii(snap: &Snapshot) -> String {
    let mut out = String::new();
    let messages = build_messages(snap);

    if messages.is_empty() {
        return "No inter-service messages found.\n".to_string();
    }

    writeln!(out, "Incident Timeline").unwrap();
    writeln!(out, "{}", "─".repeat(60)).unwrap();

    let mut prev_ts: Option<u64> = None;
    for m in &messages {
        if let Some(prev) = prev_ts {
            let delta_ms = m.timestamp_ns.saturating_sub(prev) / 1_000_000;
            if delta_ms > 0 {
                writeln!(out, "  +{}ms", delta_ms).unwrap();
            }
        }
        let arrow = if m.is_response { "<--" } else { "-->" };
        let label = truncate(&m.label, 50);
        writeln!(out, "  {} {} {}: {}", m.from, arrow, m.to, label).unwrap();
        prev_ts = Some(m.timestamp_ns);
    }

    writeln!(out, "{}", "─".repeat(60)).unwrap();
    out
}

// ── Message extraction ────────────────────────────────────────────────────────

struct Message {
    timestamp_ns: u64,
    from: String,
    to: String,
    label: String,
    is_response: bool,
}

fn build_messages(snap: &Snapshot) -> Vec<Message> {
    let mut messages: Vec<Message> = Vec::new();

    // Collect service names from the snapshot metadata for resolving "unknown".
    let services = &snap.services;
    let primary_service = services.first().cloned().unwrap_or_else(|| "service".into());

    for event in &snap.events {
        match event {
            Event::Http(h) => {
                let (from, to) = if h.direction == "inbound" {
                    // Inbound: external caller → this service
                    let caller = if h.service.is_empty() {
                        "client".to_string()
                    } else {
                        // The service received it, so "client" called it
                        "client".to_string()
                    };
                    let svc = if h.service.is_empty() {
                        primary_service.clone()
                    } else {
                        h.service.clone()
                    };
                    let is_response = h.status_code.is_some();
                    if is_response {
                        (svc, caller)
                    } else {
                        (caller, svc)
                    }
                } else {
                    // Outbound: this service → external dependency
                    let svc = if h.service.is_empty() {
                        primary_service.clone()
                    } else {
                        h.service.clone()
                    };
                    let is_response = h.status_code.is_some();
                    // Try to infer the target from the path (hostname-based routing is lost at eBPF level).
                    let target = infer_http_target(&h.path);
                    if is_response {
                        (target, svc)
                    } else {
                        (svc, target)
                    }
                };

                let label = if let Some(sc) = h.status_code {
                    format!("{} {}", sc, h.path)
                } else {
                    format!("{} {}", h.method, h.path)
                };

                messages.push(Message {
                    timestamp_ns: h.timestamp_ns,
                    from,
                    to,
                    label,
                    is_response: h.status_code.is_some(),
                });
            }

            Event::Db(d) => {
                let svc = if d.service.is_empty() {
                    primary_service.clone()
                } else {
                    d.service.clone()
                };
                let db = d.protocol.clone();
                let query = truncate(&d.query, 40);

                messages.push(Message {
                    timestamp_ns: d.timestamp_ns,
                    from: svc.clone(),
                    to: db.clone(),
                    label: query.clone(),
                    is_response: false,
                });

                if let Some(resp) = &d.response {
                    messages.push(Message {
                        timestamp_ns: d.timestamp_ns + 1,
                        from: db,
                        to: svc,
                        label: truncate(resp, 40),
                        is_response: true,
                    });
                }
            }

            Event::Grpc(g) => {
                let svc = if g.service.is_empty() {
                    primary_service.clone()
                } else {
                    g.service.clone()
                };
                let target = infer_grpc_target(&g.path);
                messages.push(Message {
                    timestamp_ns: g.timestamp_ns,
                    from: svc,
                    to: target,
                    label: g.path.clone(),
                    is_response: false,
                });
            }

            Event::Syscall(_) => {
                // Syscalls are internal — not meaningful in a sequence diagram.
            }
        }
    }

    // Sort by timestamp so the sequence is chronological.
    messages.sort_by_key(|m| m.timestamp_ns);
    messages
}

fn infer_http_target(path: &str) -> String {
    // If the path looks like it has a host prefix, extract it.
    if let Some(rest) = path.strip_prefix("http://").or_else(|| path.strip_prefix("https://")) {
        if let Some(host) = rest.split('/').next() {
            return host.to_string();
        }
    }
    "upstream".to_string()
}

fn infer_grpc_target(path: &str) -> String {
    // gRPC paths: "/package.ServiceName/Method" — use the service part.
    path.trim_start_matches('/')
        .split('/')
        .next()
        .and_then(|s| s.split('.').next_back())
        .unwrap_or("grpc")
        .to_string()
}

fn sanitize_actor(name: &str) -> String {
    // Mermaid actor names must not contain special chars.
    name.chars()
        .map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' })
        .collect()
}

fn truncate(s: &str, max: usize) -> String {
    let s = s.trim();
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

    fn fixture() -> Snapshot {
        Snapshot {
            version: 1,
            recorded_at_ns: 1_700_000_000_000_000_000,
            services: vec!["api".to_string()],
            events: vec![
                Event::Http(HttpRecord {
                    timestamp_ns: 100,
                    direction: "inbound".to_string(),
                    method: "POST".to_string(),
                    path: "/orders".to_string(),
                    status_code: None,
                    service: "api".to_string(),
                    trace_id: None,
                    body: None,
                    headers: vec![],
                }),
                Event::Db(DbRecord {
                    timestamp_ns: 200,
                    protocol: "postgres".to_string(),
                    query: "SELECT 1".to_string(),
                    response: Some("ok".to_string()),
                    service: "api".to_string(),
                    pid: 1,
                }),
                Event::Grpc(GrpcRecord {
                    timestamp_ns: 300,
                    path: "/inventory.Service/Check".to_string(),
                    service: "api".to_string(),
                    pid: 1,
                }),
                Event::Http(HttpRecord {
                    timestamp_ns: 400,
                    direction: "inbound".to_string(),
                    method: "POST".to_string(),
                    path: "/orders".to_string(),
                    status_code: Some(201),
                    service: "api".to_string(),
                    trace_id: None,
                    body: None,
                    headers: vec![],
                }),
                Event::Syscall(SyscallRecord {
                    timestamp_ns: 500,
                    kind: "clock_gettime".to_string(),
                    return_value: 0,
                    pid: 1,
                }),
            ],
        }
    }

    #[test]
    fn mermaid_starts_with_fence() {
        let snap = fixture();
        let md = to_mermaid(&snap);
        assert!(md.starts_with("```mermaid\nsequenceDiagram\n"));
        assert!(md.ends_with("```\n"));
    }

    #[test]
    fn mermaid_contains_participants() {
        let snap = fixture();
        let md = to_mermaid(&snap);
        assert!(md.contains("participant client"));
        assert!(md.contains("participant api"));
        assert!(md.contains("participant postgres"));
    }

    #[test]
    fn mermaid_contains_http_arrow() {
        let snap = fixture();
        let md = to_mermaid(&snap);
        assert!(md.contains("->>"));
        assert!(md.contains("POST /orders"));
    }

    #[test]
    fn mermaid_contains_db_query() {
        let snap = fixture();
        let md = to_mermaid(&snap);
        assert!(md.contains("SELECT 1"));
    }

    #[test]
    fn mermaid_contains_grpc() {
        let snap = fixture();
        let md = to_mermaid(&snap);
        // gRPC shows the path
        assert!(md.contains("inventory.Service/Check"));
    }

    #[test]
    fn mermaid_skips_syscalls() {
        let snap = fixture();
        let md = to_mermaid(&snap);
        assert!(!md.contains("clock_gettime"));
    }

    #[test]
    fn ascii_output_structure() {
        let snap = fixture();
        let asc = to_ascii(&snap);
        assert!(asc.contains("Incident Timeline"));
        assert!(asc.contains("-->"));
        assert!(asc.contains("POST /orders"));
        assert!(asc.contains("SELECT 1"));
    }

    #[test]
    fn ascii_empty_snapshot() {
        let snap = Snapshot {
            version: 1,
            recorded_at_ns: 0,
            services: vec![],
            events: vec![],
        };
        let asc = to_ascii(&snap);
        assert_eq!(asc, "No inter-service messages found.\n");
    }

    #[test]
    fn infer_http_target_plain_path() {
        assert_eq!(infer_http_target("/api/foo"), "upstream");
    }

    #[test]
    fn infer_http_target_full_url() {
        assert_eq!(
            infer_http_target("http://payments.svc/charge"),
            "payments.svc"
        );
    }

    #[test]
    fn infer_grpc_target_service_name() {
        assert_eq!(infer_grpc_target("/inventory.Service/Check"), "Service");
    }

    #[test]
    fn sanitize_actor_replaces_dots() {
        assert_eq!(sanitize_actor("a.b.c"), "a_b_c");
    }

    #[test]
    fn truncate_within_limit() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_over_limit() {
        let s = "a".repeat(100);
        let t = truncate(&s, 10);
        assert!(t.len() < 100);
        assert!(t.ends_with('…'));
    }
}
