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

//! Slack / generic webhook notifications after a flush or capture.
//!
//! Sends a structured alert to a Slack Incoming Webhook (or any HTTP endpoint
//! accepting JSON) with a snapshot summary: services captured, event counts,
//! and the first few steps of the inter-service timeline.
//!
//! Typical usage — run immediately after `rewind flush`:
//!
//!   rewind flush --window 5m --output incident.rwd && \
//!     rewind notify incident.rwd --slack-url "$SLACK_WEBHOOK_URL"
//!
//! Or wire into the auto-trigger webhook:
//!
//!   rewind webhook --listen 0.0.0.0:9091 --slack-url "$SLACK_WEBHOOK_URL"
//!
//! Environment variable: REWIND_SLACK_URL (avoids putting the URL in shell history)

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::cli::NotifyArgs;
use crate::crypto;
use crate::store::snapshot::{Event, Snapshot};
use crate::timeline::to_mermaid;

pub async fn run(args: NotifyArgs) -> Result<()> {
    let key = crypto::resolve_key(args.key.clone());
    let snapshot = Snapshot::read(&args.snapshot, key.as_deref())?;

    let payload = build_payload(&snapshot, &args.snapshot.to_string_lossy(), &args);

    if args.dry_run {
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    let url = args
        .slack_url
        .as_deref()
        .or(args.webhook_url.as_deref())
        .context("provide --slack-url, --webhook-url, or REWIND_SLACK_URL env var")?;

    let client = reqwest::Client::new();
    let resp = client
        .post(url)
        .json(&payload)
        .send()
        .await
        .context("failed to POST notification")?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    if status.is_success() {
        tracing::info!(status = status.as_u16(), "notification sent");
    } else {
        anyhow::bail!("notification endpoint returned {}: {}", status, body.trim());
    }
    Ok(())
}

fn build_payload(snap: &Snapshot, filename: &str, args: &NotifyArgs) -> Value {
    let stats = Stats::from(snap);
    let timeline_preview = preview_timeline(snap, args.timeline_lines);

    // Slack Block Kit message — gracefully degrades to plain text in non-Slack webhooks.
    let header_text = format!(
        "🔴 rewind captured: *{}*",
        std::path::Path::new(filename)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(filename)
    );

    let summary_text = format!(
        "*Services:* {services}\n*Events:* {total} ({http} HTTP, {db} DB, {grpc} gRPC, {syscalls} syscalls)\n*Time span:* {span}",
        services = if snap.services.is_empty() { "unknown".to_string() } else { snap.services.join(", ") },
        total    = stats.total,
        http     = stats.http,
        db       = stats.db,
        grpc     = stats.grpc,
        syscalls = stats.syscalls,
        span     = stats.span_label(),
    );

    let mut blocks: Vec<Value> = vec![
        json!({
            "type": "header",
            "text": { "type": "plain_text", "text": format!("rewind: {}", filename), "emoji": true }
        }),
        json!({
            "type": "section",
            "text": { "type": "mrkdwn", "text": header_text }
        }),
        json!({
            "type": "section",
            "text": { "type": "mrkdwn", "text": summary_text }
        }),
    ];

    if !timeline_preview.is_empty() {
        blocks.push(json!({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": format!("*Timeline preview*\n```\n{}\n```", timeline_preview)
            }
        }));
    }

    // Optional custom message appended at the end.
    if let Some(msg) = &args.message {
        blocks.push(json!({
            "type": "section",
            "text": { "type": "mrkdwn", "text": msg }
        }));
    }

    blocks.push(json!({ "type": "divider" }));

    json!({
        "text": format!("rewind snapshot captured: {filename}  |  {} events across [{}]",
            stats.total,
            snap.services.join(", ")),
        "blocks": blocks,
    })
}

fn preview_timeline(snap: &Snapshot, max_lines: usize) -> String {
    // Generate the ASCII timeline and return only the first `max_lines` event lines.
    let mermaid = to_mermaid(snap);
    // Extract the actual diagram lines (skip fences + "sequenceDiagram" + participant lines).
    let lines: Vec<&str> = mermaid
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.starts_with("```")
                && t != "sequenceDiagram"
                && !t.starts_with("participant ")
                && !t.is_empty()
        })
        .take(max_lines)
        .collect();

    if lines.is_empty() {
        return String::new();
    }

    let mut out = lines.join("\n");
    let total_msg_count = mermaid
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.starts_with("```")
                && t != "sequenceDiagram"
                && !t.starts_with("participant ")
                && !t.is_empty()
        })
        .count();

    if total_msg_count > max_lines {
        out.push_str(&format!("\n… and {} more", total_msg_count - max_lines));
    }
    out
}

// ── Stats ─────────────────────────────────────────────────────────────────────

struct Stats {
    total: usize,
    http: usize,
    db: usize,
    grpc: usize,
    syscalls: usize,
    first_ns: u64,
    last_ns: u64,
}

impl Stats {
    fn from(snap: &Snapshot) -> Self {
        let mut http = 0usize;
        let mut db = 0usize;
        let mut grpc = 0usize;
        let mut syscalls = 0usize;
        let mut first_ns = u64::MAX;
        let mut last_ns = 0u64;

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
            if ts < first_ns {
                first_ns = ts;
            }
            if ts > last_ns {
                last_ns = ts;
            }
        }

        Stats {
            total: snap.events.len(),
            http,
            db,
            grpc,
            syscalls,
            first_ns,
            last_ns,
        }
    }

    fn span_label(&self) -> String {
        if self.total == 0 {
            return "0ms".to_string();
        }
        let ms = self.last_ns.saturating_sub(self.first_ns) / 1_000_000;
        if ms < 1_000 {
            format!("{}ms", ms)
        } else {
            format!("{:.1}s", ms as f64 / 1_000.0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::snapshot::{DbRecord, GrpcRecord, HttpRecord, SyscallRecord};

    fn fixture() -> Snapshot {
        Snapshot {
            version: 1,
            recorded_at_ns: 1_700_000_000_000_000_000,
            services: vec!["api".to_string()],
            events: vec![
                Event::Http(HttpRecord {
                    timestamp_ns: 1_000_000_000,
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
                    timestamp_ns: 1_050_000_000,
                    protocol: "postgres".to_string(),
                    query: "SELECT 1".to_string(),
                    response: Some("ok".to_string()),
                    service: "api".to_string(),
                    pid: 1,
                }),
                Event::Grpc(GrpcRecord {
                    timestamp_ns: 1_100_000_000,
                    path: "/svc.Service/Call".to_string(),
                    service: "api".to_string(),
                    pid: 1,
                }),
                Event::Syscall(SyscallRecord {
                    timestamp_ns: 1_200_000_000,
                    kind: "clock_gettime".to_string(),
                    return_value: 0,
                    pid: 1,
                }),
                Event::Http(HttpRecord {
                    timestamp_ns: 1_300_000_000,
                    direction: "inbound".to_string(),
                    method: "POST".to_string(),
                    path: "/orders".to_string(),
                    status_code: Some(500),
                    service: "api".to_string(),
                    trace_id: None,
                    body: None,
                    headers: vec![],
                }),
            ],
        }
    }

    fn dummy_args() -> NotifyArgs {
        NotifyArgs {
            snapshot: std::path::PathBuf::from("test.rwd"),
            slack_url: None,
            webhook_url: None,
            message: None,
            timeline_lines: 5,
            dry_run: true,
            key: None,
        }
    }

    #[test]
    fn payload_has_blocks() {
        let snap = fixture();
        let args = dummy_args();
        let p = build_payload(&snap, "test.rwd", &args);
        assert!(p["blocks"].is_array());
        assert!(!p["blocks"].as_array().unwrap().is_empty());
    }

    #[test]
    fn payload_text_contains_filename() {
        let snap = fixture();
        let args = dummy_args();
        let p = build_payload(&snap, "incident.rwd", &args);
        assert!(p["text"].as_str().unwrap().contains("incident.rwd"));
    }

    #[test]
    fn payload_summary_counts() {
        let snap = fixture();
        let args = dummy_args();
        let p = build_payload(&snap, "t.rwd", &args);
        let blocks_str = serde_json::to_string(&p["blocks"]).unwrap();
        assert!(blocks_str.contains("HTTP"));
        assert!(blocks_str.contains("DB"));
        assert!(blocks_str.contains("gRPC"));
    }

    #[test]
    fn payload_includes_timeline() {
        let snap = fixture();
        let args = dummy_args();
        let p = build_payload(&snap, "t.rwd", &args);
        let blocks_str = serde_json::to_string(&p["blocks"]).unwrap();
        assert!(blocks_str.contains("Timeline preview"));
    }

    #[test]
    fn stats_span_ms() {
        let snap = fixture();
        let stats = Stats::from(&snap);
        let label = stats.span_label();
        assert!(label.contains("ms") || label.contains('s'));
    }

    #[test]
    fn stats_empty() {
        let snap = Snapshot {
            version: 1,
            recorded_at_ns: 0,
            services: vec![],
            events: vec![],
        };
        let stats = Stats::from(&snap);
        assert_eq!(stats.total, 0);
        assert_eq!(stats.span_label(), "0ms");
    }

    #[test]
    fn preview_timeline_limits_lines() {
        let snap = fixture();
        let preview = preview_timeline(&snap, 2);
        let line_count = preview.lines().count();
        // 2 message lines + possible "… and N more" line
        assert!(line_count <= 3);
    }

    #[test]
    fn payload_custom_message() {
        let snap = fixture();
        let mut args = dummy_args();
        args.message = Some("See runbook: https://example.com".to_string());
        let p = build_payload(&snap, "t.rwd", &args);
        let blocks_str = serde_json::to_string(&p["blocks"]).unwrap();
        assert!(blocks_str.contains("See runbook"));
    }
}
