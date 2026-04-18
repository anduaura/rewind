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

//! OTLP JSON export — converts a .rwd snapshot to OpenTelemetry trace spans
//! that can be piped to any OTEL collector.
//!
//!   rewind export incident.rwd | curl -sX POST http://collector:4318/v1/traces \
//!       -H 'Content-Type: application/json' -d @-

use anyhow::Result;
use serde_json::{json, Value};

use crate::cli::ExportArgs;
use crate::store::snapshot::{Event, Snapshot};

pub async fn run(args: ExportArgs) -> Result<()> {
    let snapshot = Snapshot::read(&args.snapshot)?;
    let otlp = to_otlp_json(&snapshot);
    let out = serde_json::to_string_pretty(&otlp)?;

    match &args.output {
        Some(path) => {
            std::fs::write(path, &out)?;
            eprintln!("Exported {} spans to {}", span_count(&otlp), path.display());
        }
        None => println!("{}", out),
    }
    Ok(())
}

fn span_count(otlp: &Value) -> usize {
    otlp["resourceSpans"][0]["scopeSpans"][0]["spans"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0)
}

/// Build an OTLP JSON document from a snapshot.
///
/// Each HTTP, DB, and syscall event becomes one span. If the HTTP event carries
/// a W3C `traceparent` the trace-id is extracted from it; otherwise all events
/// in the snapshot share a synthetic trace-id derived from `recorded_at_ns`.
fn to_otlp_json(snapshot: &Snapshot) -> Value {
    // Synthetic trace-id: right-pad recorded_at_ns hex to 32 chars.
    let default_trace_id = format!("{:032x}", snapshot.recorded_at_ns);

    let spans: Vec<Value> = snapshot
        .events
        .iter()
        .enumerate()
        .map(|(idx, event)| event_to_span(event, idx, &default_trace_id))
        .collect();

    json!({
        "resourceSpans": [{
            "resource": {
                "attributes": [
                    attr_str("service.name",      "rewind"),
                    attr_str("rewind.services",   snapshot.services.join(",")),
                    attr_int("rewind.version",    snapshot.version as i64),
                ]
            },
            "scopeSpans": [{
                "scope": {"name": "rewind", "version": "0.1.0"},
                "spans": spans
            }]
        }]
    })
}

fn event_to_span(event: &Event, idx: usize, default_trace_id: &str) -> Value {
    match event {
        Event::Http(h) => {
            // Extract 128-bit trace-id from "00-<trace_id>-<span_id>-<flags>".
            let trace_id = h
                .trace_id
                .as_deref()
                .and_then(|tp| tp.split('-').nth(1))
                .filter(|s| s.len() == 32)
                .unwrap_or(default_trace_id)
                .to_string();

            let span_id = span_id_from(h.timestamp_ns, idx);
            let kind = if h.direction == "inbound" { 2 } else { 3 }; // SERVER / CLIENT

            let mut attrs = vec![
                attr_str("http.method",    &h.method),
                attr_str("http.target",    &h.path),
                attr_str("rewind.direction", &h.direction),
                attr_str("rewind.service", &h.service),
            ];
            if let Some(sc) = h.status_code {
                attrs.push(attr_int("http.status_code", sc as i64));
            }
            if let Some(tid) = &h.trace_id {
                attrs.push(attr_str("rewind.traceparent", tid));
            }

            span_json(
                &trace_id,
                &span_id,
                &format!("{} {}", h.method, h.path),
                kind,
                h.timestamp_ns,
                attrs,
            )
        }

        Event::Db(d) => {
            let span_id = span_id_from(d.timestamp_ns, idx);
            let mut attrs = vec![
                attr_str("db.system",    &d.protocol),
                attr_str("db.statement", &d.query),
                attr_str("rewind.service", &d.service),
                attr_int("rewind.pid",   d.pid as i64),
            ];
            if let Some(resp) = &d.response {
                attrs.push(attr_str("db.response", resp));
            }

            span_json(
                default_trace_id,
                &span_id,
                &format!("{} query", d.protocol),
                3, // CLIENT
                d.timestamp_ns,
                attrs,
            )
        }

        Event::Syscall(s) => {
            let span_id = span_id_from(s.timestamp_ns, idx);
            let attrs = vec![
                attr_str("syscall.name",         &s.kind),
                attr_str("syscall.return_value",  &s.return_value.to_string()),
                attr_int("rewind.pid",            s.pid as i64),
            ];

            span_json(
                default_trace_id,
                &span_id,
                &format!("syscall/{}", s.kind),
                1, // INTERNAL
                s.timestamp_ns,
                attrs,
            )
        }
    }
}

fn span_json(
    trace_id: &str,
    span_id: &str,
    name: &str,
    kind: u8,
    timestamp_ns: u64,
    attributes: Vec<Value>,
) -> Value {
    // OTLP timestamps are Unix nanoseconds expressed as decimal strings
    // (proto3 JSON encoding of uint64).
    let ts = timestamp_ns.to_string();
    json!({
        "traceId":            trace_id,
        "spanId":             span_id,
        "name":               name,
        "kind":               kind,
        "startTimeUnixNano":  ts,
        "endTimeUnixNano":    ts,
        "attributes":         attributes,
        "status":             {}
    })
}

/// Derive a deterministic 16-hex-char span ID from a timestamp + position index.
fn span_id_from(timestamp_ns: u64, idx: usize) -> String {
    // XOR upper 32 bits with index to avoid collisions when timestamps repeat.
    let mixed = timestamp_ns ^ ((idx as u64) << 32);
    format!("{:016x}", mixed)
}

fn attr_str(key: &str, value: &str) -> Value {
    json!({"key": key, "value": {"stringValue": value}})
}

fn attr_int(key: &str, value: i64) -> Value {
    json!({"key": key, "value": {"intValue": value.to_string()}})
}
