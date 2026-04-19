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

//! Trace export — converts a .rwd snapshot to OTLP JSON or Jaeger JSON.
//!
//! OTLP (default):
//!   rewind export incident.rwd | curl -sX POST http://collector:4318/v1/traces \
//!       -H 'Content-Type: application/json' -d @-
//!
//! Jaeger:
//!   rewind export incident.rwd --format jaeger | curl -sX POST \
//!       http://jaeger:14268/api/traces?format=json -H 'Content-Type: application/json' -d @-

use anyhow::Result;
use serde_json::{json, Value};

use crate::cli::ExportArgs;
use crate::crypto;
use crate::store::snapshot::{Event, Snapshot};

pub async fn run(args: ExportArgs) -> Result<()> {
    let snapshot = Snapshot::read(&args.snapshot, crypto::resolve_key(args.key).as_deref())?;

    let (doc, count) = match args.format.as_str() {
        "jaeger" => {
            let doc = to_jaeger_json(&snapshot);
            let count = doc.as_array().map(|a| a.len()).unwrap_or(0);
            (doc, count)
        }
        _ => {
            let doc = to_otlp_json(&snapshot);
            let count = span_count(&doc);
            (doc, count)
        }
    };

    let out = serde_json::to_string_pretty(&doc)?;
    match &args.output {
        Some(path) => {
            std::fs::write(path, &out)?;
            eprintln!(
                "Exported {count} spans ({}) to {}",
                args.format,
                path.display()
            );
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
                    attr_str("rewind.services",   &snapshot.services.join(",")),
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
                attr_str("http.method", &h.method),
                attr_str("http.target", &h.path),
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
                attr_str("db.system", &d.protocol),
                attr_str("db.statement", &d.query),
                attr_str("rewind.service", &d.service),
                attr_int("rewind.pid", d.pid as i64),
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
                attr_str("syscall.name", &s.kind),
                attr_str("syscall.return_value", &s.return_value.to_string()),
                attr_int("rewind.pid", s.pid as i64),
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

        Event::Grpc(g) => {
            let span_id = span_id_from(g.timestamp_ns, idx);
            let attrs = vec![
                attr_str("rpc.system", "grpc"),
                attr_str("rpc.method", &g.path),
                attr_str("rewind.service", &g.service),
                attr_int("rewind.pid", g.pid as i64),
            ];
            span_json(
                default_trace_id,
                &span_id,
                &g.path,
                3, // CLIENT
                g.timestamp_ns,
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

// ── Jaeger JSON format ─────────────────────────────────────────────────────────
//
// Jaeger accepts a JSON envelope with one trace object per unique traceID.
// https://www.jaegertracing.io/docs/1.55/apis/#thrift-over-http-deprecated
//
// Usage:
//   rewind export incident.rwd --format jaeger | \
//     curl -sX POST http://jaeger:14268/api/traces?format=json \
//          -H 'Content-Type: application/json' -d @-

fn to_jaeger_json(snapshot: &Snapshot) -> Value {
    let default_trace_id = format!("{:032x}", snapshot.recorded_at_ns);
    let process_id = "p1";

    let spans: Vec<Value> = snapshot
        .events
        .iter()
        .enumerate()
        .map(|(idx, event)| event_to_jaeger_span(event, idx, &default_trace_id, process_id))
        .collect();

    // Group into a single trace object.
    json!([{
        "traceID": default_trace_id,
        "spans": spans,
        "processes": {
            process_id: {
                "serviceName": "rewind",
                "tags": [
                    {"key": "rewind.services", "type": "string",
                     "value": snapshot.services.join(",")},
                    {"key": "rewind.version", "type": "int64",
                     "value": snapshot.version},
                ]
            }
        },
        "warnings": null
    }])
}

fn event_to_jaeger_span(
    event: &Event,
    idx: usize,
    default_trace_id: &str,
    process_id: &str,
) -> Value {
    let (trace_id, span_id, op_name, start_us, tags) = match event {
        Event::Http(h) => {
            let tid = h
                .trace_id
                .as_deref()
                .and_then(|tp| tp.split('-').nth(1))
                .filter(|s| s.len() == 32)
                .unwrap_or(default_trace_id)
                .to_string();
            let mut tags = vec![
                jtag_str("http.method", &h.method),
                jtag_str("http.url", &h.path),
                jtag_str(
                    "span.kind",
                    if h.direction == "inbound" {
                        "server"
                    } else {
                        "client"
                    },
                ),
            ];
            if let Some(sc) = h.status_code {
                tags.push(jtag_int("http.status_code", sc as i64));
            }
            (
                tid,
                span_id_from(h.timestamp_ns, idx),
                format!("{} {}", h.method, h.path),
                h.timestamp_ns / 1_000,
                tags,
            )
        }
        Event::Db(d) => {
            let tags = vec![
                jtag_str("db.type", &d.protocol),
                jtag_str("db.statement", &d.query),
                jtag_str("span.kind", "client"),
            ];
            (
                default_trace_id.to_string(),
                span_id_from(d.timestamp_ns, idx),
                format!("{} query", d.protocol),
                d.timestamp_ns / 1_000,
                tags,
            )
        }
        Event::Grpc(g) => {
            let tags = vec![
                jtag_str("rpc.system", "grpc"),
                jtag_str("rpc.method", &g.path),
                jtag_str("span.kind", "client"),
            ];
            (
                default_trace_id.to_string(),
                span_id_from(g.timestamp_ns, idx),
                g.path.clone(),
                g.timestamp_ns / 1_000,
                tags,
            )
        }
        Event::Syscall(s) => {
            let tags = vec![
                jtag_str("syscall.name", &s.kind),
                jtag_str("syscall.return_value", &s.return_value.to_string()),
                jtag_str("span.kind", "internal"),
            ];
            (
                default_trace_id.to_string(),
                span_id_from(s.timestamp_ns, idx),
                format!("syscall/{}", s.kind),
                s.timestamp_ns / 1_000,
                tags,
            )
        }
    };

    json!({
        "traceID":       trace_id,
        "spanID":        span_id,
        "operationName": op_name,
        "startTime":     start_us,   // microseconds since epoch
        "duration":      0,
        "tags":          tags,
        "logs":          [],
        "processID":     process_id,
        "warnings":      null
    })
}

fn jtag_str(key: &str, value: &str) -> Value {
    json!({"key": key, "type": "string", "value": value})
}

fn jtag_int(key: &str, value: i64) -> Value {
    json!({"key": key, "type": "int64", "value": value})
}
