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

//! Replay diff — compare two `.rwd` snapshots side-by-side.
//!
//! Surfaces divergences in:
//!   - DB query/response pairs (missing query, changed response)
//!   - HTTP outbound responses (status code changes, path mismatches)
//!   - Syscall return values (clock, random)
//!   - Event count differences
//!
//! Usage:
//!   rewind diff baseline.rwd candidate.rwd
//!   rewind diff baseline.rwd candidate.rwd --json

use anyhow::Result;
use serde::Serialize;

use crate::cli::DiffArgs;
use crate::crypto;
use crate::store::snapshot::{Event, Snapshot};

#[derive(Debug, Serialize)]
pub struct DiffReport {
    pub baseline: String,
    pub candidate: String,
    pub event_count_baseline: usize,
    pub event_count_candidate: usize,
    pub divergences: Vec<Divergence>,
    pub summary: String,
}

#[derive(Debug, Serialize)]
pub struct Divergence {
    pub kind: DivergenceKind,
    pub description: String,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DivergenceKind {
    MissingEvent,
    ExtraEvent,
    DbResponseChanged,
    HttpStatusChanged,
    SyscallReturnChanged,
    TimingDrift,
}

pub async fn run(args: DiffArgs) -> Result<()> {
    let key = crypto::resolve_key(args.key);
    let baseline = Snapshot::read(&args.baseline, key.as_deref())?;
    let candidate = Snapshot::read(&args.candidate, key.as_deref())?;

    let report = diff_snapshots(
        args.baseline.to_string_lossy().to_string(),
        args.candidate.to_string_lossy().to_string(),
        &baseline,
        &candidate,
    );

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_report(&report);
    }

    // Exit 1 if there are divergences (useful in CI).
    if !report.divergences.is_empty() && !args.allow_divergence {
        std::process::exit(1);
    }
    Ok(())
}

fn diff_snapshots(
    baseline_name: String,
    candidate_name: String,
    baseline: &Snapshot,
    candidate: &Snapshot,
) -> DiffReport {
    let mut divergences = Vec::new();

    // ── Event count diff ─────────────────────────────────────────────────────
    let base_n = baseline.events.len();
    let cand_n = candidate.events.len();
    if base_n != cand_n {
        divergences.push(Divergence {
            kind: if cand_n < base_n {
                DivergenceKind::MissingEvent
            } else {
                DivergenceKind::ExtraEvent
            },
            description: format!(
                "event count: baseline={base_n} candidate={cand_n} (Δ{})",
                cand_n as i64 - base_n as i64
            ),
        });
    }

    // ── DB response diff ─────────────────────────────────────────────────────
    let base_db = db_events(baseline);
    let cand_db = db_events(candidate);

    for (i, base) in base_db.iter().enumerate() {
        match cand_db.get(i) {
            None => {
                divergences.push(Divergence {
                    kind: DivergenceKind::MissingEvent,
                    description: format!("DB[{i}] missing in candidate: {}", base.query),
                });
            }
            Some(cand) => {
                if base.query != cand.query {
                    divergences.push(Divergence {
                        kind: DivergenceKind::DbResponseChanged,
                        description: format!(
                            "DB[{i}] query changed:\n  baseline:  {}\n  candidate: {}",
                            base.query, cand.query
                        ),
                    });
                } else if base.response != cand.response {
                    divergences.push(Divergence {
                        kind: DivergenceKind::DbResponseChanged,
                        description: format!(
                            "DB[{i}] response changed for query '{}':\n  baseline:  {:?}\n  candidate: {:?}",
                            base.query, base.response, cand.response
                        ),
                    });
                }
            }
        }
    }
    for (i, ev) in cand_db.iter().enumerate().skip(base_db.len()) {
        divergences.push(Divergence {
            kind: DivergenceKind::ExtraEvent,
            description: format!("DB[{i}] extra in candidate: {}", ev.query),
        });
    }

    // ── HTTP outbound status diff ────────────────────────────────────────────
    let base_http = outbound_http(baseline);
    let cand_http = outbound_http(candidate);

    for (i, base) in base_http.iter().enumerate() {
        if let Some(cand) = cand_http.get(i) {
            if base.path != cand.path {
                divergences.push(Divergence {
                    kind: DivergenceKind::HttpStatusChanged,
                    description: format!("HTTP[{i}] path changed: {} → {}", base.path, cand.path),
                });
            } else if base.status_code != cand.status_code {
                divergences.push(Divergence {
                    kind: DivergenceKind::HttpStatusChanged,
                    description: format!(
                        "HTTP[{i}] status changed for {} {}: {:?} → {:?}",
                        base.method, base.path, base.status_code, cand.status_code
                    ),
                });
            }
        }
    }

    // ── Syscall return diff ──────────────────────────────────────────────────
    let base_sys = syscall_events(baseline);
    let cand_sys = syscall_events(candidate);

    for (i, base) in base_sys.iter().enumerate() {
        if let Some(cand) = cand_sys.get(i) {
            if base.kind == cand.kind && base.return_value != cand.return_value {
                divergences.push(Divergence {
                    kind: DivergenceKind::SyscallReturnChanged,
                    description: format!(
                        "syscall[{i}] {} return changed: {} → {}",
                        base.kind, base.return_value, cand.return_value
                    ),
                });
            }
        }
    }

    // ── Timing drift (first vs last event span) ──────────────────────────────
    let base_span = event_time_span(baseline);
    let cand_span = event_time_span(candidate);
    if let (Some(base_ns), Some(cand_ns)) = (base_span, cand_span) {
        let delta_ms = (cand_ns as i64 - base_ns as i64).abs() / 1_000_000;
        if delta_ms > 500 {
            divergences.push(Divergence {
                kind: DivergenceKind::TimingDrift,
                description: format!(
                    "total event duration differs by {delta_ms} ms \
                     (baseline={base_ns}ns candidate={cand_ns}ns)"
                ),
            });
        }
    }

    let summary = if divergences.is_empty() {
        "Snapshots are equivalent — no divergences found.".to_string()
    } else {
        format!("{} divergence(s) found.", divergences.len())
    };

    DiffReport {
        baseline: baseline_name,
        candidate: candidate_name,
        event_count_baseline: base_n,
        event_count_candidate: cand_n,
        divergences,
        summary,
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

struct DbEntry<'a> {
    query: &'a str,
    response: Option<&'a str>,
}

fn db_events(s: &Snapshot) -> Vec<DbEntry<'_>> {
    s.events
        .iter()
        .filter_map(|e| match e {
            Event::Db(d) => Some(DbEntry {
                query: &d.query,
                response: d.response.as_deref(),
            }),
            _ => None,
        })
        .collect()
}

struct HttpEntry<'a> {
    method: &'a str,
    path: &'a str,
    status_code: Option<u16>,
}

fn outbound_http(s: &Snapshot) -> Vec<HttpEntry<'_>> {
    s.events
        .iter()
        .filter_map(|e| match e {
            Event::Http(h) if h.direction == "outbound" => Some(HttpEntry {
                method: &h.method,
                path: &h.path,
                status_code: h.status_code,
            }),
            _ => None,
        })
        .collect()
}

struct SyscallEntry<'a> {
    kind: &'a str,
    return_value: u64,
}

fn syscall_events(s: &Snapshot) -> Vec<SyscallEntry<'_>> {
    s.events
        .iter()
        .filter_map(|e| match e {
            Event::Syscall(s) => Some(SyscallEntry {
                kind: &s.kind,
                return_value: s.return_value,
            }),
            _ => None,
        })
        .collect()
}

fn event_time_span(s: &Snapshot) -> Option<u64> {
    let timestamps: Vec<u64> = s
        .events
        .iter()
        .map(|e| match e {
            Event::Http(h) => h.timestamp_ns,
            Event::Db(d) => d.timestamp_ns,
            Event::Syscall(s) => s.timestamp_ns,
            Event::Grpc(g) => g.timestamp_ns,
        })
        .collect();
    let min = timestamps.iter().min()?;
    let max = timestamps.iter().max()?;
    Some(max - min)
}

fn print_report(report: &DiffReport) {
    println!("rewind diff");
    println!(
        "  baseline:  {} ({} events)",
        report.baseline, report.event_count_baseline
    );
    println!(
        "  candidate: {} ({} events)",
        report.candidate, report.event_count_candidate
    );
    println!();

    if report.divergences.is_empty() {
        println!("✓ {}", report.summary);
        return;
    }

    println!("✗ {}", report.summary);
    println!();
    for (i, d) in report.divergences.iter().enumerate() {
        println!("[{}] {:?}", i + 1, d.kind);
        for line in d.description.lines() {
            println!("    {line}");
        }
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::snapshot::{DbRecord, Event, HttpRecord, Snapshot, SyscallRecord};

    fn make_snapshot(events: Vec<Event>) -> Snapshot {
        let mut s = Snapshot::new(vec!["api".to_string()]);
        s.events = events;
        s
    }

    fn http_ev(direction: &str, path: &str, status: Option<u16>) -> Event {
        Event::Http(HttpRecord {
            timestamp_ns: 1_000_000,
            direction: direction.to_string(),
            method: "GET".to_string(),
            path: path.to_string(),
            status_code: status,
            service: "api".to_string(),
            trace_id: None,
            body: None,
            headers: Vec::new(),
        })
    }

    fn db_ev(query: &str, response: Option<&str>) -> Event {
        Event::Db(DbRecord {
            timestamp_ns: 1_001_000,
            protocol: "postgres".to_string(),
            query: query.to_string(),
            response: response.map(|s| s.to_string()),
            service: "api".to_string(),
            pid: 42,
        })
    }

    fn sys_ev(kind: &str, ret: u64) -> Event {
        Event::Syscall(SyscallRecord {
            timestamp_ns: 1_002_000,
            kind: kind.to_string(),
            return_value: ret,
            pid: 42,
        })
    }

    #[test]
    fn identical_snapshots_have_no_divergences() {
        let s = make_snapshot(vec![db_ev("SELECT 1", Some("1"))]);
        let report = diff_snapshots("a".into(), "b".into(), &s, &s);
        assert!(report.divergences.is_empty());
    }

    #[test]
    fn db_response_change_detected() {
        let base = make_snapshot(vec![db_ev("SELECT 1", Some("1"))]);
        let cand = make_snapshot(vec![db_ev("SELECT 1", Some("2"))]);
        let report = diff_snapshots("a".into(), "b".into(), &base, &cand);
        assert!(report
            .divergences
            .iter()
            .any(|d| d.kind == DivergenceKind::DbResponseChanged));
    }

    #[test]
    fn http_status_change_detected() {
        let base = make_snapshot(vec![http_ev("outbound", "/api/v1", Some(200))]);
        let cand = make_snapshot(vec![http_ev("outbound", "/api/v1", Some(500))]);
        let report = diff_snapshots("a".into(), "b".into(), &base, &cand);
        assert!(report
            .divergences
            .iter()
            .any(|d| d.kind == DivergenceKind::HttpStatusChanged));
    }

    #[test]
    fn syscall_return_change_detected() {
        let base = make_snapshot(vec![sys_ev("clock_gettime", 100)]);
        let cand = make_snapshot(vec![sys_ev("clock_gettime", 200)]);
        let report = diff_snapshots("a".into(), "b".into(), &base, &cand);
        assert!(report
            .divergences
            .iter()
            .any(|d| d.kind == DivergenceKind::SyscallReturnChanged));
    }

    #[test]
    fn missing_event_detected() {
        let base = make_snapshot(vec![
            db_ev("SELECT 1", Some("1")),
            db_ev("SELECT 2", Some("2")),
        ]);
        let cand = make_snapshot(vec![db_ev("SELECT 1", Some("1"))]);
        let report = diff_snapshots("a".into(), "b".into(), &base, &cand);
        assert!(report
            .divergences
            .iter()
            .any(|d| d.kind == DivergenceKind::MissingEvent));
    }
}
