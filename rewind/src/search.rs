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

//! Snapshot search — scan a directory of .rwd files and return those matching
//! one or more filter criteria.
//!
//! Usage:
//!   rewind search /var/rewind/snapshots --path /api/orders
//!   rewind search /var/rewind/snapshots --service api --status 500
//!   rewind search /var/rewind/snapshots --query "SELECT * FROM orders"
//!   rewind search /var/rewind/snapshots --service payments --json
//!
//! Multiple filters are ANDed: all conditions must match for a snapshot to be
//! included in results.  Each matching file is printed with a brief hit summary
//! (which event types matched and how many times).

use anyhow::{Context, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};

use crate::cli::SearchArgs;
use crate::store::snapshot::{Event, Snapshot};

#[derive(Debug, Serialize)]
pub struct SearchResult {
    pub path: String,
    pub services: Vec<String>,
    pub total_events: usize,
    pub hits: HitSummary,
}

#[derive(Debug, Serialize)]
pub struct HitSummary {
    pub http: usize,
    pub db: usize,
    pub grpc: usize,
}

pub async fn run(args: SearchArgs) -> Result<()> {
    let results = search(&args).await?;

    if results.is_empty() {
        if args.json {
            println!("[]");
        } else {
            println!("No matching snapshots found.");
        }
        return Ok(());
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        for r in &results {
            let hits = r.hits.http + r.hits.db + r.hits.grpc;
            println!(
                "{} — {} hit{} ({} HTTP, {} DB, {} gRPC) | services: {} | {} events total",
                r.path,
                hits,
                if hits == 1 { "" } else { "s" },
                r.hits.http,
                r.hits.db,
                r.hits.grpc,
                r.services.join(", "),
                r.total_events,
            );
        }
        println!("\n{} snapshot{} matched.", results.len(), if results.len() == 1 { "" } else { "s" });
    }
    Ok(())
}

async fn search(args: &SearchArgs) -> Result<Vec<SearchResult>> {
    let mut rwd_files = collect_rwd_files(&args.dir).await?;
    rwd_files.sort();

    let mut results = Vec::new();

    for file in &rwd_files {
        let snap = match Snapshot::read(file, args.key.as_deref()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(path = %file.display(), "skipping: {e}");
                continue;
            }
        };

        if let Some(hits) = matches_filters(&snap, args) {
            results.push(SearchResult {
                path: file.display().to_string(),
                services: snap.services.clone(),
                total_events: snap.events.len(),
                hits,
            });
        }
    }

    Ok(results)
}

/// Returns `Some(HitSummary)` if the snapshot passes all active filters,
/// `None` if it should be excluded.
///
/// Each event type is scored only by filters that apply to it:
///   HTTP  — path, status, method
///   DB    — query, protocol
///   gRPC  — path
///
/// An event type is only counted when at least one of its own filters is set
/// and passes. When NO event-level filters are set the snapshot is included
/// (service filter alone was the criterion) and all counts are zero.
fn matches_filters(snap: &Snapshot, args: &SearchArgs) -> Option<HitSummary> {
    let mut http_hits = 0usize;
    let mut db_hits = 0usize;
    let mut grpc_hits = 0usize;

    // Service filter — applies at snapshot level (fast path).
    if let Some(svc) = &args.service {
        if !snap
            .services
            .iter()
            .any(|s| s.to_lowercase().contains(&svc.to_lowercase()))
        {
            return None;
        }
    }

    let has_http_filter = args.path.is_some() || args.status.is_some() || args.method.is_some();
    let has_db_filter = args.query.is_some() || args.protocol.is_some();
    // gRPC shares the path filter with HTTP.
    let has_event_filter = has_http_filter || has_db_filter;

    if !has_event_filter {
        // Only the service filter (or no filter at all) — include the snapshot.
        return Some(HitSummary { http: 0, db: 0, grpc: 0 });
    }

    for event in &snap.events {
        match event {
            Event::Http(h) if has_http_filter => {
                if let Some(path_pat) = &args.path {
                    if !h.path.to_lowercase().contains(&path_pat.to_lowercase()) {
                        continue;
                    }
                }
                if let Some(status) = args.status {
                    match h.status_code {
                        Some(sc) if sc == status => {}
                        _ => continue,
                    }
                }
                if let Some(method_pat) = &args.method {
                    if !h.method.eq_ignore_ascii_case(method_pat) {
                        continue;
                    }
                }
                http_hits += 1;
            }
            Event::Db(d) if has_db_filter => {
                if let Some(query_pat) = &args.query {
                    if !d.query.to_lowercase().contains(&query_pat.to_lowercase()) {
                        continue;
                    }
                }
                if let Some(proto) = &args.protocol {
                    if !d.protocol.eq_ignore_ascii_case(proto) {
                        continue;
                    }
                }
                db_hits += 1;
            }
            Event::Grpc(g) if args.path.is_some() => {
                if let Some(path_pat) = &args.path {
                    if !g.path.to_lowercase().contains(&path_pat.to_lowercase()) {
                        continue;
                    }
                }
                grpc_hits += 1;
            }
            _ => {}
        }
    }

    let total_hits = http_hits + db_hits + grpc_hits;
    if total_hits == 0 {
        return None;
    }

    Some(HitSummary {
        http: http_hits,
        db: db_hits,
        grpc: grpc_hits,
    })
}

async fn collect_rwd_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut read_dir = tokio::fs::read_dir(dir)
        .await
        .with_context(|| format!("cannot read directory {}", dir.display()))?;

    while let Ok(Some(entry)) = read_dir.next_entry().await {
        let name = entry.file_name();
        if name.to_string_lossy().ends_with(".rwd") {
            files.push(entry.path());
        }
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::snapshot::{DbRecord, GrpcRecord, HttpRecord, SyscallRecord};

    fn make_snap() -> Snapshot {
        Snapshot {
            version: 1,
            recorded_at_ns: 0,
            services: vec!["api".to_string(), "worker".to_string()],
            events: vec![
                Event::Http(HttpRecord {
                    timestamp_ns: 1,
                    direction: "inbound".to_string(),
                    method: "POST".to_string(),
                    path: "/api/orders".to_string(),
                    status_code: Some(500),
                    service: "api".to_string(),
                    trace_id: None,
                    body: None,
                    headers: vec![],
                }),
                Event::Http(HttpRecord {
                    timestamp_ns: 2,
                    direction: "outbound".to_string(),
                    method: "GET".to_string(),
                    path: "/health".to_string(),
                    status_code: Some(200),
                    service: "api".to_string(),
                    trace_id: None,
                    body: None,
                    headers: vec![],
                }),
                Event::Db(DbRecord {
                    timestamp_ns: 3,
                    protocol: "postgres".to_string(),
                    query: "SELECT * FROM orders WHERE id = $1".to_string(),
                    response: None,
                    service: "api".to_string(),
                    pid: 1,
                }),
                Event::Grpc(GrpcRecord {
                    timestamp_ns: 4,
                    path: "/inventory.Service/Check".to_string(),
                    service: "worker".to_string(),
                    pid: 1,
                }),
                Event::Syscall(SyscallRecord {
                    timestamp_ns: 5,
                    kind: "clock_gettime".to_string(),
                    return_value: 0,
                    pid: 1,
                }),
            ],
        }
    }

    fn args_with(
        path: Option<&str>,
        status: Option<u16>,
        method: Option<&str>,
        query: Option<&str>,
        service: Option<&str>,
        protocol: Option<&str>,
    ) -> SearchArgs {
        SearchArgs {
            dir: PathBuf::from("."),
            path: path.map(String::from),
            status,
            method: method.map(String::from),
            query: query.map(String::from),
            service: service.map(String::from),
            protocol: protocol.map(String::from),
            json: false,
            key: None,
        }
    }

    #[test]
    fn matches_http_path() {
        let snap = make_snap();
        let args = args_with(Some("/api/orders"), None, None, None, None, None);
        let hits = matches_filters(&snap, &args).unwrap();
        assert_eq!(hits.http, 1);
        assert_eq!(hits.db, 0);
    }

    #[test]
    fn matches_http_status() {
        let snap = make_snap();
        let args = args_with(None, Some(500), None, None, None, None);
        let hits = matches_filters(&snap, &args).unwrap();
        assert_eq!(hits.http, 1);
    }

    #[test]
    fn matches_http_method() {
        let snap = make_snap();
        let args = args_with(None, None, Some("GET"), None, None, None);
        let hits = matches_filters(&snap, &args).unwrap();
        assert_eq!(hits.http, 1);
    }

    #[test]
    fn matches_db_query() {
        let snap = make_snap();
        let args = args_with(None, None, None, Some("SELECT"), None, None);
        let hits = matches_filters(&snap, &args).unwrap();
        assert_eq!(hits.db, 1);
    }

    #[test]
    fn matches_grpc_path() {
        let snap = make_snap();
        let args = args_with(Some("/inventory"), None, None, None, None, None);
        let hits = matches_filters(&snap, &args).unwrap();
        assert_eq!(hits.grpc, 1);
    }

    #[test]
    fn service_filter_excludes_unrelated() {
        let snap = make_snap();
        let args = args_with(None, None, None, None, Some("payments"), None);
        assert!(matches_filters(&snap, &args).is_none());
    }

    #[test]
    fn service_filter_includes_match() {
        let snap = make_snap();
        let args = args_with(None, None, None, None, Some("api"), None);
        assert!(matches_filters(&snap, &args).is_some());
    }

    #[test]
    fn no_filters_includes_snapshot() {
        let snap = make_snap();
        let args = args_with(None, None, None, None, None, None);
        // No event-level filter → snapshot included, hit counts are zero (N/A)
        assert!(matches_filters(&snap, &args).is_some());
    }

    #[test]
    fn combined_path_and_status_filter() {
        let snap = make_snap();
        let args = args_with(Some("/api/orders"), Some(500), None, None, None, None);
        let hits = matches_filters(&snap, &args).unwrap();
        assert_eq!(hits.http, 1);
    }

    #[test]
    fn combined_path_and_status_no_match() {
        let snap = make_snap();
        // Path matches but status doesn't
        let args = args_with(Some("/api/orders"), Some(200), None, None, None, None);
        assert!(matches_filters(&snap, &args).is_none());
    }

    #[test]
    fn protocol_filter() {
        let snap = make_snap();
        let args = args_with(None, None, None, None, None, Some("postgres"));
        let hits = matches_filters(&snap, &args).unwrap();
        assert_eq!(hits.db, 1);
    }

    #[test]
    fn protocol_filter_no_match() {
        let snap = make_snap();
        let args = args_with(None, None, None, None, None, Some("redis"));
        assert!(matches_filters(&snap, &args).is_none());
    }

    #[test]
    fn case_insensitive_path() {
        let snap = make_snap();
        let args = args_with(Some("/API/ORDERS"), None, None, None, None, None);
        let hits = matches_filters(&snap, &args).unwrap();
        assert_eq!(hits.http, 1);
    }
}
