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

//! Central collection server — agents push `.rwd` snapshots over HTTP so
//! `kubectl cp` is no longer needed to retrieve incident recordings.
//!
//! Usage:
//!   rewind server --listen 0.0.0.0:9092 --storage /var/rewind/snapshots
//!
//! Push a snapshot from an agent node:
//!   rewind push-agent incident.rwd --server http://collector:9092
//!
//! API:
//!   POST /snapshots          — upload a snapshot (body = raw .rwd bytes)
//!   GET  /snapshots          — list stored snapshots (JSON array)
//!   GET  /snapshots/<name>   — download a specific snapshot
//!   GET  /healthz            — liveness probe

use anyhow::Result;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;

use crate::cli::{PushAgentArgs, ServerArgs};

#[derive(Clone)]
struct ServerState {
    storage: PathBuf,
    token: Option<String>,
}

pub async fn run(args: ServerArgs) -> Result<()> {
    fs::create_dir_all(&args.storage).await?;

    let state = Arc::new(ServerState {
        storage: args.storage.clone(),
        token: args.token.clone(),
    });

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/snapshots", post(upload_snapshot))
        .route("/snapshots", get(list_snapshots))
        .route("/snapshots/{name}", get(download_snapshot))
        .with_state(state);

    println!("rewind server");
    println!("  listen:  {}", args.listen);
    println!("  storage: {}", args.storage.display());
    if args.token.is_some() {
        println!("  auth:    Authorization: Bearer <token> required");
    }
    println!("  POST /snapshots        — upload");
    println!("  GET  /snapshots        — list");
    println!("  GET  /snapshots/<name> — download");

    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// ── Handlers ─────────────────────────────────────────────────────────────────

async fn healthz() -> &'static str {
    "ok\n"
}

async fn upload_snapshot(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if !auth_ok(&state, &headers) {
        return (StatusCode::UNAUTHORIZED, "missing or invalid token\n").into_response();
    }
    if body.is_empty() {
        return (StatusCode::BAD_REQUEST, "empty body\n").into_response();
    }

    // Name: X-Rewind-Snapshot header, else timestamp-based.
    let name = headers
        .get("x-rewind-snapshot")
        .and_then(|v| v.to_str().ok())
        .filter(|s| is_safe_filename(s))
        .map(|s| s.to_string())
        .unwrap_or_else(snapshot_filename);

    let dest = state.storage.join(&name);
    if let Err(e) = fs::write(&dest, &body).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("write failed: {e}\n"),
        )
            .into_response();
    }

    let _ = crate::audit::log(&crate::audit::AuditEvent::Push {
        snapshot: &name,
        destination: "server",
    });

    eprintln!("[server] received {} ({} bytes)", name, body.len());
    (StatusCode::CREATED, format!("{name}\n")).into_response()
}

#[derive(Serialize)]
struct SnapshotEntry {
    name: String,
    size_bytes: u64,
}

async fn list_snapshots(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !auth_ok(&state, &headers) {
        return (StatusCode::UNAUTHORIZED, "missing or invalid token\n").into_response();
    }

    let mut entries: Vec<SnapshotEntry> = Vec::new();
    let mut dir = match fs::read_dir(&state.storage).await {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("read_dir failed: {e}\n"),
            )
                .into_response()
        }
    };

    while let Ok(Some(entry)) = dir.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".rwd") {
            continue;
        }
        let size_bytes = entry.metadata().await.map(|m| m.len()).unwrap_or(0);
        entries.push(SnapshotEntry { name, size_bytes });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    Json(entries).into_response()
}

async fn download_snapshot(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> impl IntoResponse {
    if !auth_ok(&state, &headers) {
        return (StatusCode::UNAUTHORIZED, "missing or invalid token\n").into_response();
    }
    if !is_safe_filename(&name) {
        return (StatusCode::BAD_REQUEST, "invalid filename\n").into_response();
    }

    let path = state.storage.join(&name);
    match fs::read(&path).await {
        Ok(data) => (StatusCode::OK, data).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "not found\n").into_response(),
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn auth_ok(state: &ServerState, headers: &HeaderMap) -> bool {
    match &state.token {
        None => true,
        Some(expected) => {
            let provided = headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .unwrap_or("");
            provided == expected
        }
    }
}

fn is_safe_filename(name: &str) -> bool {
    !name.is_empty()
        && name.ends_with(".rwd")
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | 'T' | 'Z'))
}

fn snapshot_filename() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("incident-{secs}.rwd")
}

// ── Agent-side push client ────────────────────────────────────────────────────

pub async fn push_agent(args: PushAgentArgs) -> Result<()> {
    let data = tokio::fs::read(&args.snapshot).await?;
    let name = args
        .snapshot
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("snapshot.rwd")
        .to_string();

    let url = format!("{}/snapshots", args.server.trim_end_matches('/'));

    let mut req = reqwest::Client::new()
        .post(&url)
        .header("content-type", "application/octet-stream")
        .header("x-rewind-snapshot", &name)
        .body(data);

    if let Some(token) = &args.token {
        req = req.header("authorization", format!("Bearer {token}"));
    }

    let resp = req.send().await?;
    if resp.status().is_success() {
        println!(
            "Pushed {} → {} ({})",
            args.snapshot.display(),
            args.server,
            resp.status()
        );
        Ok(())
    } else {
        anyhow::bail!(
            "server returned {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default().trim()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_filename_accepts_valid() {
        assert!(is_safe_filename("incident-20260419T120000Z.rwd"));
        assert!(is_safe_filename("my_snapshot.rwd"));
    }

    #[test]
    fn safe_filename_rejects_traversal() {
        assert!(!is_safe_filename("../etc/passwd"));
        assert!(!is_safe_filename("/abs/path.rwd"));
        assert!(!is_safe_filename("no-extension"));
    }

    #[test]
    fn snapshot_filename_ends_with_rwd() {
        assert!(snapshot_filename().ends_with(".rwd"));
    }

    #[test]
    fn auth_ok_when_no_token() {
        let state = ServerState {
            storage: PathBuf::from("/tmp"),
            token: None,
        };
        assert!(auth_ok(&state, &HeaderMap::new()));
    }

    #[test]
    fn auth_fails_wrong_token() {
        let state = ServerState {
            storage: PathBuf::from("/tmp"),
            token: Some("secret".to_string()),
        };
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer wrong".parse().unwrap());
        assert!(!auth_ok(&state, &h));
    }

    #[test]
    fn auth_passes_correct_token() {
        let state = ServerState {
            storage: PathBuf::from("/tmp"),
            token: Some("secret".to_string()),
        };
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer secret".parse().unwrap());
        assert!(auth_ok(&state, &h));
    }
}
