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
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;

use crate::cli::{PushAgentArgs, ServerArgs};

/// Maps bearer token → team name for RBAC.
/// Loaded from a JSON file: {"token1": "team-a", "token2": "team-b"}
#[derive(Clone, Default)]
pub struct TokenRegistry(HashMap<String, String>);

impl TokenRegistry {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        let map: HashMap<String, String> = serde_json::from_str(&raw)?;
        Ok(Self(map))
    }

    /// Resolve a bearer token → team name.
    /// Returns None if the token is invalid.
    pub fn resolve(&self, token: &str) -> Option<&str> {
        self.0.get(token).map(|s| s.as_str())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Clone)]
struct ServerState {
    storage: PathBuf,
    /// Fallback single token (no team namespacing).
    token: Option<String>,
    /// Multi-team RBAC registry (takes precedence over `token`).
    registry: Arc<TokenRegistry>,
}

pub async fn run(args: ServerArgs) -> Result<()> {
    fs::create_dir_all(&args.storage).await?;

    let registry = if let Some(p) = &args.tokens_file {
        TokenRegistry::load(p)?
    } else {
        TokenRegistry::default()
    };

    let state = Arc::new(ServerState {
        storage: args.storage.clone(),
        token: args.token.clone(),
        registry: Arc::new(registry),
    });

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/snapshots", post(upload_snapshot))
        .route("/snapshots", get(list_snapshots))
        .route("/snapshots/{name}", get(download_snapshot))
        .with_state(state.clone());

    println!("rewind server");
    println!("  listen:  {}", args.listen);
    println!("  storage: {}", args.storage.display());
    if args.tokens_file.is_some() {
        println!(
            "  auth:    RBAC token registry ({} teams)",
            state.registry.0.len()
        );
    } else if args.token.is_some() {
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
    let team = match resolve_team(&state, &headers) {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, "missing or invalid token\n").into_response(),
    };

    if body.is_empty() {
        return (StatusCode::BAD_REQUEST, "empty body\n").into_response();
    }

    // Name: X-Rewind-Snapshot header, else timestamp-based.
    let filename = headers
        .get("x-rewind-snapshot")
        .and_then(|v| v.to_str().ok())
        .filter(|s| is_safe_filename(s))
        .map(|s| s.to_string())
        .unwrap_or_else(snapshot_filename);

    // Team-namespaced storage sub-directory.
    let dir = state.storage.join(&team);
    if let Err(e) = fs::create_dir_all(&dir).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("mkdir failed: {e}\n"),
        )
            .into_response();
    }

    let dest = dir.join(&filename);
    if let Err(e) = fs::write(&dest, &body).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("write failed: {e}\n"),
        )
            .into_response();
    }

    let _ = crate::audit::log(&crate::audit::AuditEvent::Push {
        snapshot: &filename,
        destination: "server",
    });

    eprintln!(
        "[server] [{team}] received {} ({} bytes)",
        filename,
        body.len()
    );
    (StatusCode::CREATED, format!("{team}/{filename}\n")).into_response()
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
    let team = match resolve_team(&state, &headers) {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, "missing or invalid token\n").into_response(),
    };

    let dir = state.storage.join(&team);
    let mut entries: Vec<SnapshotEntry> = Vec::new();
    let mut read_dir = match fs::read_dir(&dir).await {
        Ok(d) => d,
        Err(_) => return Json(entries).into_response(), // empty team dir → empty list
    };

    while let Ok(Some(entry)) = read_dir.next_entry().await {
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
    let team = match resolve_team(&state, &headers) {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, "missing or invalid token\n").into_response(),
    };
    if !is_safe_filename(&name) {
        return (StatusCode::BAD_REQUEST, "invalid filename\n").into_response();
    }

    let path = state.storage.join(&team).join(&name);
    match fs::read(&path).await {
        Ok(data) => (StatusCode::OK, data).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "not found\n").into_response(),
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Resolve a request to a team name.
/// - No auth configured → "default" team (open server)
/// - RBAC registry active → look up token → team name
/// - Single token mode → token must match → "default" team
fn resolve_team(state: &ServerState, headers: &HeaderMap) -> Option<String> {
    let bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");

    if !state.registry.is_empty() {
        // RBAC mode: token must be in registry.
        state.registry.resolve(bearer).map(|t| t.to_string())
    } else if let Some(expected) = &state.token {
        // Single-token mode.
        if bearer == expected {
            Some("default".to_string())
        } else {
            None
        }
    } else {
        // Open server (no auth configured).
        Some("default".to_string())
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

    fn make_state(token: Option<&str>, registry: TokenRegistry) -> ServerState {
        ServerState {
            storage: PathBuf::from("/tmp"),
            token: token.map(|s| s.to_string()),
            registry: Arc::new(registry),
        }
    }

    #[test]
    fn open_server_resolves_to_default() {
        let state = make_state(None, TokenRegistry::default());
        assert_eq!(
            resolve_team(&state, &HeaderMap::new()),
            Some("default".to_string())
        );
    }

    #[test]
    fn single_token_wrong_returns_none() {
        let state = make_state(Some("secret"), TokenRegistry::default());
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer wrong".parse().unwrap());
        assert!(resolve_team(&state, &h).is_none());
    }

    #[test]
    fn single_token_correct_returns_default() {
        let state = make_state(Some("secret"), TokenRegistry::default());
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer secret".parse().unwrap());
        assert_eq!(resolve_team(&state, &h), Some("default".to_string()));
    }

    #[test]
    fn rbac_registry_maps_token_to_team() {
        let mut map = std::collections::HashMap::new();
        map.insert("tok-a".to_string(), "team-alpha".to_string());
        let reg = TokenRegistry(map);
        let state = make_state(None, reg);
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer tok-a".parse().unwrap());
        assert_eq!(resolve_team(&state, &h), Some("team-alpha".to_string()));
    }

    #[test]
    fn rbac_registry_unknown_token_returns_none() {
        let mut map = std::collections::HashMap::new();
        map.insert("tok-a".to_string(), "team-alpha".to_string());
        let reg = TokenRegistry(map);
        let state = make_state(None, reg);
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer tok-unknown".parse().unwrap());
        assert!(resolve_team(&state, &h).is_none());
    }
}
