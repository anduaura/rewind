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
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Json, Redirect},
    routing::{delete, get, post},
    Router,
};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};

use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::fs;
use tokio::sync::Mutex as TokioMutex;

use crate::cli::{PushAgentArgs, ServerArgs};
use crate::metrics::Metrics;
use crate::oidc::OidcValidator;
use crate::storage::Backend;

// ── TLS helpers ───────────────────────────────────────────────────────────────

fn load_tls_config(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> Result<rustls::ServerConfig> {
    let cert_bytes = std::fs::read(cert_path)
        .map_err(|e| anyhow::anyhow!("reading cert {:?}: {e}", cert_path))?;
    let key_bytes =
        std::fs::read(key_path).map_err(|e| anyhow::anyhow!("reading key {:?}: {e}", key_path))?;

    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_bytes.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("parsing cert: {e}"))?
            .into_iter()
            .map(|c| c.into_owned())
            .collect();

    let key = rustls_pemfile::private_key(&mut key_bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("parsing key: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {:?}", key_path))?
        .clone_key();

    Ok(rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?)
}

async fn serve_tls(
    app: axum::Router,
    addr: std::net::SocketAddr,
    cert: &std::path::Path,
    key: &std::path::Path,
) -> Result<()> {
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as HyperBuilder;
    use tokio_rustls::TlsAcceptor;
    use tower::ServiceExt as _;

    let tls_cfg = load_tls_config(cert, key)?;
    let acceptor = TlsAcceptor::from(std::sync::Arc::new(tls_cfg));
    let listener = tokio::net::TcpListener::bind(addr).await?;

    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            let tls = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("TLS handshake failed from {peer}: {e}");
                    return;
                }
            };
            let io = TokioIo::new(tls);
            let svc =
                hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let app = app.clone();
                    async move {
                        let (parts, body) = req.into_parts();
                        let req = hyper::Request::from_parts(parts, axum::body::Body::new(body));
                        app.oneshot(req).await
                    }
                });
            if let Err(e) = HyperBuilder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(io, svc)
                .await
            {
                tracing::error!("connection error: {e}");
            }
        });
    }
}

/// Permission level for a token.
#[derive(Clone, Debug, PartialEq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    /// Upload snapshots only.
    Write,
    /// Download and list snapshots only.
    Read,
    /// Full access (upload, download, list, share links).
    Admin,
}

impl Permission {
    pub fn can_read(&self) -> bool {
        matches!(self, Self::Read | Self::Admin)
    }
    pub fn can_write(&self) -> bool {
        matches!(self, Self::Write | Self::Admin)
    }
}

/// Resolved identity after authentication.
pub struct TeamAccess {
    pub team: String,
    pub perm: Permission,
}

/// Per-token entry in the registry (rich format).
#[derive(serde::Deserialize)]
struct TokenEntry {
    team: String,
    #[serde(default = "default_perm")]
    perm: Permission,
}

fn default_perm() -> Permission {
    Permission::Admin
}

/// Maps bearer token → team + permission for RBAC.
///
/// The JSON file supports two formats:
///
///   Simple (backward-compatible): `{"token": "team-name"}`
///   Rich:  `{"token": {"team": "team-name", "perm": "read|write|admin"}}`
///
/// Tokens in simple format are granted `admin` permission.
/// Mixed files are accepted.
#[derive(Clone, Default)]
pub struct TokenRegistry(HashMap<String, (String, Permission)>);

impl TokenRegistry {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        let v: serde_json::Value = serde_json::from_str(&raw)?;
        let obj = v.as_object().ok_or_else(|| anyhow::anyhow!("tokens file must be a JSON object"))?;
        let mut map = HashMap::new();
        for (token, val) in obj {
            let (team, perm) = if let Some(s) = val.as_str() {
                (s.to_string(), Permission::Admin)
            } else {
                let entry: TokenEntry = serde_json::from_value(val.clone())
                    .map_err(|e| anyhow::anyhow!("invalid entry for token '{token}': {e}"))?;
                (entry.team, entry.perm)
            };
            map.insert(token.clone(), (team, perm));
        }
        Ok(Self(map))
    }

    /// Resolve a bearer token → `TeamAccess`.  Returns `None` if the token is not registered.
    pub fn resolve(&self, token: &str) -> Option<TeamAccess> {
        self.0.get(token).map(|(team, perm)| TeamAccess {
            team: team.clone(),
            perm: perm.clone(),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[cfg(test)]
    pub fn load_from_str(s: &str) -> Result<Self> {
        let tmp = tempfile::NamedTempFile::new()?;
        std::fs::write(tmp.path(), s)?;
        Self::load(tmp.path())
    }
}

struct ShareEntry {
    team: String,
    name: String,
    expires_at: u64,
}

/// Sliding-window rate limiter: tracks upload timestamps per client IP.
struct RateLimiter {
    max_per_min: u32,
    window: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl RateLimiter {
    fn new(max_per_min: u32) -> Self {
        Self {
            max_per_min,
            window: Mutex::new(HashMap::new()),
        }
    }

    /// Returns `true` if the IP is within the rate limit; `false` if it should be rejected.
    fn check(&self, ip: &str) -> bool {
        if self.max_per_min == 0 {
            return true;
        }
        let mut w = self.window.lock().unwrap();
        let now = Instant::now();
        let entry = w.entry(ip.to_string()).or_default();
        entry.retain(|t| now.duration_since(*t).as_secs() < 60);
        if entry.len() < self.max_per_min as usize {
            entry.push_back(now);
            true
        } else {
            false
        }
    }
}

#[derive(Clone)]
struct ServerState {
    /// Pluggable storage backend (local FS or object store for HA deployments).
    backend: Arc<Backend>,
    /// Fallback single token (no team namespacing).
    token: Option<String>,
    /// Multi-team RBAC registry (takes precedence over `token`).
    registry: Arc<TokenRegistry>,
    /// In-memory share tokens → (team, name, expiry unix secs).
    shares: Arc<TokioMutex<HashMap<String, ShareEntry>>>,
    /// Per-IP upload rate limiter.
    rate_limiter: Arc<RateLimiter>,
    /// Max allowed upload body in bytes (0 = unlimited).
    max_body_bytes: usize,
    /// Prometheus metrics for the collection server.
    metrics: Arc<Metrics>,
    /// OIDC JWT validator (present when --oidc-issuer is set).
    oidc: Option<Arc<OidcValidator>>,
}

pub async fn run(args: ServerArgs) -> Result<()> {

    let registry = if let Some(p) = &args.tokens_file {
        TokenRegistry::load(p)?
    } else {
        TokenRegistry::default()
    };

    let max_body_bytes = (args.max_snapshot_mb as usize).saturating_mul(1024 * 1024);
    let metrics = Arc::new(Metrics::new(0));

    let oidc = match &args.oidc_issuer {
        Some(issuer) => {
            let audience = args
                .oidc_audience
                .clone()
                .unwrap_or_else(|| issuer.clone());
            Some(Arc::new(OidcValidator::new(
                issuer.clone(),
                audience,
                args.oidc_team_claim.clone(),
            )))
        }
        None => None,
    };

    // Build storage backend — remote object store wins over local path.
    let backend: Arc<Backend> = Arc::new(if let Some(url) = &args.storage_url {
        Backend::from_url(url)?
    } else {
        fs::create_dir_all(&args.storage).await?;
        Backend::Local(args.storage.clone())
    });

    let instance_id = args
        .instance_id
        .clone()
        .or_else(|| hostname::get().ok().and_then(|h| h.into_string().ok()))
        .unwrap_or_else(|| "rewind-0".to_string());

    let state = Arc::new(ServerState {
        backend: Arc::clone(&backend),
        token: args.token.clone(),
        registry: Arc::new(registry),
        shares: Arc::new(TokioMutex::new(HashMap::new())),
        rate_limiter: Arc::new(RateLimiter::new(args.rate_limit)),
        max_body_bytes,
        metrics: Arc::clone(&metrics),
        oidc: oidc.clone(),
    });

    // Leader election background task — only the leader runs retention jobs.
    {
        let backend_clone = Arc::clone(&backend);
        let iid = instance_id.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                std::time::Duration::from_secs(crate::storage::LEADER_TTL_SECS / 2),
            );
            loop {
                interval.tick().await;
                let is_leader = backend_clone.try_become_leader(&iid).await;
                tracing::debug!(instance_id = %iid, is_leader, "leader election tick");
            }
        });
    }

    let body_limit = if args.max_snapshot_mb > 0 {
        DefaultBodyLimit::max(max_body_bytes)
    } else {
        DefaultBodyLimit::disable()
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(server_metrics))
        .route("/snapshots", post(upload_snapshot))
        .route("/snapshots", get(list_snapshots))
        .route("/snapshots/:name", get(download_snapshot))
        .route("/snapshots/:name", delete(api_delete_snapshot))
        .route("/snapshots/:name/share", post(create_share_link))
        .route("/ui", get(ui_dashboard))
        .route("/ui/:name", get(ui_snapshot_detail))
        .route("/ui/:name/delete", post(ui_delete_snapshot))
        .route("/share/:token", get(download_shared))
        .layer(body_limit)
        .with_state(state.clone());

    println!("rewind server");
    println!("  listen:   {}", args.listen);
    println!("  instance: {instance_id}");
    if let Some(url) = &args.storage_url {
        println!("  storage:  {url} (object store — HA mode)");
    } else {
        println!("  storage:  {}", args.storage.display());
    }
    if args.oidc_issuer.is_some() {
        println!(
            "  auth:    OIDC JWT (issuer={}, audience={}, team_claim={})",
            args.oidc_issuer.as_deref().unwrap_or(""),
            args.oidc_audience.as_deref().unwrap_or("<issuer>"),
            args.oidc_team_claim,
        );
    } else if args.tokens_file.is_some() {
        println!(
            "  auth:    RBAC token registry ({} teams)",
            state.registry.len()
        );
    } else if args.token.is_some() {
        println!("  auth:    Authorization: Bearer <token> required");
    }
    if args.max_snapshot_mb > 0 {
        println!("  limit:   {} MB max upload size", args.max_snapshot_mb);
    }
    if args.rate_limit > 0 {
        println!("  rate:    {} uploads/min per IP", args.rate_limit);
    }
    println!("  POST /snapshots        — upload");
    println!("  GET  /snapshots        — list");
    println!("  GET  /snapshots/<name> — download");

    let addr: std::net::SocketAddr = args
        .listen
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid listen address: {}", args.listen))?;

    match (&args.tls_cert, &args.tls_key) {
        (Some(cert), Some(key)) => {
            println!("  tls:     enabled (cert={})", cert.display());
            serve_tls(app, addr, cert, key).await?;
        }
        (None, None) => {
            println!("  tls:     disabled (use --tls-cert + --tls-key to enable HTTPS)");
            let listener = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(listener, app).await?;
        }
        _ => {
            anyhow::bail!("--tls-cert and --tls-key must be provided together");
        }
    }
    Ok(())
}

// ── Handlers ─────────────────────────────────────────────────────────────────

async fn healthz() -> &'static str {
    "ok\n"
}

async fn server_metrics(State(state): State<Arc<ServerState>>) -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.metrics.prometheus_text(),
    )
}

async fn upload_snapshot(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let access = match resolve_team(&state, &headers).await {
        Some(a) => a,
        None => {
            state.metrics.inc_server_upload_error();
            return (StatusCode::UNAUTHORIZED, "missing or invalid token\n").into_response();
        }
    };
    if !access.perm.can_write() {
        state.metrics.inc_server_upload_error();
        return (StatusCode::FORBIDDEN, "token does not have write permission\n").into_response();
    }
    let team = access.team;

    let client_ip = extract_client_ip(&headers);
    if !state.rate_limiter.check(&client_ip) {
        state.metrics.inc_server_upload_error();
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded\n").into_response();
    }

    if body.is_empty() {
        state.metrics.inc_server_upload_error();
        return (StatusCode::BAD_REQUEST, "empty body\n").into_response();
    }

    if state.max_body_bytes > 0 && body.len() > state.max_body_bytes {
        state.metrics.inc_server_upload_error();
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            "snapshot exceeds size limit\n",
        )
            .into_response();
    }

    // Name: X-Rewind-Snapshot header, else timestamp-based.
    let filename = headers
        .get("x-rewind-snapshot")
        .and_then(|v| v.to_str().ok())
        .filter(|s| is_safe_filename(s))
        .map(|s| s.to_string())
        .unwrap_or_else(snapshot_filename);

    if let Err(e) = state.backend.put(&team, &filename, body.clone()).await {
        state.metrics.inc_server_upload_error();
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("storage write failed: {e}\n"),
        )
            .into_response();
    }

    let _ = crate::audit::log(&crate::audit::AuditEvent::Push {
        snapshot: &filename,
        destination: "server",
    });

    state.metrics.inc_server_upload();
    tracing::info!(team, filename, bytes = body.len(), "snapshot received");
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
    let access = match resolve_team(&state, &headers).await {
        Some(a) => a,
        None => return (StatusCode::UNAUTHORIZED, "missing or invalid token\n").into_response(),
    };
    if !access.perm.can_read() {
        return (StatusCode::FORBIDDEN, "token does not have read permission\n").into_response();
    }
    let team = access.team;

    let raw = state.backend.list(&team).await.unwrap_or_default();
    let mut entries: Vec<SnapshotEntry> = raw
        .into_iter()
        .map(|(name, size_bytes)| SnapshotEntry { name, size_bytes })
        .collect();
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    Json(entries).into_response()
}

async fn download_snapshot(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let access = match resolve_team(&state, &headers).await {
        Some(a) => a,
        None => return (StatusCode::UNAUTHORIZED, "missing or invalid token\n").into_response(),
    };
    if !access.perm.can_read() {
        return (StatusCode::FORBIDDEN, "token does not have read permission\n").into_response();
    }
    let team = access.team;
    if !is_safe_filename(&name) {
        return (StatusCode::BAD_REQUEST, "invalid filename\n").into_response();
    }

    match state.backend.get(&team, &name).await {
        Ok(data) => (StatusCode::OK, data.to_vec()).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "not found\n").into_response(),
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Resolve a request to a team name (static token / registry logic only).
/// Used by tests and as the inner fallback for `resolve_team`.
fn resolve_team_static(state: &ServerState, headers: &HeaderMap) -> Option<TeamAccess> {
    let bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");

    if !state.registry.is_empty() {
        // RBAC mode: token must be in registry.
        state.registry.resolve(bearer)
    } else if let Some(expected) = &state.token {
        // Single-token mode: full admin access.
        if bearer == expected {
            Some(TeamAccess { team: "default".to_string(), perm: Permission::Admin })
        } else {
            None
        }
    } else {
        // Open server (no auth configured) — admin access.
        Some(TeamAccess { team: "default".to_string(), perm: Permission::Admin })
    }
}

/// Resolve a request to a `TeamAccess`.
/// OIDC JWT validation is tried first when configured; falls back to static tokens.
async fn resolve_team(state: &ServerState, headers: &HeaderMap) -> Option<TeamAccess> {
    if let Some(oidc) = &state.oidc {
        let bearer = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        if let Some(team) = oidc.validate(bearer).await {
            // OIDC tokens get admin access (team-scoped by OIDC claims).
            return Some(TeamAccess { team, perm: Permission::Admin });
        }
        // Fall through to static token check so mixed-auth environments work.
    }
    resolve_team_static(state, headers)
}

fn extract_client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
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

// ── Web UI handlers ───────────────────────────────────────────────────────────

async fn ui_dashboard(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let qt = params.get("token").map_or("", |s| s.as_str());
    let access = match resolve_team_with_qt(&state, &headers, qt).await {
        Some(a) if a.perm.can_read() => a,
        _ => {
            return Html(ui_shell(
                "rewind — unauthorized", "", "",
                r#"<div class="empty">
                  <p style="font-size:16px;font-weight:600;margin-bottom:8px">Authentication required</p>
                  <p>Append <code>?token=&lt;tok&gt;</code> to the URL or provide an <code>Authorization: Bearer</code> header.</p>
                </div>"#,
                "",
            )).into_response();
        }
    };
    let team = access.team;
    let tqs = if qt.is_empty() { String::new() } else { format!("?token={qt}") };

    let mut entries = state.backend.list(&team).await.unwrap_or_default();
    entries.sort_by(|a, b| b.0.cmp(&a.0)); // newest first
    let total_kb: u64 = entries.iter().map(|(_, sz)| sz).sum::<u64>() / 1024;
    let count = entries.len();

    let mut rows = String::new();
    for (name, sz) in &entries {
        let kb = sz / 1024;
        let name_esc = esc(name);
        let name_lower = name.to_lowercase();
        rows.push_str(&format!(
            r#"<tr data-text="{name_lower}"><td class="mono-cell"><a href="/ui/{name_esc}{tqs}">{name_esc}</a></td><td class="muted">{kb} KB</td><td><a class="btn btn-secondary btn-sm" href="/ui/{name_esc}{tqs}">Inspect</a> <a class="btn btn-secondary btn-sm" href="/snapshots/{name_esc}{tqs}" download>⬇</a></td></tr>"#
        ));
    }
    let empty = if entries.is_empty() {
        r#"<tr><td colspan="3" class="empty">No snapshots yet.</td></tr>"#
    } else { "" };

    let team_esc = esc(&team);
    let body = format!(r#"<h1 class="page-title">Snapshots</h1>
<p class="page-sub">Team: <strong>{team_esc}</strong> &middot; {count} snapshots &middot; {total_kb} KB total</p>
<div class="cards">
  <div class="card"><div class="card-label">Snapshots</div><div class="card-value">{count}</div></div>
  <div class="card"><div class="card-label">Total size</div><div class="card-value">{total_kb} KB</div></div>
</div>
<div class="toolbar">
  <input class="filter-input" id="snap-filter" type="text" placeholder="Filter snapshots…" oninput="filterTable(this,'snap-table')">
</div>
<div class="table-wrap">
  <table id="snap-table">
    <thead><tr><th>Name</th><th>Size</th><th>Actions</th></tr></thead>
    <tbody>{rows}{empty}</tbody>
  </table>
</div>"#);
    Html(ui_shell(&format!("rewind — {team_esc}"), &team, &tqs, &body, "")).into_response()
}

async fn ui_snapshot_detail(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let qt = params.get("token").map_or("", |s| s.as_str());
    let access = match resolve_team_with_qt(&state, &headers, qt).await {
        Some(a) if a.perm.can_read() => a,
        _ => return Html(ui_shell("unauthorized", "", "", "<p>Unauthorized.</p>", "")).into_response(),
    };
    let team = access.team.clone();
    let is_admin = access.perm == Permission::Admin;
    let tqs = if qt.is_empty() { String::new() } else { format!("?token={qt}") };

    if !is_safe_filename(&name) {
        return Html(ui_shell("error", &team, &tqs, "<p>Invalid snapshot name.</p>", "")).into_response();
    }
    let data = match state.backend.get(&team, &name).await {
        Ok(b) => b.to_vec(),
        Err(_) => return Html(ui_shell("not found", &team, &tqs, "<p>Snapshot not found.</p>", "")).into_response(),
    };

    let size_kb = data.len() / 1024;
    let name_esc = esc(&name);
    let back = format!(r#"<div class="breadcrumb"><a href="/ui{tqs}">← Snapshots</a></div>"#);

    if crate::crypto::is_encrypted(&data) {
        let body = format!(r#"{back}<h1 class="page-title mono">{name_esc}</h1>
<p class="page-sub">Encrypted snapshot &middot; {size_kb} KB</p>
<p style="margin-top:16px;color:var(--muted)"><a href="/snapshots/{name_esc}{tqs}" download>Download</a> and inspect with <code>rewind inspect --key &lt;passphrase&gt;</code>.</p>"#);
        return Html(ui_shell(&format!("rewind — {name_esc}"), &team, &tqs, &body, "")).into_response();
    }

    use crate::store::snapshot::Event;
    let Ok(snap) = serde_json::from_slice::<crate::store::snapshot::Snapshot>(&data) else {
        let body = format!(r#"{back}<h1 class="page-title mono">{name_esc}</h1>
<p>Could not parse snapshot ({size_kb} KB). <a href="/snapshots/{name_esc}{tqs}" download>Download</a>.</p>"#);
        return Html(ui_shell(&format!("rewind — {name_esc}"), &team, &tqs, &body, "")).into_response();
    };

    let (mut http_cnt, mut db_cnt, mut grpc_cnt, mut sys_cnt) = (0usize, 0usize, 0usize, 0usize);
    let recorded_at = format_ts_ns(snap.recorded_at_ns);
    let services_esc = esc(&snap.services.join(", "));
    let base_ts = snap.events.first().map(|e| ev_ts(e)).unwrap_or(0);

    let mut ev_rows = String::new();
    for (i, ev) in snap.events.iter().enumerate() {
        let ts = ev_ts(ev);
        let delta_ms = ts.saturating_sub(base_ts) / 1_000_000;
        let (type_badge, service, detail, search_text) = match ev {
            Event::Http(h) => {
                http_cnt += 1;
                let dir_cls = if h.direction == "inbound" { "badge-in" } else { "badge-out" };
                let dir_lbl = if h.direction == "inbound" { "IN" } else { "OUT" };
                let st = status_badge(h.status_code);
                let d = format!(r#"<span class="badge {dir_cls}">{dir_lbl}</span> <span class="mono-cell">{} {}</span> {st}"#, esc(&h.method), esc(&h.path));
                let s = format!("http {} {} {} {}", h.direction, h.method, h.path, h.status_code.map(|c|c.to_string()).unwrap_or_default());
                (r#"<span class="badge badge-http">HTTP</span>"#.to_string(), esc(&h.service), d, s)
            }
            Event::Db(d) => {
                db_cnt += 1;
                let proto_cls = if d.protocol == "redis" { "badge-teal" } else { "badge-db" };
                let det = format!(r#"<span class="badge {proto_cls}">{}</span> <span class="mono-cell">{}</span>"#, esc(&d.protocol.to_uppercase()), esc(&d.query));
                let s = format!("db {} {}", d.protocol, d.query);
                (r#"<span class="badge badge-db">DB</span>"#.to_string(), esc(&d.service), det, s)
            }
            Event::Grpc(g) => {
                grpc_cnt += 1;
                let det = format!(r#"<span class="mono-cell">{}</span>"#, esc(&g.path));
                let s = format!("grpc {}", g.path);
                (r#"<span class="badge badge-grpc">gRPC</span>"#.to_string(), esc(&g.service), det, s)
            }
            Event::Syscall(s) => {
                sys_cnt += 1;
                let det = format!(r#"<span class="mono-cell">{}</span> <span class="muted">→ {}</span>"#, esc(&s.kind), s.return_value);
                let sr = format!("syscall {} {}", s.kind, s.return_value);
                (r#"<span class="badge badge-sys">SYS</span>"#.to_string(), String::new(), det, sr)
            }
        };
        ev_rows.push_str(&format!(
            r#"<tr data-text="{sl}"><td class="muted" style="width:42px">{i}</td><td style="width:70px">{type_badge}</td><td class="muted" style="width:90px">{service}</td><td>{detail}</td><td class="muted" style="width:70px;text-align:right">+{delta_ms}ms</td></tr>"#,
            sl = esc(&search_text.to_lowercase()),
        ));
    }

    let delete_btn = if is_admin {
        format!(r#"<form method="post" action="/ui/{name}/delete{tqs}" style="display:inline" onsubmit="return confirm('Delete {name_esc}? This cannot be undone.')"><button type="submit" class="btn btn-danger">🗑 Delete</button></form>"#)
    } else { String::new() };

    let mermaid_src = crate::timeline::to_mermaid_inner(&snap);
    let mermaid_js = js_str(&mermaid_src);
    let has_diagram = !snap.events.is_empty();

    let diagram_html = if has_diagram {
        format!(r#"<div class="diagram-section">
  <div class="section-title">Sequence Diagram <button class="copy-btn" onclick="copyMermaid()">Copy source</button></div>
  <div class="diagram-wrap" id="diagram"><div style="color:var(--muted);font-size:12px">Loading diagram…</div></div>
</div>"#)
    } else { String::new() };

    let scripts = if has_diagram {
        format!(r#"<script type="module">
import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs';
mermaid.initialize({{startOnLoad:false,theme:'dark',securityLevel:'loose'}});
const src = `{mermaid_js}`;
window._mSrc = src;
(async()=>{{
  const el = document.getElementById('diagram');
  if(!el) return;
  try{{const {{svg}}=await mermaid.render('seq'+Date.now(),src);el.innerHTML=svg;el.querySelector('svg').style.maxWidth='100%';}}
  catch(e){{el.innerHTML='<pre style="white-space:pre-wrap;font-size:11px;color:var(--muted)">'+src.replace(/</g,'&lt;')+'</pre>';}}
}})();
</script><script>function copyMermaid(){{navigator.clipboard.writeText(window._mSrc||'').then(()=>showToast('Copied!'));}}</script>"#)
    } else { String::new() };

    let body = format!(r#"{back}
<h1 class="page-title mono">{name_esc}</h1>
<p class="page-sub">Recorded {recorded_at} &middot; {services_esc} &middot; {size_kb} KB</p>
<div class="cards">
  <div class="card"><div class="card-label">HTTP</div><div class="card-value blue">{http_cnt}</div></div>
  <div class="card"><div class="card-label">DB</div><div class="card-value purple">{db_cnt}</div></div>
  <div class="card"><div class="card-label">gRPC</div><div class="card-value teal">{grpc_cnt}</div></div>
  <div class="card"><div class="card-label">Syscall</div><div class="card-value gray">{sys_cnt}</div></div>
</div>
<div class="btn-group">
  <a class="btn btn-primary" href="/snapshots/{name_esc}{tqs}" download>⬇ Download</a>
  <button class="btn btn-secondary" id="share-btn" onclick="doShare()">🔗 Share (24h)</button>
  {delete_btn}
</div>
<div class="toolbar">
  <span class="section-title" style="margin:0">Events</span>
  <input class="filter-input" id="ev-filter" type="text" placeholder="Filter events…" oninput="filterTable(this,'ev-table')">
</div>
<div class="table-wrap">
  <table id="ev-table">
    <thead><tr><th style="width:42px">#</th><th style="width:70px">Type</th><th style="width:90px">Service</th><th>Detail</th><th style="width:70px;text-align:right">Offset</th></tr></thead>
    <tbody>{ev_rows}</tbody>
  </table>
</div>
{diagram_html}
<script>
async function doShare(){{
  const btn=document.getElementById('share-btn');
  btn.disabled=true;btn.textContent='Generating…';
  try{{
    const r=await fetch('/snapshots/{name_esc}/share{tqs}',{{method:'POST',headers:{{accept:'application/json'}}}});
    const d=await r.json();
    prompt('Share link (valid 24 h):',location.origin+d.share_url);
  }}catch(e){{showToast('Error: '+e.message);}}
  finally{{btn.disabled=false;btn.textContent='🔗 Share (24h)';}}
}}
</script>"#);
    Html(ui_shell(&format!("rewind — {name_esc}"), &team, &tqs, &body, &scripts)).into_response()
}

async fn ui_delete_snapshot(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let qt = params.get("token").map_or("", |s| s.as_str());
    let tqs = if qt.is_empty() { String::new() } else { format!("?token={qt}") };
    let access = match resolve_team_with_qt(&state, &headers, qt).await {
        Some(a) => a,
        None => return (StatusCode::UNAUTHORIZED, "unauthorized\n").into_response(),
    };
    if access.perm != Permission::Admin {
        return (StatusCode::FORBIDDEN, "admin permission required\n").into_response();
    }
    if !is_safe_filename(&name) {
        return (StatusCode::BAD_REQUEST, "invalid filename\n").into_response();
    }
    match state.backend.delete(&access.team, &name).await {
        Ok(()) => tracing::info!(team = access.team, name, "snapshot deleted via UI"),
        Err(e) => tracing::warn!(name, "UI delete failed: {e}"),
    }
    Redirect::to(&format!("/ui{tqs}")).into_response()
}

async fn api_delete_snapshot(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let access = match resolve_team(&state, &headers).await {
        Some(a) => a,
        None => return (StatusCode::UNAUTHORIZED, "missing or invalid token\n").into_response(),
    };
    if access.perm != Permission::Admin {
        return (StatusCode::FORBIDDEN, "admin permission required\n").into_response();
    }
    if !is_safe_filename(&name) {
        return (StatusCode::BAD_REQUEST, "invalid filename\n").into_response();
    }
    match state.backend.delete(&access.team, &name).await {
        Ok(()) => {
            tracing::info!(team = access.team, name, "snapshot deleted via API");
            (StatusCode::NO_CONTENT, "").into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("delete failed: {e}\n")).into_response(),
    }
}

async fn create_share_link(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let qt = params.get("token").map_or("", |s| s.as_str());
    let team = match resolve_team_ui(&state, &headers, qt).await {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, "unauthorized\n").into_response(),
    };
    if !is_safe_filename(&name) {
        return (StatusCode::BAD_REQUEST, "invalid filename\n").into_response();
    }
    if !state.backend.exists(&team, &name).await {
        return (StatusCode::NOT_FOUND, "not found\n").into_response();
    }

    let token = random_token();
    let expires_at = unix_now() + 86_400;
    state.shares.lock().await.insert(
        token.clone(),
        ShareEntry {
            team: team.clone(),
            name: name.clone(),
            expires_at,
        },
    );

    let accept = headers.get("accept").and_then(|v| v.to_str().ok()).unwrap_or("");
    if accept.contains("text/html") || params.contains_key("token") {
        let tqs = if qt.is_empty() { String::new() } else { format!("?token={qt}") };
        let url = format!("/share/{token}");
        let name_esc = esc(&name);
        let back = format!(r#"<div class="breadcrumb"><a href="/ui/{name_esc}{tqs}">← {name_esc}</a></div>"#);
        let body = format!(r#"{back}<h1 class="page-title">Share link created</h1>
<p class="page-sub">Valid for 24 hours</p>
<div style="margin-top:16px;background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px">
  <p class="mono-cell" style="word-break:break-all">{url}</p>
</div>
<div class="btn-group" style="margin-top:16px">
  <a class="btn btn-primary" href="{url}">⬇ Download via share link</a>
  <button class="btn btn-secondary" onclick="navigator.clipboard.writeText(location.origin+'{url}').then(()=>showToast('Copied!'))">Copy URL</button>
</div>"#);
        Html(ui_shell(&format!("rewind — {name_esc}"), &team, &tqs, &body, "")).into_response()
    } else {
        Json(serde_json::json!({ "share_url": format!("/share/{token}"), "expires_in_secs": 86_400 })).into_response()
    }
}

async fn download_shared(
    State(state): State<Arc<ServerState>>,
    Path(token): Path<String>,
) -> impl IntoResponse {
    let now = unix_now();
    let entry = {
        let mut shares = state.shares.lock().await;
        shares.retain(|_, e| e.expires_at > now);
        shares.get(&token).map(|e| (e.team.clone(), e.name.clone()))
    };
    match entry {
        None => (StatusCode::NOT_FOUND, "share link expired or not found\n").into_response(),
        Some((team, name)) => match state.backend.get(&team, &name).await {
            Ok(data) => (
                StatusCode::OK,
                [(
                    "content-disposition",
                    format!("attachment; filename=\"{name}\""),
                )],
                data.to_vec(),
            )
                .into_response(),
            Err(_) => (StatusCode::NOT_FOUND, "snapshot not found\n").into_response(),
        },
    }
}

// ── UI helpers ────────────────────────────────────────────────────────────────

fn ui_shell(title: &str, team: &str, tqs: &str, body: &str, scripts: &str) -> String {
    let team_badge = if team.is_empty() {
        String::new()
    } else {
        format!(r#"<span class="nav-team">{}</span>"#, esc(team))
    };
    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
:root{{--bg:#0f1117;--surface:#161b27;--border:#2a2f42;--text:#e2e8f0;--muted:#8892a4;--accent:#3b82f6;--green:#22c55e;--amber:#f59e0b;--red:#ef4444;--purple:#a855f7;--teal:#14b8a6}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,sans-serif;font-size:14px;line-height:1.5}}
code,.mono,.mono-cell{{font-family:'Cascadia Code','Fira Code',Menlo,monospace;font-size:12px}}
a{{color:var(--accent);text-decoration:none}}a:hover{{text-decoration:underline}}
nav{{background:var(--surface);border-bottom:1px solid var(--border);padding:0 24px;display:flex;align-items:center;gap:12px;height:48px}}
.nav-logo{{font-weight:700;font-size:16px;letter-spacing:-.3px;color:var(--text)}}
.nav-logo span{{color:var(--accent)}}
.nav-team{{margin-left:auto;font-size:12px;color:var(--muted);background:rgba(255,255,255,.05);padding:2px 10px;border-radius:12px;border:1px solid var(--border)}}
.container{{max-width:1100px;margin:0 auto;padding:32px 24px}}
.page-title{{font-size:20px;font-weight:600;margin-bottom:6px}}
.page-title.mono{{font-family:'Cascadia Code','Fira Code',Menlo,monospace;font-size:16px}}
.page-sub{{color:var(--muted);font-size:13px;margin-bottom:24px}}
.breadcrumb{{font-size:13px;color:var(--muted);margin-bottom:16px}}
.cards{{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}}
.card{{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px 20px;min-width:120px}}
.card-label{{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px}}
.card-value{{font-size:26px;font-weight:700}}
.card-value.blue{{color:var(--accent)}}.card-value.purple{{color:var(--purple)}}
.card-value.teal{{color:var(--teal)}}.card-value.gray{{color:var(--muted)}}
.toolbar{{display:flex;align-items:center;gap:12px;margin-bottom:12px}}
.filter-input{{background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:6px;padding:6px 12px;font-size:13px;width:260px;outline:none}}
.filter-input:focus{{border-color:var(--accent)}}.filter-input::placeholder{{color:var(--muted)}}
.table-wrap{{border:1px solid var(--border);border-radius:8px;overflow:hidden}}
table{{width:100%;border-collapse:collapse}}
th{{background:var(--surface);color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px;padding:10px 14px;text-align:left;font-weight:500;border-bottom:1px solid var(--border)}}
td{{padding:9px 14px;border-bottom:1px solid var(--border);vertical-align:middle}}
tr:last-child td{{border-bottom:none}}tr:hover td{{background:rgba(255,255,255,.02)}}
.badge{{display:inline-block;font-size:10px;font-weight:600;padding:2px 6px;border-radius:4px;letter-spacing:.3px;text-transform:uppercase}}
.badge-http{{background:rgba(59,130,246,.15);color:var(--accent)}}
.badge-db{{background:rgba(168,85,247,.15);color:var(--purple)}}
.badge-grpc{{background:rgba(20,184,166,.15);color:var(--teal)}}
.badge-teal{{background:rgba(20,184,166,.15);color:var(--teal)}}
.badge-sys{{background:rgba(136,146,164,.15);color:var(--muted)}}
.badge-in{{background:rgba(34,197,94,.12);color:var(--green)}}
.badge-out{{background:rgba(245,158,11,.12);color:var(--amber)}}
.s2xx{{background:rgba(34,197,94,.15);color:var(--green)}}.s3xx{{background:rgba(59,130,246,.15);color:var(--accent)}}
.s4xx{{background:rgba(245,158,11,.15);color:var(--amber)}}.s5xx{{background:rgba(239,68,68,.15);color:var(--red)}}
.btn{{display:inline-flex;align-items:center;gap:6px;padding:6px 14px;border-radius:6px;font-size:13px;font-weight:500;cursor:pointer;border:none;text-decoration:none!important}}
.btn-sm{{padding:4px 10px;font-size:12px}}
.btn-primary{{background:var(--accent);color:#fff}}.btn-primary:hover{{background:#2563eb}}
.btn-secondary{{background:var(--surface);color:var(--text);border:1px solid var(--border)}}
.btn-secondary:hover{{border-color:var(--accent);color:var(--accent)}}
.btn-danger{{background:rgba(239,68,68,.1);color:var(--red);border:1px solid rgba(239,68,68,.25)}}
.btn-danger:hover{{background:rgba(239,68,68,.2)}}
.btn-group{{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:20px}}
.section-title{{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);display:flex;align-items:center;gap:8px}}
.diagram-section{{margin-top:28px}}
.diagram-wrap{{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:24px;overflow-x:auto;min-height:80px}}
.copy-btn{{background:none;border:1px solid var(--border);color:var(--muted);border-radius:4px;padding:3px 10px;font-size:11px;cursor:pointer}}
.copy-btn:hover{{color:var(--text);border-color:var(--muted)}}
.empty{{text-align:center;color:var(--muted);padding:48px}}
#toast{{position:fixed;bottom:20px;right:20px;background:var(--surface);border:1px solid var(--green);color:var(--green);border-radius:8px;padding:10px 16px;font-size:13px;opacity:0;transition:opacity .3s;pointer-events:none}}
</style>
</head>
<body>
<nav>
  <a href="/ui{tqs}" class="nav-logo" style="text-decoration:none">re<span>wind</span></a>
  {team_badge}
</nav>
<div class="container">
{body}
</div>
<div id="toast"></div>
<script>
function filterTable(input,tableId){{const q=input.value.toLowerCase();document.querySelectorAll('#'+tableId+' tbody tr').forEach(r=>{{r.style.display=(r.dataset.text||'').includes(q)?'':'none';}});}}
function showToast(msg){{const t=document.getElementById('toast');t.textContent=msg;t.style.opacity='1';clearTimeout(t._tid);t._tid=setTimeout(()=>t.style.opacity='0',2200);}}
</script>
{scripts}
</body>
</html>"#,
        tqs = tqs,
    )
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn js_str(s: &str) -> String {
    s.replace('\\', "\\\\").replace('`', "\\`").replace('$', "\\$")
}

fn status_badge(code: Option<u16>) -> String {
    match code {
        None => String::new(),
        Some(c) => {
            let cls = match c { 200..=299 => "s2xx", 300..=399 => "s3xx", 400..=499 => "s4xx", _ => "s5xx" };
            format!(r#"<span class="badge {cls}">{c}</span>"#)
        }
    }
}

fn ev_ts(ev: &crate::store::snapshot::Event) -> u64 {
    use crate::store::snapshot::Event;
    match ev {
        Event::Http(h) => h.timestamp_ns,
        Event::Db(d) => d.timestamp_ns,
        Event::Grpc(g) => g.timestamp_ns,
        Event::Syscall(s) => s.timestamp_ns,
    }
}

fn format_ts_ns(ns: u64) -> String {
    use chrono::{TimeZone, Utc};
    let secs = (ns / 1_000_000_000) as i64;
    Utc.timestamp_opt(secs, 0)
        .single()
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| secs.to_string())
}

async fn resolve_team_with_qt(
    state: &ServerState,
    headers: &HeaderMap,
    query_token: &str,
) -> Option<TeamAccess> {
    if !query_token.is_empty() {
        let mut h = headers.clone();
        if let Ok(v) = format!("Bearer {query_token}").parse() {
            h.insert(axum::http::header::AUTHORIZATION, v);
        }
        resolve_team(state, &h).await
    } else {
        resolve_team(state, headers).await
    }
}

async fn resolve_team_ui(
    state: &ServerState,
    headers: &HeaderMap,
    query_token: &str,
) -> Option<String> {
    resolve_team_with_qt(state, headers, query_token)
        .await
        .filter(|a| a.perm.can_read())
        .map(|a| a.team)
}

fn random_token() -> String {
    use std::io::Read;
    let mut buf = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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
            backend: Arc::new(Backend::Local(std::path::PathBuf::from("/tmp"))),
            token: token.map(|s| s.to_string()),
            registry: Arc::new(registry),
            shares: Arc::new(TokioMutex::new(HashMap::new())),
            rate_limiter: Arc::new(RateLimiter::new(10)),
            max_body_bytes: 100 * 1024 * 1024,
            metrics: Arc::new(Metrics::new(0)),
            oidc: None,
        }
    }

    #[test]
    fn open_server_resolves_to_default() {
        let state = make_state(None, TokenRegistry::default());
        let access = resolve_team_static(&state, &HeaderMap::new());
        assert!(access.is_some());
        assert_eq!(access.unwrap().team, "default");
    }

    #[test]
    fn single_token_wrong_returns_none() {
        let state = make_state(Some("secret"), TokenRegistry::default());
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer wrong".parse().unwrap());
        assert!(resolve_team_static(&state, &h).is_none());
    }

    #[test]
    fn single_token_correct_returns_default() {
        let state = make_state(Some("secret"), TokenRegistry::default());
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer secret".parse().unwrap());
        let access = resolve_team_static(&state, &h);
        assert!(access.is_some());
        let access = access.unwrap();
        assert_eq!(access.team, "default");
        assert_eq!(access.perm, Permission::Admin);
    }

    #[test]
    fn single_token_grants_admin_perm() {
        let state = make_state(Some("tok"), TokenRegistry::default());
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer tok".parse().unwrap());
        let access = resolve_team_static(&state, &h).unwrap();
        assert!(access.perm.can_read());
        assert!(access.perm.can_write());
    }

    #[test]
    fn rbac_registry_maps_token_to_team() {
        let mut map = std::collections::HashMap::new();
        map.insert("tok-a".to_string(), ("team-alpha".to_string(), Permission::Admin));
        let reg = TokenRegistry(map);
        let state = make_state(None, reg);
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer tok-a".parse().unwrap());
        let access = resolve_team_static(&state, &h);
        assert!(access.is_some());
        assert_eq!(access.unwrap().team, "team-alpha");
    }

    #[test]
    fn rbac_registry_unknown_token_returns_none() {
        let mut map = std::collections::HashMap::new();
        map.insert("tok-a".to_string(), ("team-alpha".to_string(), Permission::Admin));
        let reg = TokenRegistry(map);
        let state = make_state(None, reg);
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer tok-unknown".parse().unwrap());
        assert!(resolve_team_static(&state, &h).is_none());
    }

    #[test]
    fn rbac_registry_write_only_token_cannot_read() {
        let reg = TokenRegistry::load_from_str(
            r#"{"agent": {"team": "payments", "perm": "write"}}"#,
        )
        .unwrap();
        let state = make_state(None, reg);
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer agent".parse().unwrap());
        let access = resolve_team_static(&state, &h).unwrap();
        assert!(access.perm.can_write());
        assert!(!access.perm.can_read());
    }

    #[test]
    fn rbac_registry_read_only_token_cannot_write() {
        let reg = TokenRegistry::load_from_str(
            r#"{"dev": {"team": "payments", "perm": "read"}}"#,
        )
        .unwrap();
        let state = make_state(None, reg);
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer dev".parse().unwrap());
        let access = resolve_team_static(&state, &h).unwrap();
        assert!(access.perm.can_read());
        assert!(!access.perm.can_write());
    }

    #[test]
    fn rate_limiter_allows_up_to_limit() {
        let rl = RateLimiter::new(3);
        assert!(rl.check("10.0.0.1"));
        assert!(rl.check("10.0.0.1"));
        assert!(rl.check("10.0.0.1"));
        assert!(!rl.check("10.0.0.1")); // 4th exceeds limit
    }

    #[test]
    fn rate_limiter_unlimited_when_zero() {
        let rl = RateLimiter::new(0);
        for _ in 0..1000 {
            assert!(rl.check("10.0.0.1"));
        }
    }

    #[test]
    fn rate_limiter_separate_ips_independent() {
        let rl = RateLimiter::new(1);
        assert!(rl.check("1.1.1.1"));
        assert!(!rl.check("1.1.1.1")); // exhausted
        assert!(rl.check("2.2.2.2")); // different IP still allowed
    }

    #[test]
    fn extract_client_ip_uses_forwarded_for() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.5, 10.0.0.1".parse().unwrap());
        assert_eq!(extract_client_ip(&h), "203.0.113.5");
    }

    #[test]
    fn extract_client_ip_falls_back_to_real_ip() {
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", "203.0.113.99".parse().unwrap());
        assert_eq!(extract_client_ip(&h), "203.0.113.99");
    }

    #[test]
    fn extract_client_ip_unknown_when_no_header() {
        assert_eq!(extract_client_ip(&HeaderMap::new()), "unknown");
    }
}
