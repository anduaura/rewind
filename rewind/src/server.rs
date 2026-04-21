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
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::fs;
use tokio::sync::Mutex as TokioMutex;

use crate::cli::{PushAgentArgs, ServerArgs};
use crate::metrics::Metrics;
use crate::oidc::OidcValidator;

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
    storage: PathBuf,
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
    fs::create_dir_all(&args.storage).await?;

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

    let state = Arc::new(ServerState {
        storage: args.storage.clone(),
        token: args.token.clone(),
        registry: Arc::new(registry),
        shares: Arc::new(TokioMutex::new(HashMap::new())),
        rate_limiter: Arc::new(RateLimiter::new(args.rate_limit)),
        max_body_bytes,
        metrics: Arc::clone(&metrics),
        oidc: oidc.clone(),
    });

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
        .route("/snapshots/{name}", get(download_snapshot))
        .route("/snapshots/{name}/share", post(create_share_link))
        .route("/ui", get(ui_dashboard))
        .route("/ui/{name}", get(ui_snapshot_detail))
        .route("/share/{token}", get(download_shared))
        .layer(body_limit)
        .with_state(state.clone());

    println!("rewind server");
    println!("  listen:  {}", args.listen);
    println!("  storage: {}", args.storage.display());
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
            state.registry.0.len()
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
    let team = match resolve_team(&state, &headers).await {
        Some(t) => t,
        None => {
            state.metrics.inc_server_upload_error();
            return (StatusCode::UNAUTHORIZED, "missing or invalid token\n").into_response();
        }
    };

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

    // Team-namespaced storage sub-directory.
    let dir = state.storage.join(&team);
    if let Err(e) = fs::create_dir_all(&dir).await {
        state.metrics.inc_server_upload_error();
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("mkdir failed: {e}\n"),
        )
            .into_response();
    }

    let dest = dir.join(&filename);
    if let Err(e) = fs::write(&dest, &body).await {
        state.metrics.inc_server_upload_error();
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
    let team = match resolve_team(&state, &headers).await {
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
    let team = match resolve_team(&state, &headers).await {
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

/// Resolve a request to a team name (static token / registry logic only).
/// Used by tests and as the inner fallback for `resolve_team`.
fn resolve_team_static(state: &ServerState, headers: &HeaderMap) -> Option<String> {
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

/// Resolve a request to a team name.
/// OIDC JWT validation is tried first when configured; falls back to static tokens.
async fn resolve_team(state: &ServerState, headers: &HeaderMap) -> Option<String> {
    if let Some(oidc) = &state.oidc {
        let bearer = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        if let Some(team) = oidc.validate(bearer).await {
            return Some(team);
        }
        // Fall through to static token check so mixed-auth environments work
        // during migration (e.g. long-lived static tokens alongside OIDC).
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
    let team = match resolve_team_ui(&state, &headers, qt).await {
        Some(t) => t,
        None => {
            return Html(ui_page(
                "unauthorized",
                "<p>Append <code>?token=&lt;tok&gt;</code> to the URL.</p>",
            ))
            .into_response()
        }
    };

    let dir = state.storage.join(&team);
    let mut rows = String::new();
    if let Ok(mut rd) = fs::read_dir(&dir).await {
        let mut entries: Vec<(String, u64)> = Vec::new();
        while let Ok(Some(e)) = rd.next_entry().await {
            let name = e.file_name().to_string_lossy().to_string();
            if !name.ends_with(".rwd") {
                continue;
            }
            let sz = e.metadata().await.map(|m| m.len()).unwrap_or(0);
            entries.push((name, sz));
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let tqs = if qt.is_empty() {
            String::new()
        } else {
            format!("?token={qt}")
        };
        for (name, sz) in &entries {
            rows.push_str(&format!(
                "<tr><td><a href=\"/ui/{name}{tqs}\">{name}</a></td><td>{} KB</td><td><a href=\"/share/{name}{tqs}\">detail</a></td></tr>",
                sz / 1024
            ));
        }
    }
    let body = format!("<h2>Team: {team}</h2><table border=1 cellpadding=6><tr><th>Snapshot</th><th>Size</th><th>Actions</th></tr>{rows}</table>");
    Html(ui_page(&format!("rewind — {team}"), &body)).into_response()
}

async fn ui_snapshot_detail(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let qt = params.get("token").map_or("", |s| s.as_str());
    let team = match resolve_team_ui(&state, &headers, qt).await {
        Some(t) => t,
        None => return Html(ui_page("unauthorized", "<p>Unauthorized.</p>")).into_response(),
    };
    if !is_safe_filename(&name) {
        return Html(ui_page("error", "<p>Invalid snapshot name.</p>")).into_response();
    }
    let path = state.storage.join(&team).join(&name);
    let data = match fs::read(&path).await {
        Ok(d) => d,
        Err(_) => return Html(ui_page("not found", "<p>Snapshot not found.</p>")).into_response(),
    };

    let size_kb = data.len() / 1024;
    let tqs = if qt.is_empty() {
        String::new()
    } else {
        format!("?token={qt}")
    };

    let detail = if crate::crypto::is_encrypted(&data) {
        format!("<p><b>Encrypted</b> snapshot ({size_kb} KB). <a href=\"/snapshots/{name}{tqs}\">Download</a> and decrypt with <code>rewind inspect --key</code>.</p>")
    } else if let Ok(snap) = serde_json::from_slice::<crate::store::snapshot::Snapshot>(&data) {
        let (mut http, mut db, mut grpc, mut sys) = (0usize, 0usize, 0usize, 0usize);
        let mut rows = String::new();
        use crate::store::snapshot::Event;
        for (i, ev) in snap.events.iter().enumerate() {
            if i < 50 {
                let row = match ev {
                    Event::Http(h) => {
                        http += 1;
                        format!(
                            "<tr><td>{i}</td><td>HTTP</td><td>{} {} {:?}</td></tr>",
                            h.method, h.path, h.status_code
                        )
                    }
                    Event::Db(d) => {
                        db += 1;
                        format!("<tr><td>{i}</td><td>DB</td><td>{}</td></tr>", d.query)
                    }
                    Event::Grpc(g) => {
                        grpc += 1;
                        format!("<tr><td>{i}</td><td>gRPC</td><td>{}</td></tr>", g.path)
                    }
                    Event::Syscall(s) => {
                        sys += 1;
                        format!(
                            "<tr><td>{i}</td><td>SYSCALL</td><td>{} → {}</td></tr>",
                            s.kind, s.return_value
                        )
                    }
                };
                rows.push_str(&row);
            } else {
                match ev {
                    Event::Http(_) => http += 1,
                    Event::Db(_) => db += 1,
                    Event::Grpc(_) => grpc += 1,
                    Event::Syscall(_) => sys += 1,
                }
            }
        }
        let share_url = format!("/snapshots/{name}/share?token={qt}");
        format!(
            "<p>{size_kb} KB &nbsp;|&nbsp; services: {} &nbsp;|&nbsp; HTTP:{http} DB:{db} gRPC:{grpc} SYS:{sys}</p>\
             <p><a href=\"/snapshots/{name}{tqs}\">⬇ Download</a> &nbsp; <a href=\"{share_url}\">🔗 Share (24h)</a></p>\
             <table border=1 cellpadding=4><tr><th>#</th><th>Type</th><th>Detail</th></tr>{rows}</table>",
            snap.services.join(", ")
        )
    } else {
        format!("<p>Could not parse snapshot ({size_kb} KB). <a href=\"/snapshots/{name}{tqs}\">Download</a>.</p>")
    };

    let back = format!("<p><a href=\"/ui{tqs}\">← back</a></p>");
    Html(ui_page(
        &format!("rewind — {name}"),
        &format!("{back}<h2>{name}</h2>{detail}"),
    ))
    .into_response()
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
    if !state.storage.join(&team).join(&name).exists() {
        return (StatusCode::NOT_FOUND, "not found\n").into_response();
    }

    let token = random_token();
    let expires_at = unix_now() + 86_400;
    state.shares.lock().await.insert(
        token.clone(),
        ShareEntry {
            team,
            name: name.clone(),
            expires_at,
        },
    );

    let accept = headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if accept.contains("text/html") || params.contains_key("token") {
        let url = format!("/share/{token}");
        let body = format!("<h2>Share link for {name}</h2><p>Valid 24 hours:</p><pre>{url}</pre><p><a href=\"{url}\">{url}</a></p>");
        Html(ui_page("share link", &body)).into_response()
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
        Some((team, name)) => match fs::read(state.storage.join(&team).join(&name)).await {
            Ok(data) => (
                StatusCode::OK,
                [(
                    "content-disposition",
                    format!("attachment; filename=\"{name}\""),
                )],
                data,
            )
                .into_response(),
            Err(_) => (StatusCode::NOT_FOUND, "snapshot not found\n").into_response(),
        },
    }
}

// ── UI helpers ────────────────────────────────────────────────────────────────

fn ui_page(title: &str, body: &str) -> String {
    format!(
        "<!DOCTYPE html><html><head><meta charset=utf-8><title>{title}</title>\
         <style>body{{font-family:monospace;max-width:900px;margin:32px auto;padding:0 16px}}\
         table{{border-collapse:collapse}}a{{color:#06c}}</style></head>\
         <body><h1>rewind</h1>{body}</body></html>"
    )
}

async fn resolve_team_ui(
    state: &ServerState,
    headers: &HeaderMap,
    query_token: &str,
) -> Option<String> {
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
            storage: PathBuf::from("/tmp"),
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
        assert_eq!(
            resolve_team_static(&state, &HeaderMap::new()),
            Some("default".to_string())
        );
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
        assert_eq!(
            resolve_team_static(&state, &h),
            Some("default".to_string())
        );
    }

    #[test]
    fn rbac_registry_maps_token_to_team() {
        let mut map = std::collections::HashMap::new();
        map.insert("tok-a".to_string(), "team-alpha".to_string());
        let reg = TokenRegistry(map);
        let state = make_state(None, reg);
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer tok-a".parse().unwrap());
        assert_eq!(
            resolve_team_static(&state, &h),
            Some("team-alpha".to_string())
        );
    }

    #[test]
    fn rbac_registry_unknown_token_returns_none() {
        let mut map = std::collections::HashMap::new();
        map.insert("tok-a".to_string(), "team-alpha".to_string());
        let reg = TokenRegistry(map);
        let state = make_state(None, reg);
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer tok-unknown".parse().unwrap());
        assert!(resolve_team_static(&state, &h).is_none());
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
