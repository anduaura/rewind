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

//! Auto-trigger webhook — PagerDuty / Opsgenie can POST to this endpoint and
//! rewind will immediately flush the in-memory ring buffer to a timestamped
//! snapshot file.
//!
//! Start alongside `rewind record`:
//!   rewind webhook --listen 0.0.0.0:9091 --output-dir /var/rewind/snapshots
//!
//! PagerDuty webhook v3 (generic): POST /webhook
//! Opsgenie outbound webhook:      POST /webhook
//! Generic curl test:              curl -X POST http://localhost:9091/webhook
//!
//! Optional auth: set --secret (or REWIND_WEBHOOK_SECRET). When set, every
//! request must carry the header  X-Rewind-Secret: <value>.

use anyhow::Result;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::cli::WebhookArgs;

const SOCKET_PATH: &str = "/tmp/rewind.sock";

#[derive(Clone)]
struct AppState {
    output_dir: PathBuf,
    window: String,
    secret: Option<String>,
}

pub async fn run(args: WebhookArgs) -> Result<()> {
    let state = Arc::new(AppState {
        output_dir: args.output_dir,
        window: args.window,
        secret: args.secret,
    });

    println!("rewind webhook");
    println!("  listen:  {}", args.listen);
    println!("  output:  {}", state.output_dir.display());
    println!("  window:  {}", state.window);
    if state.secret.is_some() {
        println!("  auth:    X-Rewind-Secret required");
    }

    let app = Router::new()
        .route("/webhook", post(handle_webhook))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    println!("Waiting for alerts… POST /webhook to trigger a flush");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn handle_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    // Optional secret check.
    if let Some(expected) = &state.secret {
        let provided = headers
            .get("x-rewind-secret")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if provided != expected {
            return (
                StatusCode::UNAUTHORIZED,
                "invalid or missing X-Rewind-Secret\n",
            )
                .into_response();
        }
    }

    let alert_source = detect_source(&headers, &body);
    let ts = timestamp_tag();
    let filename = format!("incident-{ts}.rwd");
    let output = state.output_dir.join(&filename);

    eprintln!(
        "[webhook] alert from {alert_source} → flushing to {}",
        output.display()
    );

    match trigger_flush(&state.window, &output).await {
        Ok(count) => {
            let msg = format!("flushed {count} events to {filename}\n");
            eprintln!("[webhook] {}", msg.trim());
            (StatusCode::OK, msg).into_response()
        }
        Err(e) => {
            let msg = format!("flush failed: {e}\n");
            eprintln!("[webhook] {}", msg.trim());
            (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response()
        }
    }
}

/// Send a FLUSH IPC command to the running agent and return the event count.
async fn trigger_flush(window: &str, output: &std::path::Path) -> Result<usize> {
    let window_secs = parse_window_secs(window)?;

    let mut stream = UnixStream::connect(SOCKET_PATH).await?;
    let msg = format!("FLUSH {} {}\n", window_secs, output.display());
    stream.write_all(msg.as_bytes()).await?;

    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response).await?;
    let response = response.trim();

    if let Some(rest) = response.strip_prefix("OK ") {
        Ok(rest.parse().unwrap_or(0))
    } else if let Some(err) = response.strip_prefix("ERR ") {
        anyhow::bail!("agent error: {err}")
    } else {
        anyhow::bail!("unexpected agent response: {response}")
    }
}

fn timestamp_tag() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let s = secs % 60;
    secs /= 60;
    let mi = secs % 60;
    secs /= 60;
    let h = secs % 24;
    secs /= 24;
    // Approximate year/month/day (good enough for a filename tag).
    let year = 1970 + secs / 365;
    let doy = secs % 365;
    let mo = doy / 30 + 1;
    let d = doy % 30 + 1;
    format!("{year:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}Z")
}

fn parse_window_secs(window: &str) -> Result<u64> {
    if let Some(n) = window.strip_suffix('m') {
        Ok(n.parse::<u64>()? * 60)
    } else if let Some(n) = window.strip_suffix('s') {
        Ok(n.parse::<u64>()?)
    } else if let Some(n) = window.strip_suffix('h') {
        Ok(n.parse::<u64>()? * 3600)
    } else {
        window
            .parse::<u64>()
            .map_err(|e| anyhow::anyhow!("invalid window '{window}': {e}"))
    }
}

/// Heuristically identify the alert source from headers or body.
fn detect_source(headers: &HeaderMap, body: &str) -> &'static str {
    if headers.contains_key("x-pagerduty-signature") {
        return "PagerDuty";
    }
    if body.contains("\"source\":\"opsgenie\"") || body.contains("\"integrationType\"") {
        return "Opsgenie";
    }
    "unknown"
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn detect_pagerduty() {
        let mut h = HeaderMap::new();
        h.insert("x-pagerduty-signature", "v1=abc".parse().unwrap());
        assert_eq!(detect_source(&h, "{}"), "PagerDuty");
    }

    #[test]
    fn detect_opsgenie() {
        let h = HeaderMap::new();
        assert_eq!(
            detect_source(&h, r#"{"source":"opsgenie","type":"alert"}"#),
            "Opsgenie"
        );
    }

    #[test]
    fn detect_unknown() {
        assert_eq!(detect_source(&HeaderMap::new(), "{}"), "unknown");
    }
}
