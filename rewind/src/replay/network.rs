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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use axum::{
    extract::{Request, State},
    response::Response,
    Router,
};

use crate::store::snapshot::HttpRecord;

/// Intercepts outbound HTTP calls during replay and returns recorded responses.
///
/// Services have HTTP_PROXY pointing here. Each request is matched against
/// the recorded response set and consumed in order, preserving the original
/// causal sequence.
pub struct MockServer {
    responses: Vec<HttpRecord>,
}

#[derive(Clone)]
struct MockState {
    /// (method, path) → queue of responses, consumed front-to-back.
    queues: Arc<Mutex<HashMap<String, Vec<HttpRecord>>>>,
}

impl MockServer {
    pub fn new(responses: Vec<HttpRecord>) -> Self {
        Self { responses }
    }

    /// Bind to `addr` and start serving.
    pub async fn listen(self, addr: SocketAddr) -> Result<()> {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        self.serve(listener).await
    }

    /// Serve on a pre-bound listener (use this when you need the port number
    /// before starting, e.g. to inject it into compose services).
    pub async fn serve(self, listener: tokio::net::TcpListener) -> Result<()> {
        let mut queues: HashMap<String, Vec<HttpRecord>> = HashMap::new();
        for r in self.responses {
            // Only outbound responses have a status code.
            if r.status_code.is_some() {
                let key = format!("{} {}", r.method, r.path);
                queues.entry(key).or_default().push(r);
            }
        }

        let state = MockState {
            queues: Arc::new(Mutex::new(queues)),
        };

        let app = Router::new()
            .fallback(handle_request)
            .with_state(state);

        let addr = listener.local_addr()?;
        println!("  MockServer on {addr}");
        axum::serve(listener, app).await?;
        Ok(())
    }
}

async fn handle_request(State(state): State<MockState>, req: Request) -> Response {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let key = format!("{method} {path}");

    let record = state.queues.lock().unwrap()
        .get_mut(&key)
        .and_then(|q| if q.is_empty() { None } else { Some(q.remove(0)) });

    match record {
        Some(r) => {
            let status = r.status_code.unwrap_or(200);
            let body = r.body.unwrap_or_default();
            Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body))
                .unwrap_or_else(|_| internal_error())
        }
        None => {
            // No recorded response — return a diagnostic 502 so the developer
            // knows exactly which call wasn't captured.
            let msg = format!(
                r#"{{"error":"no recorded response","method":"{method}","path":"{path}"}}"#
            );
            eprintln!("  MockServer [502] {method} {path} — no recorded response");
            Response::builder()
                .status(502)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(msg))
                .unwrap_or_else(|_| internal_error())
        }
    }
}

fn internal_error() -> Response {
    Response::builder()
        .status(500)
        .body(axum::body::Body::empty())
        .unwrap()
}
