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

//! Lightweight Prometheus-compatible metrics for the rewind agent.
//!
//! Exposes two endpoints on port 9090 (configurable):
//!   GET /healthz  → 200 OK  (liveness probe)
//!   GET /metrics  → Prometheus text format

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub struct Metrics {
    pub events_captured_http: AtomicU64,
    pub events_captured_db: AtomicU64,
    pub events_captured_syscall: AtomicU64,
    pub events_captured_grpc: AtomicU64,
    pub snapshots_flushed: AtomicU64,
    pub ring_buffer_capacity: AtomicU64,
    pub ring_buffer_size: AtomicU64,
}

impl Metrics {
    pub fn new(ring_capacity: usize) -> Self {
        Self {
            events_captured_http: AtomicU64::new(0),
            events_captured_db: AtomicU64::new(0),
            events_captured_syscall: AtomicU64::new(0),
            events_captured_grpc: AtomicU64::new(0),
            snapshots_flushed: AtomicU64::new(0),
            ring_buffer_capacity: AtomicU64::new(ring_capacity as u64),
            ring_buffer_size: AtomicU64::new(0),
        }
    }

    pub fn inc_http(&self) {
        self.events_captured_http.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_db(&self) {
        self.events_captured_db.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_syscall(&self) {
        self.events_captured_syscall.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_grpc(&self) {
        self.events_captured_grpc.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_flushed(&self) {
        self.snapshots_flushed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_ring_size(&self, n: usize) {
        self.ring_buffer_size.store(n as u64, Ordering::Relaxed);
    }

    pub fn prometheus_text(&self) -> String {
        let http = self.events_captured_http.load(Ordering::Relaxed);
        let db = self.events_captured_db.load(Ordering::Relaxed);
        let syscall = self.events_captured_syscall.load(Ordering::Relaxed);
        let grpc = self.events_captured_grpc.load(Ordering::Relaxed);
        let flushed = self.snapshots_flushed.load(Ordering::Relaxed);
        let cap = self.ring_buffer_capacity.load(Ordering::Relaxed);
        let size = self.ring_buffer_size.load(Ordering::Relaxed);
        let util = if cap > 0 {
            (size * 1000 / cap) as f64 / 1000.0
        } else {
            0.0
        };

        format!(
            "# HELP rewind_events_captured_total Total events captured by type\n\
             # TYPE rewind_events_captured_total counter\n\
             rewind_events_captured_total{{type=\"http\"}} {http}\n\
             rewind_events_captured_total{{type=\"db\"}} {db}\n\
             rewind_events_captured_total{{type=\"syscall\"}} {syscall}\n\
             rewind_events_captured_total{{type=\"grpc\"}} {grpc}\n\
             # HELP rewind_snapshots_flushed_total Total snapshots written to disk\n\
             # TYPE rewind_snapshots_flushed_total counter\n\
             rewind_snapshots_flushed_total {flushed}\n\
             # HELP rewind_ring_buffer_capacity Maximum events the ring buffer holds\n\
             # TYPE rewind_ring_buffer_capacity gauge\n\
             rewind_ring_buffer_capacity {cap}\n\
             # HELP rewind_ring_buffer_size Current number of events in the ring buffer\n\
             # TYPE rewind_ring_buffer_size gauge\n\
             rewind_ring_buffer_size {size}\n\
             # HELP rewind_ring_buffer_utilization Ring buffer fill ratio (0–1)\n\
             # TYPE rewind_ring_buffer_utilization gauge\n\
             rewind_ring_buffer_utilization {util:.3}\n"
        )
    }
}

/// Serve /healthz and /metrics on `addr` (e.g. "0.0.0.0:9090").
/// Returns immediately; the server runs in a background tokio task.
pub async fn serve(addr: &str, metrics: Arc<Metrics>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            let metrics = Arc::clone(&metrics);
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let req = std::str::from_utf8(&buf[..n]).unwrap_or("");

                let (status, content_type, body) = if req.starts_with("GET /metrics") {
                    (
                        "200 OK",
                        "text/plain; version=0.0.4",
                        metrics.prometheus_text(),
                    )
                } else if req.starts_with("GET /healthz") {
                    ("200 OK", "text/plain", "ok\n".to_string())
                } else {
                    ("404 Not Found", "text/plain", "not found\n".to_string())
                };

                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    Ok(())
}
