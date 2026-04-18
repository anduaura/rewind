use anyhow::Result;
use std::net::SocketAddr;

use crate::store::snapshot::HttpRecord;

/// Intercepts outbound HTTP calls during replay and returns recorded responses.
///
/// During replay, services have HTTP_PROXY pointing at this server. Each
/// outbound request is matched against the recorded response set and answered
/// in order, ensuring deterministic replay without touching the real network.
pub struct MockServer {
    responses: Vec<HttpRecord>,
    cursor: usize,
}

impl MockServer {
    pub fn new(responses: Vec<HttpRecord>) -> Self {
        Self {
            responses,
            cursor: 0,
        }
    }

    /// Start the mock HTTP server and block until shutdown.
    pub async fn listen(self, addr: SocketAddr) -> Result<()> {
        // TODO: implement with tokio + hyper (or axum)
        //
        // For each incoming request:
        //   1. Parse method + path from the HTTP/1.1 request line
        //   2. Call self.match_response(method, path) to find the best match
        //   3. Return the recorded status_code + body
        //   4. If no match: return 502 with a JSON diagnostic:
        //      { "error": "no recorded response", "method": "...", "path": "..." }
        //
        // Matching strategy (in priority order):
        //   a. Exact method + path match, unconsumed, earliest timestamp
        //   b. Path-prefix match
        //   c. Method-only match (last resort)
        //
        // In-order consumption: each response is served once and then marked
        // consumed. This surfaces bugs that deduplicate identical requests and
        // masks the missing second call.

        println!("MockServer stubbed — would listen on {addr}");
        println!("  {} recorded responses loaded", self.responses.len());

        Ok(())
    }

    pub fn match_response(&mut self, method: &str, path: &str) -> Option<&HttpRecord> {
        // TODO: implement matching logic described above
        let _ = (method, path);
        None
    }
}
