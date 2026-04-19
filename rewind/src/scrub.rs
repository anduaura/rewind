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

//! PII scrubbing for captured traffic.
//!
//! `ScrubConfig` is built from CLI flags and applied in the eBPF drain tasks
//! before events enter the ring buffer:
//!   - `redact_headers`: header names whose values are replaced with `[REDACTED]`
//!   - `allow_paths`: if non-empty, only events whose path starts with a listed
//!     prefix are captured; all others are silently dropped.

/// Header names that carry credentials or session tokens by default.
pub const DEFAULT_REDACT_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
];

#[derive(Clone, Debug)]
pub struct ScrubConfig {
    redact_headers: Vec<String>, // all lowercase
    allow_paths: Vec<String>,
}

impl Default for ScrubConfig {
    fn default() -> Self {
        Self::new(&[], &[])
    }
}

impl ScrubConfig {
    /// Build a config from CLI-supplied lists.
    ///
    /// An empty `redact_headers` slice applies `DEFAULT_REDACT_HEADERS`.
    /// An empty `allow_paths` slice means all paths are captured.
    pub fn new(redact_headers: &[String], allow_paths: &[String]) -> Self {
        let redact_headers = if redact_headers.is_empty() {
            DEFAULT_REDACT_HEADERS
                .iter()
                .map(|s| s.to_string())
                .collect()
        } else {
            redact_headers
                .iter()
                .map(|h| h.to_ascii_lowercase())
                .collect()
        };
        Self {
            redact_headers,
            allow_paths: allow_paths.to_vec(),
        }
    }

    /// Returns `false` when a non-empty allow-list is configured and `path`
    /// doesn't start with any listed prefix.  Always returns `true` otherwise.
    pub fn path_allowed(&self, path: &str) -> bool {
        self.allow_paths.is_empty()
            || self
                .allow_paths
                .iter()
                .any(|prefix| path.starts_with(prefix.as_str()))
    }

    /// Replace the value of each matching header with `"[REDACTED]"`.
    pub fn scrub_headers(&self, headers: &mut [(String, String)]) {
        for (name, value) in headers.iter_mut() {
            if self.redact_headers.contains(&name.to_ascii_lowercase()) {
                *value = "[REDACTED]".to_string();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_redacts_authorization() {
        let cfg = ScrubConfig::default();
        let mut headers = vec![
            ("Authorization".to_string(), "Bearer secret".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];
        cfg.scrub_headers(&mut headers);
        assert_eq!(headers[0].1, "[REDACTED]");
        assert_eq!(headers[1].1, "application/json");
    }

    #[test]
    fn default_redacts_cookie() {
        let cfg = ScrubConfig::default();
        let mut headers = vec![("Cookie".to_string(), "session=abc123".to_string())];
        cfg.scrub_headers(&mut headers);
        assert_eq!(headers[0].1, "[REDACTED]");
    }

    #[test]
    fn custom_list_overrides_defaults() {
        let cfg = ScrubConfig::new(&["x-custom".to_string()], &[]);
        let mut headers = vec![
            ("Authorization".to_string(), "Bearer secret".to_string()),
            ("x-custom".to_string(), "private".to_string()),
        ];
        cfg.scrub_headers(&mut headers);
        // authorization is NOT in the custom list — kept as-is
        assert_eq!(headers[0].1, "Bearer secret");
        assert_eq!(headers[1].1, "[REDACTED]");
    }

    #[test]
    fn header_matching_is_case_insensitive() {
        let cfg = ScrubConfig::default();
        let mut headers = vec![("COOKIE".to_string(), "session=abc".to_string())];
        cfg.scrub_headers(&mut headers);
        assert_eq!(headers[0].1, "[REDACTED]");
    }

    #[test]
    fn allow_paths_empty_permits_all() {
        let cfg = ScrubConfig::default();
        assert!(cfg.path_allowed("/api/v1/users"));
        assert!(cfg.path_allowed("/internal/debug"));
    }

    #[test]
    fn allow_paths_filters_unmatched() {
        let cfg = ScrubConfig::new(&[], &["/api".to_string()]);
        assert!(cfg.path_allowed("/api/v1/users"));
        assert!(!cfg.path_allowed("/internal/debug"));
    }

    #[test]
    fn allow_paths_multi_prefix() {
        let cfg = ScrubConfig::new(&[], &["/api".to_string(), "/health".to_string()]);
        assert!(cfg.path_allowed("/health"));
        assert!(!cfg.path_allowed("/metrics"));
    }
}
