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

//! PID → service name attribution.
//!
//! At startup, `ServiceMap::build` calls `docker inspect` for each named
//! service to obtain its container ID.  At event time, `lookup(pid)` reads
//! `/proc/<pid>/cgroup`, extracts the container ID, and returns the matching
//! service name.  Results are cached so each PID costs at most one `/proc`
//! read.
//!
//! Degrades gracefully: if Docker is unavailable or a PID belongs to no known
//! container, `lookup` returns an empty string (preserving prior behaviour).

use std::collections::HashMap;
use std::process::Command;
use std::sync::Mutex;

pub struct ServiceMap {
    /// First 12 hex chars of container ID → service name.
    container_to_service: HashMap<String, String>,
    /// PID → resolved service name; `None` means "tried, not found".
    cache: Mutex<HashMap<u32, Option<String>>>,
}

impl ServiceMap {
    /// Build by resolving each service name to a Docker container ID.
    /// Services that cannot be found via `docker inspect` are silently skipped.
    pub fn build(services: &[String]) -> Self {
        let mut container_to_service = HashMap::new();
        for service in services {
            if let Some(id) = docker_container_id(service) {
                let key: String = id.chars().take(12).collect();
                if key.len() == 12 {
                    container_to_service.insert(key, service.clone());
                }
            }
        }
        if !container_to_service.is_empty() {
            tracing::debug!(
                "service map: {} container(s) resolved",
                container_to_service.len()
            );
        }
        Self {
            container_to_service,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Empty map — all lookups return `""`.  Used when Docker is unavailable.
    pub fn empty() -> Self {
        Self {
            container_to_service: HashMap::new(),
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Return the service name for `pid`, or `""` if unknown.
    pub fn lookup(&self, pid: u32) -> String {
        // Fast path: cached result.
        {
            let cache = self.cache.lock().unwrap();
            if let Some(entry) = cache.get(&pid) {
                return entry.clone().unwrap_or_default();
            }
        }

        let result = self.resolve(pid);
        self.cache.lock().unwrap().insert(pid, result.clone());
        result.unwrap_or_default()
    }

    fn resolve(&self, pid: u32) -> Option<String> {
        if self.container_to_service.is_empty() {
            return None;
        }
        let cgroup =
            std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
        let container_id = parse_container_id(&cgroup)?;
        self.container_to_service.get(&container_id).cloned()
    }
}

// ── Docker helpers ────────────────────────────────────────────────────────────

fn docker_container_id(service: &str) -> Option<String> {
    let out = Command::new("docker")
        .args(["inspect", "--format", "{{.Id}}", service])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if id.len() >= 12 {
        Some(id)
    } else {
        None
    }
}

// ── cgroup parsing ────────────────────────────────────────────────────────────

/// Extract the first 12 hex chars of a Docker container ID from
/// `/proc/<pid>/cgroup` content.
///
/// Handles both cgroup v1 (`...:/docker/<id>`) and cgroup v2
/// (`...docker-<id>.scope`).
pub(crate) fn parse_container_id(cgroup: &str) -> Option<String> {
    for line in cgroup.lines() {
        // cgroup v1: 12:memory:/docker/abc123def456...
        if let Some(pos) = line.find("/docker/") {
            let id: String = line[pos + 8..].chars().take(12).collect();
            if id.len() == 12 && id.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(id);
            }
        }
        // cgroup v2: 0::/system.slice/docker-abc123def456.scope
        if let Some(pos) = line.find("docker-") {
            let id: String = line[pos + 7..].chars().take(12).collect();
            if id.len() == 12 && id.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(id);
            }
        }
    }
    None
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_v1_docker_path() {
        let cgroup =
            "12:memory:/docker/abc123def456789abcdef0123456789ab\n\
             11:cpu,cpuacct:/docker/abc123def456789abcdef0123456789ab\n";
        assert_eq!(
            parse_container_id(cgroup),
            Some("abc123def456".to_string())
        );
    }

    #[test]
    fn cgroup_v2_scope_format() {
        let cgroup =
            "0::/system.slice/docker-abc123def456789abcdef0123456789ab.scope\n";
        assert_eq!(
            parse_container_id(cgroup),
            Some("abc123def456".to_string())
        );
    }

    #[test]
    fn cgroup_not_a_container() {
        let cgroup = "12:memory:/user.slice/user-1000.slice\n0::/init.scope\n";
        assert_eq!(parse_container_id(cgroup), None);
    }

    #[test]
    fn cgroup_id_too_short_rejected() {
        // "docker/" followed by fewer than 12 hex chars → not a valid container ID
        let cgroup = "12:memory:/docker/abc\n";
        assert_eq!(parse_container_id(cgroup), None);
    }

    #[test]
    fn empty_map_lookup_returns_empty() {
        let map = ServiceMap::empty();
        assert_eq!(map.lookup(1234), "");
    }

    #[test]
    fn map_with_known_container_resolves() {
        let mut m = ServiceMap::empty();
        m.container_to_service
            .insert("abc123def456".to_string(), "api".to_string());

        // Simulate: pid 99 cgroup has that container ID.
        // We can't actually write /proc, so test resolve() indirectly via
        // the inner parse_container_id helper used in the real resolve path.
        let cgroup = "12:memory:/docker/abc123def456789abcdef\n";
        let id = parse_container_id(cgroup).unwrap();
        assert_eq!(m.container_to_service.get(&id), Some(&"api".to_string()));
    }

    #[test]
    fn lookup_caches_negative_result() {
        let map = ServiceMap::empty();
        // First lookup for pid 42
        assert_eq!(map.lookup(42), "");
        // Cache should now have pid 42 → None
        let cache = map.cache.lock().unwrap();
        assert!(cache.contains_key(&42));
        assert_eq!(cache[&42], None);
    }
}
