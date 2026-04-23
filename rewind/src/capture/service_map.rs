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

//! PID → service name attribution, supporting both Docker Compose and Kubernetes.
//!
//! ## Lookup strategy
//!
//! **At startup** (`build`):
//!   1. Docker Compose — `docker inspect` each named service to get its container ID.
//!   2. Kubernetes — `crictl ps --output json` to populate all running containers and
//!      their workload labels (`app`, `app.kubernetes.io/name`, `component`).
//!
//! **At event time** (`lookup`):
//!   1. Fast path: return the cached result for this PID.
//!   2. Read `/proc/<pid>/cgroup` and extract the container ID.
//!      Handles Docker, containerd (k8s), and CRI-O cgroup path formats.
//!   3. Look up the container ID in the static map built at startup.
//!   4. If not found (e.g. container started after agent init), fall back to
//!      reading `HOSTNAME` from `/proc/<pid>/environ` and applying a pod-name
//!      hash-stripping heuristic to derive the workload (deployment) name.
//!
//! All results are cached per-PID so each process costs at most one `/proc` read.

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
    /// Build by resolving containers to service names.
    ///
    /// Tries Docker Compose (`docker inspect`) first, then Kubernetes
    /// (`crictl ps`).  Either or both may fail silently; the map degrades
    /// gracefully to an empty state where all lookups use the `/proc` fallback.
    pub fn build(services: &[String]) -> Self {
        let mut container_to_service = HashMap::new();

        // ── Docker Compose ──────────────────────────────────────────────────
        for service in services {
            if let Some(id) = docker_container_id(service) {
                let key: String = id.chars().take(12).collect();
                if key.len() == 12 {
                    container_to_service.insert(key, service.clone());
                }
            }
        }

        // ── Kubernetes (crictl) ─────────────────────────────────────────────
        // Run regardless of Docker results: a k8s node may have no Docker but
        // have crictl; and in mixed environments we want both.
        if let Some(k8s_map) = crictl_container_map() {
            let before = container_to_service.len();
            for (id, name) in k8s_map {
                container_to_service.entry(id).or_insert(name);
            }
            let added = container_to_service.len() - before;
            if added > 0 {
                tracing::debug!("service map: {added} container(s) from crictl");
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

    /// Empty map — all lookups fall through to `/proc` heuristics.
    pub fn empty() -> Self {
        Self {
            container_to_service: HashMap::new(),
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Return the service name for `pid`, or `""` if unknown.
    pub fn lookup(&self, pid: u32) -> String {
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
        let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
        let container_id = parse_container_id(&cgroup)?;

        // Static map hit (Docker or crictl at startup).
        if let Some(name) = self.container_to_service.get(&container_id) {
            return Some(name.clone());
        }

        // Static map miss: container started after agent init, or the map was
        // never populated (no Docker, no crictl).  Derive from process environ.
        resolve_from_proc_environ(pid)
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
    if id.len() >= 12 { Some(id) } else { None }
}

// ── Kubernetes / crictl helpers ───────────────────────────────────────────────

/// Query `crictl ps --output json` for all running containers on this node and
/// build a container-ID → service-name map.
///
/// Label priority: `app.kubernetes.io/name` > `app` > `component` > container name.
fn crictl_container_map() -> Option<HashMap<String, String>> {
    let out = Command::new("crictl")
        .args(["ps", "--output", "json"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;

    let mut map = HashMap::new();
    if let Some(containers) = json["containers"].as_array() {
        for c in containers {
            let id_full = c["id"].as_str().unwrap_or("");
            let id: String = id_full.chars().take(12).collect();
            if id.len() != 12 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }

            let labels = &c["labels"];
            let service = labels["app.kubernetes.io/name"]
                .as_str()
                .or_else(|| labels["app"].as_str())
                .or_else(|| labels["component"].as_str())
                .or_else(|| c["metadata"]["name"].as_str())
                .unwrap_or("unknown")
                .to_string();

            map.insert(id, service);
        }
    }

    if map.is_empty() { None } else { Some(map) }
}

// ── /proc fallback ────────────────────────────────────────────────────────────

/// Read `HOSTNAME` from `/proc/<pid>/environ` (null-separated KEY=VALUE pairs).
/// In Kubernetes, HOSTNAME equals the pod name.  Strip the Kubernetes-appended
/// hash suffixes to recover the workload (Deployment / StatefulSet) name.
fn resolve_from_proc_environ(pid: u32) -> Option<String> {
    let environ = std::fs::read(format!("/proc/{pid}/environ")).ok()?;
    let hostname = environ
        .split(|&b| b == 0)
        .find_map(|kv| {
            let s = std::str::from_utf8(kv).ok()?;
            s.strip_prefix("HOSTNAME=")
        })?
        .to_string();
    if hostname.is_empty() {
        return None;
    }
    Some(strip_pod_suffix(&hostname))
}

/// Strip Kubernetes pod-name hash suffixes to recover the workload name.
///
/// Patterns:
/// - ReplicaSet: `<name>-<rs-hash>-<pod-hash>`  e.g. `api-7d9f8b64c-xk2p9`
///   rs-hash: 9-10 alphanumeric chars; pod-hash: 5 alphanumeric chars
/// - StatefulSet: `<name>-<ordinal>` e.g. `postgres-0`
pub(crate) fn strip_pod_suffix(pod_name: &str) -> String {
    let parts: Vec<&str> = pod_name.split('-').collect();

    if parts.len() >= 3 {
        let last = parts[parts.len() - 1];
        let second_last = parts[parts.len() - 2];
        // ReplicaSet pod: last segment is 5 alphanumeric, second-to-last is 8-10
        let last_is_pod_hash =
            last.len() == 5 && last.chars().all(|c| c.is_ascii_alphanumeric());
        let second_is_rs_hash = (8..=10).contains(&second_last.len())
            && second_last.chars().all(|c| c.is_ascii_alphanumeric());
        if last_is_pod_hash && second_is_rs_hash {
            return parts[..parts.len() - 2].join("-");
        }
    }
    if parts.len() >= 2 {
        // StatefulSet: last segment is a small integer ordinal
        let last = parts[parts.len() - 1];
        if last.chars().all(|c| c.is_ascii_digit()) && last.len() <= 4 {
            return parts[..parts.len() - 1].join("-");
        }
    }

    pod_name.to_string()
}

// ── cgroup parsing ────────────────────────────────────────────────────────────

/// Extract the first 12 hex chars of a container ID from `/proc/<pid>/cgroup`.
///
/// Handles:
/// - Docker cgroup v1: `…:/docker/<id>`
/// - Docker cgroup v2: `…docker-<id>.scope`
/// - containerd (k8s): `…cri-containerd-<id>.scope`
/// - CRI-O (k8s):      `…crio-<id>.scope`
/// - k8s cgroup v1:    `…/kubepods/…/pod<uid>/<container-id>`
pub(crate) fn parse_container_id(cgroup: &str) -> Option<String> {
    for line in cgroup.lines() {
        // Docker cgroup v1: 12:memory:/docker/abc123def456...
        if let Some(pos) = line.find("/docker/") {
            let id: String = line[pos + 8..].chars().take(12).collect();
            if is_valid_id(&id) {
                return Some(id);
            }
        }
        // Docker cgroup v2: 0::/system.slice/docker-abc123def456.scope
        // containerd (k8s): …/cri-containerd-abc123def456.scope
        // CRI-O (k8s):      …/crio-abc123def456.scope
        for prefix in &["docker-", "cri-containerd-", "crio-"] {
            if let Some(pos) = line.find(prefix) {
                let after = &line[pos + prefix.len()..];
                let id: String = after.chars().take(12).collect();
                if is_valid_id(&id) {
                    return Some(id);
                }
            }
        }
        // Kubernetes cgroup v1: /kubepods/besteffort/pod<uid>/<container-id>
        // The container ID is the last path component.
        if line.contains("/kubepods") {
            if let Some(last) = line.split('/').next_back() {
                let id: String = last.chars().take(12).collect();
                if is_valid_id(&id) {
                    return Some(id);
                }
            }
        }
    }
    None
}

fn is_valid_id(id: &str) -> bool {
    id.len() == 12 && id.chars().all(|c| c.is_ascii_hexdigit())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_container_id ────────────────────────────────────────────────────

    #[test]
    fn cgroup_v1_docker_path() {
        let cgroup =
            "12:memory:/docker/abc123def456789abcdef0123456789ab\n\
             11:cpu,cpuacct:/docker/abc123def456789abcdef0123456789ab\n";
        assert_eq!(parse_container_id(cgroup), Some("abc123def456".to_string()));
    }

    #[test]
    fn cgroup_v2_scope_format() {
        let cgroup = "0::/system.slice/docker-abc123def456789abcdef0123456789ab.scope\n";
        assert_eq!(parse_container_id(cgroup), Some("abc123def456".to_string()));
    }

    #[test]
    fn cgroup_containerd_k8s() {
        let cgroup = "0::/kubepods.slice/kubepods-burstable.slice/\
            kubepods-burstable-podabc.slice/cri-containerd-abc123def456789ab.scope\n";
        assert_eq!(parse_container_id(cgroup), Some("abc123def456".to_string()));
    }

    #[test]
    fn cgroup_crio_k8s() {
        let cgroup = "0::/kubepods.slice/kubepods-besteffort.slice/\
            kubepods-besteffort-podabc.slice/crio-abc123def456789ab.scope\n";
        assert_eq!(parse_container_id(cgroup), Some("abc123def456".to_string()));
    }

    #[test]
    fn cgroup_k8s_v1_kubepods_path() {
        let cgroup =
            "11:memory:/kubepods/besteffort/pod9876fedc-ba98-7654-3210-fedcba987654/\
             abc123def456789abcdef0123456789ab\n";
        assert_eq!(parse_container_id(cgroup), Some("abc123def456".to_string()));
    }

    #[test]
    fn cgroup_not_a_container() {
        let cgroup = "12:memory:/user.slice/user-1000.slice\n0::/init.scope\n";
        assert_eq!(parse_container_id(cgroup), None);
    }

    #[test]
    fn cgroup_id_too_short_rejected() {
        let cgroup = "12:memory:/docker/abc\n";
        assert_eq!(parse_container_id(cgroup), None);
    }

    // ── strip_pod_suffix ──────────────────────────────────────────────────────

    #[test]
    fn strip_replicaset_pod() {
        // <deployment>-<rs-hash(9)>-<pod-hash(5)>
        assert_eq!(strip_pod_suffix("api-7d9f8b64c-xk2p9"), "api");
    }

    #[test]
    fn strip_multi_word_deployment() {
        assert_eq!(strip_pod_suffix("payment-service-7d9f8b64c-xk2p9"), "payment-service");
    }

    #[test]
    fn strip_statefulset_ordinal() {
        assert_eq!(strip_pod_suffix("postgres-0"), "postgres");
        assert_eq!(strip_pod_suffix("kafka-2"), "kafka");
    }

    #[test]
    fn strip_no_suffix_unchanged() {
        assert_eq!(strip_pod_suffix("api"), "api");
        assert_eq!(strip_pod_suffix("my-service"), "my-service");
    }

    // ── ServiceMap helpers ────────────────────────────────────────────────────

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
        let cgroup = "12:memory:/docker/abc123def456789abcdef\n";
        let id = parse_container_id(cgroup).unwrap();
        assert_eq!(m.container_to_service.get(&id), Some(&"api".to_string()));
    }

    #[test]
    fn lookup_caches_negative_result() {
        let map = ServiceMap::empty();
        assert_eq!(map.lookup(42), "");
        let cache = map.cache.lock().unwrap();
        assert!(cache.contains_key(&42));
        assert_eq!(cache[&42], None);
    }

    #[test]
    fn containerd_cgroup_extracts_correct_id() {
        let cgroup = "0::/kubepods.slice/kubepods-burstable.slice/\
            kubepods-burstable-podabc.slice/cri-containerd-deadbeefcafe1234.scope\n";
        assert_eq!(parse_container_id(cgroup), Some("deadbeefcafe".to_string()));
    }
}
