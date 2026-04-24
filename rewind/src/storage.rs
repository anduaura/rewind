//! Storage backend abstraction for `rewind server`.
//!
//! Supports two backends:
//!   **Local** — standard filesystem (default; `--storage /var/rewind/snapshots`)
//!   **Remote** — any `object_store`-compatible target: S3, GCS, Azure Blob
//!                (`--storage-url s3://bucket/prefix`)
//!
//! Both backends expose the same async API:
//!   put(team, name, bytes)  — store a snapshot
//!   get(team, name)         — retrieve a snapshot
//!   list(team)              — list snapshots for a team (name + size in bytes)
//!   exists(team, name)      — check for existence without downloading
//!
//! ## Leader election
//!
//! When multiple replicas run against the same shared backend (HPA / multi-pod),
//! periodic retention jobs should only run on one replica at a time.  The
//! `try_become_leader()` method implements a simple TTL-based lock:
//!
//!   - One replica wins by writing `rewind-leader.lock` with its instance ID
//!     and an expiry timestamp.
//!   - Every `LEADER_TTL` seconds the winner refreshes the lock.
//!   - Replicas that cannot claim the lock skip retention.
//!   - If the lock expires (replica crashed), any replica can claim it next cycle.
//!
//! This is not perfectly atomic but is safe for idempotent jobs like retention.

use anyhow::{Context, Result};
use bytes::Bytes;
use object_store::{path::Path as ObjPath, ObjectStore};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub const LEADER_TTL_SECS: u64 = 60;

// ── Backend enum ──────────────────────────────────────────────────────────────

pub enum Backend {
    Local(PathBuf),
    Remote {
        store: Arc<dyn ObjectStore>,
        prefix: String,
    },
}

impl Backend {
    /// Parse a `--storage-url` value and construct the appropriate backend.
    /// Returns `None` for a plain filesystem path (caller should use `Backend::Local`).
    pub fn from_url(url: &str) -> Result<Self> {
        use object_store::{
            aws::AmazonS3Builder, azure::MicrosoftAzureBuilder,
            gcp::GoogleCloudStorageBuilder,
        };
        if let Some(rest) = url.strip_prefix("s3://") {
            let (bucket, prefix) = split_bucket_prefix(rest)?;
            let store = AmazonS3Builder::from_env()
                .with_bucket_name(bucket)
                .build()
                .context("building S3 storage backend")?;
            Ok(Self::Remote {
                store: Arc::new(store),
                prefix,
            })
        } else if let Some(rest) = url.strip_prefix("gs://") {
            let (bucket, prefix) = split_bucket_prefix(rest)?;
            let store = GoogleCloudStorageBuilder::from_env()
                .with_bucket_name(bucket)
                .build()
                .context("building GCS storage backend")?;
            Ok(Self::Remote {
                store: Arc::new(store),
                prefix,
            })
        } else if let Some(rest) = url.strip_prefix("az://") {
            let (container, prefix) = split_bucket_prefix(rest)?;
            let store = MicrosoftAzureBuilder::from_env()
                .with_container_name(container)
                .build()
                .context("building Azure Blob storage backend")?;
            Ok(Self::Remote {
                store: Arc::new(store),
                prefix,
            })
        } else {
            Ok(Self::Local(PathBuf::from(url)))
        }
    }

    /// Store snapshot bytes under `{team}/{name}`.
    pub async fn put(&self, team: &str, name: &str, bytes: Bytes) -> Result<()> {
        match self {
            Self::Local(root) => {
                let dir = root.join(team);
                tokio::fs::create_dir_all(&dir)
                    .await
                    .context("creating team directory")?;
                tokio::fs::write(dir.join(name), &bytes)
                    .await
                    .context("writing snapshot")?;
            }
            Self::Remote { store, prefix } => {
                let key = obj_key(prefix, team, name);
                store
                    .put(&key, bytes.into())
                    .await
                    .with_context(|| format!("putting {key}"))?;
            }
        }
        Ok(())
    }

    /// Retrieve snapshot bytes for `{team}/{name}`.
    pub async fn get(&self, team: &str, name: &str) -> Result<Bytes> {
        match self {
            Self::Local(root) => {
                let path = root.join(team).join(name);
                let bytes = tokio::fs::read(&path)
                    .await
                    .with_context(|| format!("reading {}", path.display()))?;
                Ok(Bytes::from(bytes))
            }
            Self::Remote { store, prefix } => {
                let key = obj_key(prefix, team, name);
                let result = store
                    .get(&key)
                    .await
                    .with_context(|| format!("getting {key}"))?;
                result.bytes().await.context("reading object bytes")
            }
        }
    }

    /// List snapshots in `{team}/`. Returns `(name, size_bytes)` pairs.
    pub async fn list(&self, team: &str) -> Result<Vec<(String, u64)>> {
        match self {
            Self::Local(root) => {
                let dir = root.join(team);
                let mut entries = Vec::new();
                let mut rd = match tokio::fs::read_dir(&dir).await {
                    Ok(d) => d,
                    Err(_) => return Ok(entries),
                };
                while let Ok(Some(entry)) = rd.next_entry().await {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if !name.ends_with(".rwd") {
                        continue;
                    }
                    let size = entry.metadata().await.map(|m| m.len()).unwrap_or(0);
                    entries.push((name, size));
                }
                entries.sort_by(|a, b| a.0.cmp(&b.0));
                Ok(entries)
            }
            Self::Remote { store, prefix } => {
                use object_store::ListResult;
                let team_prefix = if prefix.is_empty() {
                    ObjPath::from(team)
                } else {
                    ObjPath::from(format!("{prefix}/{team}"))
                };
                let ListResult { objects, .. } = store
                    .list_with_delimiter(Some(&team_prefix))
                    .await
                    .context("listing objects")?;
                let mut entries: Vec<(String, u64)> = objects
                    .into_iter()
                    .filter_map(|o| {
                        let name = o.location.filename()?.to_string();
                        if name.ends_with(".rwd") {
                            Some((name, o.size as u64))
                        } else {
                            None
                        }
                    })
                    .collect();
                entries.sort_by(|a, b| a.0.cmp(&b.0));
                Ok(entries)
            }
        }
    }

    /// Check if `{team}/{name}` exists without downloading it.
    pub async fn exists(&self, team: &str, name: &str) -> bool {
        match self {
            Self::Local(root) => root.join(team).join(name).exists(),
            Self::Remote { store, prefix } => {
                let key = obj_key(prefix, team, name);
                store.head(&key).await.is_ok()
            }
        }
    }

    /// Delete snapshot `{team}/{name}`.
    pub async fn delete(&self, team: &str, name: &str) -> Result<()> {
        match self {
            Self::Local(root) => {
                tokio::fs::remove_file(root.join(team).join(name))
                    .await
                    .with_context(|| format!("deleting {team}/{name}"))?;
            }
            Self::Remote { store, prefix } => {
                let key = obj_key(prefix, team, name);
                store
                    .delete(&key)
                    .await
                    .with_context(|| format!("deleting {key}"))?;
            }
        }
        Ok(())
    }

    /// Try to claim (or refresh) the leader lock.
    /// Returns `true` if this instance is the leader after the call.
    pub async fn try_become_leader(&self, instance_id: &str) -> bool {
        let expiry = now_secs() + LEADER_TTL_SECS;
        let content = format!("{instance_id}\t{expiry}");

        match self.read_lock().await {
            Some((holder, exp)) if exp > now_secs() && holder != instance_id => {
                // Another replica holds a valid lock.
                return false;
            }
            _ => {}
        }

        // Lock is expired or absent — try to claim it.
        if let Err(e) = self.write_lock(content.as_bytes()).await {
            tracing::warn!("leader lock write failed: {e}");
            return false;
        }

        // Verify we actually wrote our content (last-write-wins is fine for retention).
        matches!(self.read_lock().await, Some((id, _)) if id == instance_id)
    }

    async fn read_lock(&self) -> Option<(String, u64)> {
        let bytes = match self {
            Self::Local(root) => {
                tokio::fs::read(root.join("rewind-leader.lock"))
                    .await
                    .ok()?
            }
            Self::Remote { store, prefix } => {
                let key = if prefix.is_empty() {
                    ObjPath::from("rewind-leader.lock")
                } else {
                    ObjPath::from(format!("{prefix}/rewind-leader.lock"))
                };
                store.get(&key).await.ok()?.bytes().await.ok()?.to_vec()
            }
        };
        let text = String::from_utf8(bytes).ok()?;
        let mut parts = text.splitn(2, '\t');
        let id = parts.next()?.to_string();
        let exp: u64 = parts.next()?.trim().parse().ok()?;
        Some((id, exp))
    }

    async fn write_lock(&self, content: &[u8]) -> Result<()> {
        match self {
            Self::Local(root) => {
                tokio::fs::write(root.join("rewind-leader.lock"), content)
                    .await
                    .context("writing leader lock")?;
            }
            Self::Remote { store, prefix } => {
                let key = if prefix.is_empty() {
                    ObjPath::from("rewind-leader.lock")
                } else {
                    ObjPath::from(format!("{prefix}/rewind-leader.lock"))
                };
                store
                    .put(&key, Bytes::copy_from_slice(content).into())
                    .await
                    .context("writing leader lock")?;
            }
        }
        Ok(())
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn obj_key(prefix: &str, team: &str, name: &str) -> ObjPath {
    if prefix.is_empty() {
        ObjPath::from(format!("{team}/{name}"))
    } else {
        ObjPath::from(format!("{prefix}/{team}/{name}"))
    }
}

fn split_bucket_prefix(rest: &str) -> Result<(String, String)> {
    let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
    if bucket.is_empty() {
        anyhow::bail!("bucket name is empty in storage URL");
    }
    Ok((bucket.to_string(), prefix.to_string()))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_put_get_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let backend = Backend::Local(dir.path().to_path_buf());
        let data = Bytes::from("hello snapshot");
        backend.put("team-a", "snap.rwd", data.clone()).await.unwrap();
        let got = backend.get("team-a", "snap.rwd").await.unwrap();
        assert_eq!(got, data);
    }

    #[tokio::test]
    async fn local_list_returns_rwd_files() {
        let dir = tempfile::tempdir().unwrap();
        let backend = Backend::Local(dir.path().to_path_buf());
        backend.put("t1", "a.rwd", Bytes::from("x")).await.unwrap();
        backend.put("t1", "b.rwd", Bytes::from("yy")).await.unwrap();
        let list = backend.list("t1").await.unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].0, "a.rwd");
        assert_eq!(list[1].0, "b.rwd");
        assert_eq!(list[1].1, 2); // size in bytes
    }

    #[tokio::test]
    async fn local_list_empty_dir_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let backend = Backend::Local(dir.path().to_path_buf());
        let list = backend.list("nonexistent-team").await.unwrap();
        assert!(list.is_empty());
    }

    #[tokio::test]
    async fn local_exists_true_and_false() {
        let dir = tempfile::tempdir().unwrap();
        let backend = Backend::Local(dir.path().to_path_buf());
        backend.put("t", "snap.rwd", Bytes::from("x")).await.unwrap();
        assert!(backend.exists("t", "snap.rwd").await);
        assert!(!backend.exists("t", "missing.rwd").await);
    }

    #[tokio::test]
    async fn local_leader_election_single_instance() {
        let dir = tempfile::tempdir().unwrap();
        let backend = Backend::Local(dir.path().to_path_buf());
        // First call — no lock exists — should win.
        let won = backend.try_become_leader("instance-1").await;
        assert!(won, "sole instance should become leader");
        // Second call by same instance — should still be leader (refresh).
        let still_leader = backend.try_become_leader("instance-1").await;
        assert!(still_leader);
    }

    #[tokio::test]
    async fn local_leader_election_second_instance_loses() {
        let dir = tempfile::tempdir().unwrap();
        let backend = Backend::Local(dir.path().to_path_buf());
        // Instance-1 claims the lock.
        backend.try_become_leader("instance-1").await;
        // Instance-2 should not be able to claim it.
        let won = backend.try_become_leader("instance-2").await;
        assert!(!won, "second instance should not steal a valid lock");
    }

    #[test]
    fn split_bucket_prefix_no_prefix() {
        let (b, p) = split_bucket_prefix("my-bucket").unwrap();
        assert_eq!(b, "my-bucket");
        assert_eq!(p, "");
    }

    #[test]
    fn split_bucket_prefix_with_prefix() {
        let (b, p) = split_bucket_prefix("my-bucket/prod/rewind").unwrap();
        assert_eq!(b, "my-bucket");
        assert_eq!(p, "prod/rewind");
    }
}
