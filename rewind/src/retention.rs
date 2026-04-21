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

//! Snapshot retention — enforce max-age and max-size policies.
//!
//! `rewind retention` scans a directory, deletes snapshots older than
//! --max-age and, if total size still exceeds --max-size, evicts the oldest
//! files until the limit is satisfied.
//!
//! Designed to run as a Kubernetes CronJob or cron on a bare VM:
//!   rewind retention --dir /var/rewind/snapshots --max-age 7d --max-size 10GB
//!
//! Dry-run mode (default) prints what would be deleted without touching disk.
//! Pass --delete to actually remove files.

use anyhow::{Context, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::cli::RetentionArgs;

#[derive(Debug, Serialize)]
pub struct RetentionReport {
    pub scanned: usize,
    pub deleted: usize,
    pub bytes_freed: u64,
    pub dry_run: bool,
}

pub async fn run(args: RetentionArgs) -> Result<()> {
    let max_age = args.max_age.as_deref().map(parse_duration).transpose()?;
    let max_size = args.max_size.as_deref().map(parse_bytes).transpose()?;

    if max_age.is_none() && max_size.is_none() {
        anyhow::bail!("specify at least one of --max-age or --max-size");
    }

    let report = enforce(&args.dir, max_age, max_size, args.delete).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        let action = if report.dry_run {
            "would delete"
        } else {
            "deleted"
        };
        println!(
            "Scanned {} snapshots, {action} {} ({} bytes freed){}",
            report.scanned,
            report.deleted,
            report.bytes_freed,
            if report.dry_run { " [dry-run]" } else { "" },
        );
    }
    Ok(())
}

async fn enforce(
    dir: &Path,
    max_age: Option<Duration>,
    max_size: Option<u64>,
    delete: bool,
) -> Result<RetentionReport> {
    let now = SystemTime::now();
    let mut entries = collect_snapshots(dir).await?;

    // Sort oldest-first so we evict them first when trimming for size.
    entries.sort_by_key(|e| e.modified);

    let mut deleted = 0usize;
    let mut bytes_freed = 0u64;

    // Phase 1: age-based eviction.
    if let Some(max_age) = max_age {
        for entry in &entries {
            let age = now.duration_since(entry.modified).unwrap_or_default();
            if age > max_age {
                maybe_delete(
                    &entry.path,
                    entry.size,
                    delete,
                    &mut deleted,
                    &mut bytes_freed,
                )?;
            }
        }
    }

    // Phase 2: size-based eviction — remove oldest until under limit.
    if let Some(max_size) = max_size {
        // Recompute remaining total after age deletions.
        let total: u64 = entries
            .iter()
            .filter(|e| e.path.exists())
            .map(|e| e.size)
            .sum();

        let mut remaining = total;
        for entry in &entries {
            if remaining <= max_size {
                break;
            }
            if entry.path.exists() {
                maybe_delete(
                    &entry.path,
                    entry.size,
                    delete,
                    &mut deleted,
                    &mut bytes_freed,
                )?;
                remaining = remaining.saturating_sub(entry.size);
            }
        }
    }

    Ok(RetentionReport {
        scanned: entries.len(),
        deleted,
        bytes_freed,
        dry_run: !delete,
    })
}

struct SnapshotFile {
    path: PathBuf,
    modified: SystemTime,
    size: u64,
}

async fn collect_snapshots(dir: &Path) -> Result<Vec<SnapshotFile>> {
    let mut entries = Vec::new();
    let mut read_dir = tokio::fs::read_dir(dir)
        .await
        .with_context(|| format!("cannot read directory {}", dir.display()))?;

    while let Ok(Some(entry)) = read_dir.next_entry().await {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.ends_with(".rwd") {
            continue;
        }
        let meta = match entry.metadata().await {
            Ok(m) => m,
            Err(_) => continue,
        };
        let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        entries.push(SnapshotFile {
            path: entry.path(),
            modified,
            size: meta.len(),
        });
    }
    Ok(entries)
}

fn maybe_delete(
    path: &Path,
    size: u64,
    delete: bool,
    deleted: &mut usize,
    bytes_freed: &mut u64,
) -> Result<()> {
    if delete {
        std::fs::remove_file(path)
            .with_context(|| format!("failed to delete {}", path.display()))?;
        tracing::info!(path = %path.display(), "deleted snapshot");
    } else {
        tracing::info!(path = %path.display(), bytes = size, "would delete snapshot (dry-run)");
    }
    *deleted += 1;
    *bytes_freed += size;
    Ok(())
}

// ── Duration / size parsers ───────────────────────────────────────────────────

pub fn parse_duration(s: &str) -> Result<Duration> {
    if let Some(n) = s.strip_suffix('d') {
        Ok(Duration::from_secs(n.parse::<u64>()? * 86400))
    } else if let Some(n) = s.strip_suffix('h') {
        Ok(Duration::from_secs(n.parse::<u64>()? * 3600))
    } else if let Some(n) = s.strip_suffix('m') {
        Ok(Duration::from_secs(n.parse::<u64>()? * 60))
    } else if let Some(n) = s.strip_suffix('s') {
        Ok(Duration::from_secs(n.parse::<u64>()?))
    } else {
        anyhow::bail!("invalid duration '{s}': expected suffix d/h/m/s (e.g. 7d, 24h)")
    }
}

pub fn parse_bytes(s: &str) -> Result<u64> {
    let s_upper = s.to_uppercase();
    if let Some(n) = s_upper.strip_suffix("GB") {
        Ok(n.trim().parse::<u64>()? * 1_000_000_000)
    } else if let Some(n) = s_upper.strip_suffix("MB") {
        Ok(n.trim().parse::<u64>()? * 1_000_000)
    } else if let Some(n) = s_upper.strip_suffix("KB") {
        Ok(n.trim().parse::<u64>()? * 1_000)
    } else if let Some(n) = s_upper.strip_suffix('B') {
        Ok(n.trim().parse::<u64>()?)
    } else {
        s.parse::<u64>().map_err(|_| {
            anyhow::anyhow!("invalid size '{s}': expected suffix KB/MB/GB (e.g. 10GB)")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn parse_duration_days() {
        assert_eq!(
            parse_duration("7d").unwrap(),
            Duration::from_secs(7 * 86400)
        );
    }

    #[test]
    fn parse_duration_hours() {
        assert_eq!(parse_duration("24h").unwrap(), Duration::from_secs(86400));
    }

    #[test]
    fn parse_duration_minutes() {
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
    }

    #[test]
    fn parse_duration_seconds() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
    }

    #[test]
    fn parse_duration_invalid() {
        assert!(parse_duration("7x").is_err());
    }

    #[test]
    fn parse_bytes_gb() {
        assert_eq!(parse_bytes("10GB").unwrap(), 10_000_000_000);
    }

    #[test]
    fn parse_bytes_mb() {
        assert_eq!(parse_bytes("500MB").unwrap(), 500_000_000);
    }

    #[test]
    fn parse_bytes_kb() {
        assert_eq!(parse_bytes("100KB").unwrap(), 100_000);
    }

    #[test]
    fn parse_bytes_raw() {
        assert_eq!(parse_bytes("1024").unwrap(), 1024);
    }

    #[test]
    fn parse_bytes_invalid() {
        assert!(parse_bytes("lots").is_err());
    }
}
