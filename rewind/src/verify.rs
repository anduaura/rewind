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

//! Snapshot integrity verification — SHA-256 manifest + tamper detection.
//!
//! A manifest sidecar file (`<snapshot>.sha256`) stores the SHA-256 hash of
//! the raw snapshot bytes in sha256sum-compatible format:
//!
//!   <64-hex-chars>  incident.rwd
//!
//! Usage:
//!   rewind verify incident.rwd --write    # create / refresh manifest
//!   rewind verify incident.rwd            # check; exits 1 on tamper, 2 on missing
//!   rewind verify incident.rwd --json     # machine-readable output

use anyhow::Result;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use crate::cli::VerifyArgs;

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum VerifyStatus {
    Ok,
    Tampered,
    NoManifest,
    Written,
}

#[derive(Debug, Serialize)]
pub struct VerifyReport {
    pub snapshot: String,
    pub manifest: String,
    pub hash_actual: String,
    pub hash_expected: String,
    pub status: VerifyStatus,
}

pub async fn run(args: VerifyArgs) -> Result<()> {
    let snap = &args.snapshot;
    let manifest = manifest_path(snap);

    let raw = tokio::fs::read(snap)
        .await
        .map_err(|e| anyhow::anyhow!("reading {:?}: {e}", snap))?;
    let actual = sha256_hex(&raw);

    if args.write {
        let filename = snap
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let content = format!("{actual}  {filename}\n");
        tokio::fs::write(&manifest, content)
            .await
            .map_err(|e| anyhow::anyhow!("writing manifest {:?}: {e}", manifest))?;

        let report = VerifyReport {
            snapshot: snap.to_string_lossy().to_string(),
            manifest: manifest.to_string_lossy().to_string(),
            hash_actual: actual.clone(),
            hash_expected: actual,
            status: VerifyStatus::Written,
        };
        emit(&report, args.json);
        return Ok(());
    }

    // Read and parse existing manifest.
    let manifest_text = match tokio::fs::read_to_string(&manifest).await {
        Ok(t) => t,
        Err(_) => {
            let report = VerifyReport {
                snapshot: snap.to_string_lossy().to_string(),
                manifest: manifest.to_string_lossy().to_string(),
                hash_actual: actual,
                hash_expected: String::new(),
                status: VerifyStatus::NoManifest,
            };
            emit(&report, args.json);
            if !args.allow_missing {
                std::process::exit(2);
            }
            return Ok(());
        }
    };

    let expected = parse_manifest_hash(&manifest_text)
        .ok_or_else(|| anyhow::anyhow!("unrecognised manifest format in {:?}", manifest))?;

    let status = if actual == expected {
        VerifyStatus::Ok
    } else {
        VerifyStatus::Tampered
    };

    let report = VerifyReport {
        snapshot: snap.to_string_lossy().to_string(),
        manifest: manifest.to_string_lossy().to_string(),
        hash_actual: actual,
        hash_expected: expected,
        status,
    };
    emit(&report, args.json);

    if report.status == VerifyStatus::Tampered {
        std::process::exit(1);
    }
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Returns `<snapshot_path>.sha256`.
fn manifest_path(snapshot: &Path) -> PathBuf {
    let mut s = snapshot.as_os_str().to_owned();
    s.push(".sha256");
    PathBuf::from(s)
}

/// SHA-256 of `data` as a lowercase hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse the hash from a sha256sum-format line: `<64 hex chars>  <filename>`.
pub fn parse_manifest_hash(content: &str) -> Option<String> {
    let line = content.lines().find(|l| !l.trim().is_empty())?;
    let hash = line.split_whitespace().next()?;
    if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(hash.to_string())
    } else {
        None
    }
}

fn emit(report: &VerifyReport, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(report).unwrap_or_default()
        );
        return;
    }
    println!("rewind verify");
    println!("  snapshot: {}", report.snapshot);
    println!("  manifest: {}", report.manifest);
    println!();
    match report.status {
        VerifyStatus::Written => {
            println!("✓ manifest written");
            println!("  sha256: {}", report.hash_actual);
        }
        VerifyStatus::Ok => {
            println!("✓ integrity ok");
            println!("  sha256: {}", report.hash_actual);
        }
        VerifyStatus::Tampered => {
            println!("✗ TAMPERED — hash mismatch");
            println!("  expected: {}", report.hash_expected);
            println!("  actual:   {}", report.hash_actual);
        }
        VerifyStatus::NoManifest => {
            println!("? no manifest found");
            println!("  run with --write to create one");
            println!("  sha256: {}", report.hash_actual);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_empty_bytes_known_hash() {
        // SHA-256 of empty input is a known constant
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_deterministic() {
        // Same input always produces same output.
        assert_eq!(sha256_hex(b"rewind"), sha256_hex(b"rewind"));
        // Different inputs produce different outputs.
        assert_ne!(sha256_hex(b"rewind"), sha256_hex(b"rewInD"));
    }

    #[test]
    fn sha256_output_is_64_hex_chars() {
        for input in [b"".as_ref(), b"abc", b"rewind snapshot data"] {
            let h = sha256_hex(input);
            assert_eq!(h.len(), 64, "hash of {input:?} should be 64 chars");
            assert!(
                h.chars().all(|c| c.is_ascii_hexdigit()),
                "hash should be hex"
            );
        }
    }

    #[test]
    fn parse_manifest_hash_standard_format() {
        let content =
            "abc123def456abc123def456abc123def456abc123def456abc123def456abc1  incident.rwd\n";
        assert_eq!(
            parse_manifest_hash(content),
            Some("abc123def456abc123def456abc123def456abc123def456abc123def456abc1".to_string())
        );
    }

    #[test]
    fn parse_manifest_hash_rejects_short_hash() {
        assert!(parse_manifest_hash("abc123  file.rwd\n").is_none());
    }

    #[test]
    fn parse_manifest_hash_rejects_non_hex() {
        let bad = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz  f.rwd";
        assert!(parse_manifest_hash(bad).is_none());
    }

    #[test]
    fn parse_manifest_hash_skips_blank_lines() {
        let content =
            "\n\nabc123def456abc123def456abc123def456abc123def456abc123def456abc1  f.rwd\n";
        assert!(parse_manifest_hash(content).is_some());
    }

    #[test]
    fn manifest_path_appends_sha256_extension() {
        let p = PathBuf::from("/var/rewind/incident.rwd");
        assert_eq!(
            manifest_path(&p),
            PathBuf::from("/var/rewind/incident.rwd.sha256")
        );
    }

    #[test]
    fn verify_status_serialises_correctly() {
        assert_eq!(serde_json::to_string(&VerifyStatus::Ok).unwrap(), "\"ok\"");
        assert_eq!(
            serde_json::to_string(&VerifyStatus::Tampered).unwrap(),
            "\"tampered\""
        );
        assert_eq!(
            serde_json::to_string(&VerifyStatus::NoManifest).unwrap(),
            "\"no_manifest\""
        );
        assert_eq!(
            serde_json::to_string(&VerifyStatus::Written).unwrap(),
            "\"written\""
        );
    }
}
