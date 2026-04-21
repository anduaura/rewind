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

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

use crate::cli::InspectArgs;

#[derive(Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub version: u8,
    pub recorded_at_ns: u64,
    pub services: Vec<String>,
    pub events: Vec<Event>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Http(HttpRecord),
    Syscall(SyscallRecord),
    Db(DbRecord),
    Grpc(GrpcRecord),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GrpcRecord {
    pub timestamp_ns: u64,
    pub path: String, // "/package.Service/Method"
    pub service: String,
    pub pid: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HttpRecord {
    pub timestamp_ns: u64,
    pub direction: String,
    pub method: String,
    pub path: String,
    pub status_code: Option<u16>,
    pub service: String,
    pub trace_id: Option<String>,
    pub body: Option<String>,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyscallRecord {
    pub timestamp_ns: u64,
    pub kind: String,
    pub return_value: u64,
    pub pid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbRecord {
    pub timestamp_ns: u64,
    pub protocol: String, // "postgres" | "redis"
    pub query: String,
    pub response: Option<String>,
    pub service: String,
    pub pid: u32,
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::Http(h) => write!(
                f,
                "[{:>16}ns] HTTP {:6} {:3} {}  ({})",
                h.timestamp_ns,
                h.method,
                h.status_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "---".to_string()),
                h.path,
                h.direction,
            ),
            Event::Syscall(s) => write!(
                f,
                "[{:>16}ns] SYSCALL {:12} -> {}",
                s.timestamp_ns, s.kind, s.return_value
            ),
            Event::Db(d) => write!(
                f,
                "[{:>16}ns] DB {:8} {}",
                d.timestamp_ns, d.protocol, d.query
            ),
            Event::Grpc(g) => write!(
                f,
                "[{:>16}ns] GRPC {}  ({})",
                g.timestamp_ns, g.path, g.service
            ),
        }
    }
}

impl Snapshot {
    pub fn new(services: Vec<String>) -> Self {
        Self {
            version: 1,
            recorded_at_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
            services,
            events: Vec::new(),
        }
    }

    pub fn write(&self, path: &Path, key: Option<&str>) -> Result<()> {
        let json = serde_json::to_vec_pretty(self)?;
        let data = match key {
            Some(passphrase) => crate::crypto::encrypt(&json, passphrase)?,
            None => json,
        };
        std::fs::write(path, data)?;
        Ok(())
    }

    pub fn read(path: &Path, key: Option<&str>) -> Result<Self> {
        let raw = std::fs::read(path)?;
        let json = if crate::crypto::is_encrypted(&raw) {
            let passphrase = key.ok_or_else(|| {
                anyhow::anyhow!("snapshot is encrypted — provide --key or set REWIND_SNAPSHOT_KEY")
            })?;
            crate::crypto::decrypt(&raw, passphrase)?
        } else {
            raw
        };
        let snapshot: Self = serde_json::from_slice(&json)?;
        Ok(snapshot)
    }
}

pub async fn inspect(args: InspectArgs) -> Result<()> {
    let snapshot = Snapshot::read(
        &args.snapshot,
        crate::crypto::resolve_key(args.key).as_deref(),
    )?;

    let _ = crate::audit::log(&crate::audit::AuditEvent::Inspect {
        snapshot: &args.snapshot.to_string_lossy(),
        event_count: snapshot.events.len(),
    });

    let http_count = snapshot
        .events
        .iter()
        .filter(|e| matches!(e, Event::Http(_)))
        .count();
    let db_count = snapshot
        .events
        .iter()
        .filter(|e| matches!(e, Event::Db(_)))
        .count();
    let sys_count = snapshot
        .events
        .iter()
        .filter(|e| matches!(e, Event::Syscall(_)))
        .count();
    let grpc_count = snapshot
        .events
        .iter()
        .filter(|e| matches!(e, Event::Grpc(_)))
        .count();

    println!("rewind snapshot v{}", snapshot.version);
    println!("recorded:  {} ns since epoch", snapshot.recorded_at_ns);
    println!("services:  {}", snapshot.services.join(", "));
    println!(
        "events:    {}  (http={http_count} grpc={grpc_count} db={db_count} syscall={sys_count})",
        snapshot.events.len()
    );
    println!();

    for event in &snapshot.events {
        println!("{}", event);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sample_snapshot() -> Snapshot {
        let mut s = Snapshot::new(vec!["api".to_string(), "worker".to_string()]);
        s.events.push(Event::Http(HttpRecord {
            timestamp_ns: 1_000_000,
            direction: "inbound".to_string(),
            method: "POST".to_string(),
            path: "/checkout".to_string(),
            status_code: Some(200),
            service: "api".to_string(),
            trace_id: Some("00-abc-def-01".to_string()),
            body: None,
            headers: Vec::new(),
        }));
        s.events.push(Event::Db(DbRecord {
            timestamp_ns: 1_001_000,
            protocol: "postgres".to_string(),
            query: "SELECT * FROM orders".to_string(),
            response: Some("SELECT 1".to_string()),
            service: "api".to_string(),
            pid: 42,
        }));
        s.events.push(Event::Syscall(SyscallRecord {
            timestamp_ns: 1_002_000,
            kind: "clock_gettime".to_string(),
            return_value: 0,
            pid: 42,
        }));
        s.events.push(Event::Grpc(GrpcRecord {
            timestamp_ns: 1_003_000,
            path: "/payment.Service/Charge".to_string(),
            service: "worker".to_string(),
            pid: 99,
        }));
        s
    }

    #[test]
    fn snapshot_write_read_roundtrip() {
        let tmp = std::env::temp_dir().join("rewind_test_snapshot.rwd");
        let original = sample_snapshot();
        original.write(&tmp, None).expect("write failed");

        let loaded = Snapshot::read(&tmp, None).expect("read failed");
        std::fs::remove_file(&tmp).ok();

        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.services, vec!["api", "worker"]);
        assert_eq!(loaded.events.len(), 4);
    }

    #[test]
    fn snapshot_event_types_preserved() {
        let tmp = std::env::temp_dir().join("rewind_test_types.rwd");
        let original = sample_snapshot();
        original.write(&tmp, None).expect("write failed");

        let loaded = Snapshot::read(&tmp, None).expect("read failed");
        std::fs::remove_file(&tmp).ok();

        assert!(matches!(loaded.events[0], Event::Http(_)));
        assert!(matches!(loaded.events[1], Event::Db(_)));
        assert!(matches!(loaded.events[2], Event::Syscall(_)));
        assert!(matches!(loaded.events[3], Event::Grpc(_)));
    }

    #[test]
    fn snapshot_http_fields_roundtrip() {
        let tmp = std::env::temp_dir().join("rewind_test_http.rwd");
        let original = sample_snapshot();
        original.write(&tmp, None).expect("write failed");

        let loaded = Snapshot::read(&tmp, None).expect("read failed");
        std::fs::remove_file(&tmp).ok();

        if let Event::Http(h) = &loaded.events[0] {
            assert_eq!(h.method, "POST");
            assert_eq!(h.path, "/checkout");
            assert_eq!(h.status_code, Some(200));
            assert_eq!(h.trace_id.as_deref(), Some("00-abc-def-01"));
        } else {
            panic!("expected Http event");
        }
    }

    #[test]
    fn snapshot_db_fields_roundtrip() {
        let tmp = std::env::temp_dir().join("rewind_test_db.rwd");
        let original = sample_snapshot();
        original.write(&tmp, None).expect("write failed");

        let loaded = Snapshot::read(&tmp, None).expect("read failed");
        std::fs::remove_file(&tmp).ok();

        if let Event::Db(d) = &loaded.events[1] {
            assert_eq!(d.protocol, "postgres");
            assert_eq!(d.query, "SELECT * FROM orders");
            assert_eq!(d.response.as_deref(), Some("SELECT 1"));
        } else {
            panic!("expected Db event");
        }
    }

    #[test]
    fn snapshot_read_nonexistent_file_errors() {
        let result = Snapshot::read(&PathBuf::from("/nonexistent/path.rwd"), None);
        assert!(result.is_err());
    }

    #[test]
    fn snapshot_new_sets_version_one() {
        let s = Snapshot::new(vec![]);
        assert_eq!(s.version, 1);
        assert_eq!(s.events.len(), 0);
    }
}
