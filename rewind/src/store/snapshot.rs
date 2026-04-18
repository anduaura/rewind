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

    pub fn write(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn read(path: &Path) -> Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let snapshot: Self = serde_json::from_str(&json)?;
        Ok(snapshot)
    }
}

pub async fn inspect(args: InspectArgs) -> Result<()> {
    let snapshot = Snapshot::read(&args.snapshot)?;

    let http_count  = snapshot.events.iter().filter(|e| matches!(e, Event::Http(_))).count();
    let db_count    = snapshot.events.iter().filter(|e| matches!(e, Event::Db(_))).count();
    let sys_count   = snapshot.events.iter().filter(|e| matches!(e, Event::Syscall(_))).count();

    println!("rewind snapshot v{}", snapshot.version);
    println!("recorded:  {} ns since epoch", snapshot.recorded_at_ns);
    println!("services:  {}", snapshot.services.join(", "));
    println!("events:    {}  (http={http_count} db={db_count} syscall={sys_count})", snapshot.events.len());
    println!();

    for event in &snapshot.events {
        println!("{}", event);
    }

    Ok(())
}
