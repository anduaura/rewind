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

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Http(HttpRecord),
    Syscall(SyscallRecord),
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct SyscallRecord {
    pub timestamp_ns: u64,
    pub kind: String,
    pub return_value: u64,
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

    println!("rewind snapshot v{}", snapshot.version);
    println!("recorded:  {} ns since epoch", snapshot.recorded_at_ns);
    println!("services:  {}", snapshot.services.join(", "));
    println!("events:    {}", snapshot.events.len());
    println!();

    for event in &snapshot.events {
        println!("{}", event);
    }

    Ok(())
}
