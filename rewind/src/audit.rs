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

//! Structured audit log — one JSON line per significant rewind event.
//!
//! Default path: /var/log/rewind/audit.log (falls back to ./rewind-audit.log
//! when the directory is not writable). Controlled by REWIND_AUDIT_LOG env var.
//!
//! Each record:
//!   {"ts":"2026-04-19T12:00:00Z","action":"capture_start","user":"root","pid":1234,...}

use anyhow::Result;
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

const DEFAULT_LOG_DIR: &str = "/var/log/rewind";
const FALLBACK_LOG: &str = "rewind-audit.log";

#[derive(Debug, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum AuditEvent<'a> {
    CaptureStart {
        services: &'a [String],
        output: &'a str,
        encrypted: bool,
    },
    CaptureStop {
        output: &'a str,
        events_flushed: usize,
    },
    Flush {
        output: &'a str,
        window_secs: u64,
        events_flushed: usize,
    },
    ReplayStart {
        snapshot: &'a str,
        compose: &'a str,
        encrypted: bool,
    },
    ReplayComplete {
        snapshot: &'a str,
        status_code: u16,
    },
    Inspect {
        snapshot: &'a str,
        event_count: usize,
    },
    Export {
        snapshot: &'a str,
        format: &'a str,
    },
    Push {
        snapshot: &'a str,
        destination: &'a str,
    },
}

#[derive(Serialize)]
struct LogRecord<'a> {
    ts: String,
    user: String,
    pid: u32,
    #[serde(flatten)]
    event: &'a AuditEvent<'a>,
}

pub fn log(event: &AuditEvent<'_>) -> Result<()> {
    let record = LogRecord {
        ts: now_rfc3339(),
        user: current_user(),
        pid: std::process::id(),
        event,
    };
    let line = serde_json::to_string(&record)? + "\n";

    let path = log_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .or_else(|_| {
            // Fallback to cwd when /var/log/rewind isn't writable.
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(FALLBACK_LOG)
        })?;

    f.write_all(line.as_bytes())?;
    Ok(())
}

fn log_path() -> PathBuf {
    if let Ok(p) = std::env::var("REWIND_AUDIT_LOG") {
        return PathBuf::from(p);
    }
    PathBuf::from(DEFAULT_LOG_DIR).join("audit.log")
}

fn now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Minimal RFC 3339 without pulling in chrono: format as UTC.
    let (y, mo, d, h, mi, s) = epoch_to_ymd_hms(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

fn epoch_to_ymd_hms(mut secs: u64) -> (u64, u64, u64, u64, u64, u64) {
    let s = secs % 60;
    secs /= 60;
    let mi = secs % 60;
    secs /= 60;
    let h = secs % 24;
    secs /= 24;
    // Days since 1970-01-01
    let (y, mo, d) = days_to_ymd(secs);
    (y, mo, d, h, mi, s)
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    // Gregorian calendar approximation sufficient for audit timestamps.
    let mut year = 1970u64;
    loop {
        let leap = is_leap(year);
        let days_in_year = if leap { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }
    let leap = is_leap(year);
    let months = [
        31u64,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1u64;
    for &dim in &months {
        if days < dim {
            break;
        }
        days -= dim;
        month += 1;
    }
    (year, month, days + 1)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| format!("uid:{}", unsafe { libc_getuid() }))
}

#[cfg(unix)]
fn libc_getuid() -> u32 {
    unsafe extern "C" {
        fn getuid() -> u32;
    }
    unsafe { getuid() }
}

#[cfg(not(unix))]
fn libc_getuid() -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_event_serialises_to_json() {
        let ev = AuditEvent::CaptureStart {
            services: &["api".to_string(), "worker".to_string()],
            output: "incident.rwd",
            encrypted: false,
        };
        let record = LogRecord {
            ts: "2026-04-19T12:00:00Z".to_string(),
            user: "root".to_string(),
            pid: 1,
            event: &ev,
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"action\":\"capture_start\""));
        assert!(json.contains("\"encrypted\":false"));
        assert!(json.contains("\"output\":\"incident.rwd\""));
    }

    #[test]
    fn flush_event_serialises() {
        let ev = AuditEvent::Flush {
            output: "out.rwd",
            window_secs: 300,
            events_flushed: 42,
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"action\":\"flush\""));
        assert!(json.contains("\"events_flushed\":42"));
    }

    #[test]
    fn now_rfc3339_looks_valid() {
        let ts = now_rfc3339();
        assert!(ts.ends_with('Z'));
        assert!(ts.contains('T'));
        assert_eq!(ts.len(), 20);
    }

    #[test]
    fn epoch_zero_is_epoch() {
        let (y, mo, d, h, mi, s) = epoch_to_ymd_hms(0);
        assert_eq!((y, mo, d, h, mi, s), (1970, 1, 1, 0, 0, 0));
    }

    #[test]
    fn log_path_uses_env_var() {
        std::env::set_var("REWIND_AUDIT_LOG", "/tmp/rewind-test-audit.log");
        let p = log_path();
        std::env::remove_var("REWIND_AUDIT_LOG");
        assert_eq!(p, std::path::PathBuf::from("/tmp/rewind-test-audit.log"));
    }
}
