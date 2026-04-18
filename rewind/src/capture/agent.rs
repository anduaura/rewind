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

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{AsyncPerfEventArray, HashMap},
    programs::{KProbe, TracePoint},
    util::online_cpus,
    Bpf, BpfLoader,
};
use aya_log::BpfLogger;
use bytes::BytesMut;
use std::sync::{Arc, Mutex};
use tokio::signal;

use crate::cli::{FlushArgs, RecordArgs};
use crate::store::snapshot::{DbRecord, Event, HttpRecord, Snapshot, SyscallRecord};
use rewind_common::{DbEvent, DbProtocol, Direction, HttpEvent, SyscallEvent};

// Embedded eBPF object file — built separately with:
//   cd rewind-ebpf && cargo build --target bpfel-unknown-none --release
#[cfg(not(test))]
static REWIND_EBPF: &[u8] = include_bytes_aligned!(
    "../../../rewind-ebpf/target/bpfel-unknown-none/release/rewind-ebpf"
);
#[cfg(test)]
static REWIND_EBPF: &[u8] = &[];

pub async fn run(args: RecordArgs) -> Result<()> {
    println!("rewind record");
    println!("  services: {}", args.services.join(", "));
    println!("  output:   {}", args.output.display());
    if args.capture_bodies {
        println!("  bodies:   enabled");
    }

    let events: Arc<Mutex<Vec<Event>>> = Arc::new(Mutex::new(Vec::new()));

    let mut bpf = BpfLoader::new()
        .load(REWIND_EBPF)
        .context("failed to load eBPF object — did you run `make build-ebpf`?")?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        eprintln!("warn: eBPF logger not available: {e}");
    }

    attach_probes(&mut bpf)?;
    init_watched_ports(&mut bpf)?;

    let http_task    = spawn_http_drain(&mut bpf, Arc::clone(&events))?;
    let syscall_task = spawn_syscall_drain(&mut bpf, Arc::clone(&events))?;
    let db_task      = spawn_db_drain(&mut bpf, Arc::clone(&events))?;

    println!("Recording… press Ctrl+C to flush and exit");
    signal::ctrl_c().await?;

    http_task.abort();
    syscall_task.abort();
    db_task.abort();

    let mut snapshot = Snapshot::new(args.services.clone());
    {
        let mut guard = events.lock().unwrap();
        guard.sort_by_key(|e| match e {
            Event::Http(h)    => h.timestamp_ns,
            Event::Syscall(s) => s.timestamp_ns,
            Event::Db(d)      => d.timestamp_ns,
        });
        snapshot.events = std::mem::take(&mut *guard);
    }

    println!(
        "\nFlushing {} events to {}",
        snapshot.events.len(),
        args.output.display()
    );
    snapshot.write(&args.output)?;
    println!("Done.");

    Ok(())
}

fn attach_probes(bpf: &mut Bpf) -> Result<()> {
    let kprobe: &mut KProbe = bpf
        .program_mut("tcp_sendmsg")
        .context("tcp_sendmsg program not found")?
        .try_into()?;
    kprobe.load()?;
    kprobe
        .attach("tcp_sendmsg", 0)
        .context("failed to attach kprobe to tcp_sendmsg")?;

    let tp: &mut TracePoint = bpf
        .program_mut("sys_exit")
        .context("sys_exit program not found")?
        .try_into()?;
    tp.load()?;
    tp.attach("syscalls", "sys_exit")
        .context("failed to attach tracepoint to syscalls:sys_exit")?;

    Ok(())
}

/// Seed the WATCHED_PORTS map so the eBPF probe knows which destination ports
/// carry DB traffic. The probe skips expensive parsing for all other ports.
fn init_watched_ports(bpf: &mut Bpf) -> Result<()> {
    let mut map: HashMap<_, u32, u8> = HashMap::try_from(
        bpf.map_mut("WATCHED_PORTS").context("WATCHED_PORTS map not found")?,
    )?;
    map.insert(5432u32, 0u8, 0)?; // Postgres
    map.insert(6379u32, 1u8, 0)?; // Redis
    Ok(())
}

// ── Per-map drain helpers ──────────────────────────────────────────────────────

fn spawn_http_drain(
    bpf: &mut Bpf,
    events: Arc<Mutex<Vec<Event>>>,
) -> Result<tokio::task::JoinHandle<()>> {
    drain_perf_array::<HttpEvent, _>(
        bpf, "HTTP_EVENTS", 1024, events,
        |buf| parse_http_event(buf).map(Event::Http),
    )
}

fn spawn_syscall_drain(
    bpf: &mut Bpf,
    events: Arc<Mutex<Vec<Event>>>,
) -> Result<tokio::task::JoinHandle<()>> {
    drain_perf_array::<SyscallEvent, _>(
        bpf, "SYSCALL_EVENTS", 256, events,
        |buf| parse_syscall_event(buf).map(Event::Syscall),
    )
}

fn spawn_db_drain(
    bpf: &mut Bpf,
    events: Arc<Mutex<Vec<Event>>>,
) -> Result<tokio::task::JoinHandle<()>> {
    drain_perf_array::<DbEvent, _>(
        bpf, "DB_EVENTS", 512, events,
        |buf| parse_db_event(buf).map(Event::Db),
    )
}

/// Generic helper: opens a PerfEventArray by name, spawns one reader task per
/// CPU, and pushes parsed events into `events` via the provided parser.
fn drain_perf_array<T, F>(
    bpf: &mut Bpf,
    map_name: &'static str,
    buf_capacity: usize,
    events: Arc<Mutex<Vec<Event>>>,
    parse: F,
) -> Result<tokio::task::JoinHandle<()>>
where
    T: aya::Pod,
    F: Fn(&BytesMut) -> Result<Event> + Send + Sync + 'static,
{
    let mut perf_array = AsyncPerfEventArray::try_from(
        bpf.take_map(map_name)
            .with_context(|| format!("{map_name} map not found"))?,
    )?;
    let parse = Arc::new(parse);

    let handle = tokio::spawn(async move {
        let cpus = online_cpus().unwrap_or_else(|_| vec![0]);
        let mut tasks = Vec::new();

        for cpu_id in cpus {
            let Ok(mut buf) = perf_array.open(cpu_id, Some(32)) else {
                continue;
            };
            let events = Arc::clone(&events);
            let parse  = Arc::clone(&parse);

            tasks.push(tokio::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(buf_capacity))
                    .collect::<Vec<_>>();
                loop {
                    let Ok(info) = buf.read_events(&mut buffers).await else { break };
                    for b in buffers.iter().take(info.read) {
                        if let Ok(event) = parse(b) {
                            events.lock().unwrap().push(event);
                        }
                    }
                }
            }));
        }
        for t in tasks { let _ = t.await; }
    });

    Ok(handle)
}

// ── Event parsers ──────────────────────────────────────────────────────────────

fn parse_http_event(buf: &BytesMut) -> Result<HttpRecord> {
    if buf.len() < std::mem::size_of::<HttpEvent>() {
        anyhow::bail!("buffer too small for HttpEvent");
    }
    let raw: HttpEvent = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const HttpEvent) };

    Ok(HttpRecord {
        timestamp_ns: raw.timestamp_ns,
        direction: match raw.direction {
            Direction::Inbound  => "inbound",
            Direction::Outbound => "outbound",
        }
        .to_string(),
        method: cstr_to_string(&raw.method),
        path: cstr_to_string(&raw.path),
        status_code: if raw.status_code == 0 { None } else { Some(raw.status_code) },
        service: String::new(),
        trace_id: None,
        body: None,
    })
}

fn parse_syscall_event(buf: &BytesMut) -> Result<SyscallRecord> {
    if buf.len() < std::mem::size_of::<SyscallEvent>() {
        anyhow::bail!("buffer too small for SyscallEvent");
    }
    let raw: SyscallEvent = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const SyscallEvent) };

    Ok(SyscallRecord {
        timestamp_ns: raw.timestamp_ns,
        kind: match raw.kind {
            rewind_common::SyscallKind::ClockGettime => "clock_gettime",
            rewind_common::SyscallKind::Getrandom    => "getrandom",
        }
        .to_string(),
        return_value: raw.return_value,
        pid: raw.pid,
    })
}

fn parse_db_event(buf: &BytesMut) -> Result<DbRecord> {
    if buf.len() < std::mem::size_of::<DbEvent>() {
        anyhow::bail!("buffer too small for DbEvent");
    }
    let raw: DbEvent = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const DbEvent) };

    let len = (raw.payload_len as usize).min(256);
    let payload = &raw.payload[..len];

    let (protocol, query) = match raw.protocol {
        DbProtocol::Postgres => ("postgres".to_string(), parse_postgres_payload(payload)),
        DbProtocol::Redis    => ("redis".to_string(),    parse_redis_payload(payload)),
    };

    Ok(DbRecord {
        timestamp_ns: raw.timestamp_ns,
        protocol,
        query,
        response: None,
        service: String::new(),
        pid: raw.pid,
    })
}

/// Parse a Postgres wire-protocol payload. Handles the most common client
/// message types:
///   'Q' (0x51) — simple query: Q + u32be length + null-terminated SQL
///   'P' (0x50) — prepared statement parse: P + len + name + SQL
fn parse_postgres_payload(data: &[u8]) -> String {
    if data.len() < 5 {
        return format!("(raw {} bytes)", data.len());
    }
    match data[0] {
        b'Q' | b'P' => {
            // Skip message type (1) + length (4); remainder is null-terminated SQL.
            let text = &data[5..];
            let end = text.iter().position(|&b| b == 0).unwrap_or(text.len());
            String::from_utf8_lossy(&text[..end]).trim().to_string()
        }
        // Startup message (no leading type byte): first 4 bytes are protocol version.
        _ => format!("(msg_type=0x{:02x} {} bytes)", data[0], data.len()),
    }
}

/// Parse a Redis RESP payload. Handles:
///   RESP arrays:   `*N\r\n$M\r\n<token>\r\n…`  (inline commands from clients)
///   Inline commands: `COMMAND arg1 arg2\r\n`
fn parse_redis_payload(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    let s = String::from_utf8_lossy(data);

    if data[0] == b'*' {
        // RESP array: extract the token strings (lines that don't start with * or $).
        let tokens: Vec<&str> = s
            .split("\r\n")
            .filter(|line| {
                !line.is_empty() && !line.starts_with('*') && !line.starts_with('$')
            })
            .take(6) // command + up to 5 args is plenty
            .collect();
        tokens.join(" ")
    } else {
        // Inline command: everything up to \r\n.
        let end = s.find("\r\n").unwrap_or(s.len());
        s[..end].to_string()
    }
}

fn cstr_to_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

pub async fn flush(args: FlushArgs) -> Result<()> {
    println!("rewind flush");
    println!("  window: {}", args.window);
    println!("  output: {}", args.output.display());
    println!("flush not yet implemented — start `rewind record` first");
    Ok(())
}
