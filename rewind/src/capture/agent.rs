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
use std::collections::{HashMap as StdHashMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal;

use crate::capture::ring::RingBuffer;
use crate::cli::{AttachArgs, FlushArgs, RecordArgs};
use crate::store::snapshot::{DbRecord, Event, HttpRecord, Snapshot, SyscallRecord};
use rewind_common::{DbEvent, DbProtocol, Direction, HttpEvent, SyscallEvent};

const SOCKET_PATH: &str = "/tmp/rewind.sock";
const RING_MAX_EVENTS: usize = 200_000;

// (pid, protocol) → FIFO queue of queries waiting for a matching response
type PendingDb = StdHashMap<(u32, String), VecDeque<DbRecord>>;

// ── eBPF object ────────────────────────────────────────────────────────────────

#[cfg(not(test))]
static REWIND_EBPF: &[u8] = include_bytes_aligned!(
    "../../../rewind-ebpf/target/bpfel-unknown-none/release/rewind-ebpf"
);
#[cfg(test)]
static REWIND_EBPF: &[u8] = &[];

// ── Public entry points ────────────────────────────────────────────────────────

pub async fn run(args: RecordArgs) -> Result<()> {
    println!("rewind record");
    println!("  services: {}", args.services.join(", "));
    println!("  output:   {}", args.output.display());
    if args.capture_bodies {
        println!("  bodies:   enabled");
    }

    let ring: Arc<Mutex<RingBuffer>> = Arc::new(Mutex::new(RingBuffer::new(RING_MAX_EVENTS)));
    let pending_db: Arc<Mutex<PendingDb>> = Arc::new(Mutex::new(StdHashMap::new()));

    let mut bpf = BpfLoader::new()
        .load(REWIND_EBPF)
        .context("failed to load eBPF object — did you run `make build-ebpf`?")?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        eprintln!("warn: eBPF logger not available: {e}");
    }

    attach_probes(&mut bpf)?;
    init_watched_ports(&mut bpf)?;

    let http_task    = spawn_http_drain(&mut bpf, Arc::clone(&ring))?;
    let syscall_task = spawn_syscall_drain(&mut bpf, Arc::clone(&ring))?;
    let db_task      = spawn_db_drain(&mut bpf, Arc::clone(&ring), Arc::clone(&pending_db))?;

    let services = args.services.clone();
    let socket_task = tokio::spawn(run_socket_listener(
        Arc::clone(&ring),
        Arc::clone(&pending_db),
        services.clone(),
    ));

    println!("Recording… press Ctrl+C to stop, or run `rewind flush` to snapshot");
    signal::ctrl_c().await?;

    http_task.abort();
    syscall_task.abort();
    db_task.abort();
    socket_task.abort();

    let snapshot = build_snapshot(&ring, &pending_db, Duration::MAX, &services);
    println!("\nFlushing {} events to {}", snapshot.events.len(), args.output.display());
    snapshot.write(&args.output)?;
    println!("Done.");
    let _ = std::fs::remove_file(SOCKET_PATH);

    Ok(())
}

/// Read a Docker Compose file and start recording all discovered services.
pub async fn attach(args: AttachArgs) -> Result<()> {
    let services = detect_services(&args.compose)?;
    println!("Detected {} service(s): {}", services.len(), services.join(", "));
    run(RecordArgs {
        services,
        output: args.output,
        capture_bodies: args.capture_bodies,
    })
    .await
}

/// Parse `services:` keys from a docker-compose.yml (v2/v3 format).
fn detect_services(compose_path: &Path) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(compose_path)
        .with_context(|| format!("could not read {}", compose_path.display()))?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&content)
        .with_context(|| format!("invalid YAML in {}", compose_path.display()))?;
    let services = doc
        .get("services")
        .and_then(|s| s.as_mapping())
        .ok_or_else(|| {
            anyhow::anyhow!("no 'services' section in {}", compose_path.display())
        })?;
    let names: Vec<String> = services
        .keys()
        .filter_map(|k| k.as_str().map(str::to_string))
        .collect();
    if names.is_empty() {
        anyhow::bail!("no services found in {}", compose_path.display());
    }
    Ok(names)
}

pub async fn flush(args: FlushArgs) -> Result<()> {
    let window_secs = parse_window_secs(&args.window)?;

    let mut stream = UnixStream::connect(SOCKET_PATH)
        .await
        .context("could not connect to rewind agent — is `rewind record` running?")?;

    let msg = format!("FLUSH {} {}\n", window_secs, args.output.display());
    stream.write_all(msg.as_bytes()).await?;

    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response).await?;
    let response = response.trim();

    if let Some(rest) = response.strip_prefix("OK ") {
        let count: usize = rest.parse().unwrap_or(0);
        println!("Flushed {count} events to {}", args.output.display());
        Ok(())
    } else if let Some(msg) = response.strip_prefix("ERR ") {
        anyhow::bail!("agent error: {msg}")
    } else {
        anyhow::bail!("unexpected agent response: {response}")
    }
}

// ── eBPF setup ─────────────────────────────────────────────────────────────────

fn attach_probes(bpf: &mut Bpf) -> Result<()> {
    let prog: &mut KProbe = bpf
        .program_mut("tcp_sendmsg")
        .context("tcp_sendmsg program not found")?
        .try_into()?;
    prog.load()?;
    prog.attach("tcp_sendmsg", 0)
        .context("failed to attach kprobe to tcp_sendmsg")?;

    let prog: &mut KProbe = bpf
        .program_mut("tcp_recvmsg_enter")
        .context("tcp_recvmsg_enter program not found")?
        .try_into()?;
    prog.load()?;
    prog.attach("tcp_recvmsg", 0)
        .context("failed to attach kprobe to tcp_recvmsg")?;

    let prog: &mut KProbe = bpf
        .program_mut("tcp_recvmsg_ret")
        .context("tcp_recvmsg_ret program not found")?
        .try_into()?;
    prog.load()?;
    prog.attach("tcp_recvmsg", 0)
        .context("failed to attach kretprobe to tcp_recvmsg")?;

    let prog: &mut TracePoint = bpf
        .program_mut("sys_exit")
        .context("sys_exit program not found")?
        .try_into()?;
    prog.load()?;
    prog.attach("syscalls", "sys_exit")
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

// ── Drain task spawners ────────────────────────────────────────────────────────

fn spawn_http_drain(
    bpf: &mut Bpf,
    ring: Arc<Mutex<RingBuffer>>,
) -> Result<tokio::task::JoinHandle<()>> {
    drain_perf_array::<HttpEvent, _>(
        bpf, "HTTP_EVENTS", 1024, ring,
        |buf| parse_http_event(buf).map(Event::Http),
    )
}

fn spawn_syscall_drain(
    bpf: &mut Bpf,
    ring: Arc<Mutex<RingBuffer>>,
) -> Result<tokio::task::JoinHandle<()>> {
    drain_perf_array::<SyscallEvent, _>(
        bpf, "SYSCALL_EVENTS", 256, ring,
        |buf| parse_syscall_event(buf).map(Event::Syscall),
    )
}

fn spawn_db_drain(
    bpf: &mut Bpf,
    ring: Arc<Mutex<RingBuffer>>,
    pending_db: Arc<Mutex<PendingDb>>,
) -> Result<tokio::task::JoinHandle<()>> {
    let mut perf_array = AsyncPerfEventArray::try_from(
        bpf.take_map("DB_EVENTS").context("DB_EVENTS map not found")?,
    )?;

    let handle = tokio::spawn(async move {
        let cpus = online_cpus().unwrap_or_else(|_| vec![0]);
        let mut tasks = Vec::new();

        for cpu_id in cpus {
            let Ok(mut buf) = perf_array.open(cpu_id, Some(32)) else { continue };
            let ring = Arc::clone(&ring);
            let pending_db = Arc::clone(&pending_db);

            tasks.push(tokio::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(512))
                    .collect::<Vec<_>>();
                loop {
                    let Ok(info) = buf.read_events(&mut buffers).await else { break };
                    for b in buffers.iter().take(info.read) {
                        correlate_db_buf(b, &ring, &pending_db);
                    }
                }
            }));
        }
        for t in tasks {
            let _ = t.await;
        }
    });

    Ok(handle)
}

/// Generic helper: opens a PerfEventArray by name, spawns one reader task per
/// CPU, and pushes parsed events into the ring buffer via the provided parser.
fn drain_perf_array<T, F>(
    bpf: &mut Bpf,
    map_name: &'static str,
    buf_capacity: usize,
    ring: Arc<Mutex<RingBuffer>>,
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
            let Ok(mut buf) = perf_array.open(cpu_id, Some(32)) else { continue };
            let ring  = Arc::clone(&ring);
            let parse = Arc::clone(&parse);

            tasks.push(tokio::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(buf_capacity))
                    .collect::<Vec<_>>();
                loop {
                    let Ok(info) = buf.read_events(&mut buffers).await else { break };
                    for b in buffers.iter().take(info.read) {
                        if let Ok(event) = parse(b) {
                            ring.lock().unwrap().push(event);
                        }
                    }
                }
            }));
        }
        for t in tasks {
            let _ = t.await;
        }
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
        trace_id: extract_traceparent(&raw.headers_raw),
        body: None,
    })
}

/// Scans raw header bytes for the W3C `traceparent` header and returns its value.
fn extract_traceparent(headers_raw: &[u8; 128]) -> Option<String> {
    let end = headers_raw.iter().position(|&b| b == 0).unwrap_or(128);
    let s = std::str::from_utf8(&headers_raw[..end]).ok()?;
    let lower = s.to_ascii_lowercase();
    let pos = lower.find("traceparent:")?;
    let after = s[pos + 12..].trim_start_matches([' ', '\t']);
    let end = after.find('\r').or_else(|| after.find('\n')).unwrap_or(after.len());
    let value = after[..end].trim();
    if value.is_empty() { None } else { Some(value.to_string()) }
}

fn parse_syscall_event(buf: &BytesMut) -> Result<SyscallRecord> {
    if buf.len() < std::mem::size_of::<SyscallEvent>() {
        anyhow::bail!("buffer too small for SyscallEvent");
    }
    let raw: SyscallEvent =
        unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const SyscallEvent) };

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

// ── DB correlation ─────────────────────────────────────────────────────────────
//
// Queries go into `pending_db` (keyed by pid+protocol). When the matching
// response arrives the pair is completed and pushed to the ring buffer.
// Any queries still pending at flush time are included without a response.

fn correlate_db_buf(
    buf: &BytesMut,
    ring: &Arc<Mutex<RingBuffer>>,
    pending: &Arc<Mutex<PendingDb>>,
) {
    if buf.len() < std::mem::size_of::<DbEvent>() {
        return;
    }
    let raw: DbEvent = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const DbEvent) };

    let len = (raw.payload_len as usize).min(256);
    let payload = &raw.payload[..len];
    let protocol = match raw.protocol {
        DbProtocol::Postgres => "postgres",
        DbProtocol::Redis    => "redis",
    };

    if raw.is_response == 0 {
        let query = match raw.protocol {
            DbProtocol::Postgres => parse_postgres_query(payload),
            DbProtocol::Redis    => parse_redis_query(payload),
        };
        let record = DbRecord {
            timestamp_ns: raw.timestamp_ns,
            protocol: protocol.to_string(),
            query,
            response: None,
            service: String::new(),
            pid: raw.pid,
        };
        pending
            .lock()
            .unwrap()
            .entry((raw.pid, protocol.to_string()))
            .or_default()
            .push_back(record);
    } else {
        let response_text = match raw.protocol {
            DbProtocol::Postgres => parse_postgres_response(payload),
            DbProtocol::Redis    => parse_redis_response(payload),
        };
        let completed = pending
            .lock()
            .unwrap()
            .get_mut(&(raw.pid, protocol.to_string()))
            .and_then(|q| q.pop_front());
        if let Some(mut record) = completed {
            record.response = Some(response_text);
            ring.lock().unwrap().push(Event::Db(record));
        }
    }
}

/// Postgres client messages: 'Q' = simple query, 'P' = extended parse.
fn parse_postgres_query(data: &[u8]) -> String {
    if data.len() < 5 {
        return format!("(raw {} bytes)", data.len());
    }
    match data[0] {
        b'Q' | b'P' => {
            let text = &data[5..];
            let end = text.iter().position(|&b| b == 0).unwrap_or(text.len());
            String::from_utf8_lossy(&text[..end]).trim().to_string()
        }
        _ => format!("(msg_type=0x{:02x} {} bytes)", data[0], data.len()),
    }
}

/// Redis RESP arrays (`*N\r\n$M\r\n<token>…`) and inline commands.
fn parse_redis_query(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    let s = String::from_utf8_lossy(data);
    if data[0] == b'*' {
        let tokens: Vec<&str> = s
            .split("\r\n")
            .filter(|line| !line.is_empty() && !line.starts_with('*') && !line.starts_with('$'))
            .take(6)
            .collect();
        tokens.join(" ")
    } else {
        let end = s.find("\r\n").unwrap_or(s.len());
        s[..end].to_string()
    }
}

/// Postgres server messages: CommandComplete ('C') is the most informative.
fn parse_postgres_response(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    match data[0] {
        b'C' if data.len() >= 5 => {
            let text = &data[5..];
            let end = text.iter().position(|&b| b == 0).unwrap_or(text.len());
            String::from_utf8_lossy(&text[..end]).trim().to_string()
        }
        b'E' if data.len() >= 5 => {
            let fields = &data[5..];
            let mut i = 0usize;
            while i < fields.len() {
                let code = fields[i];
                i += 1;
                let len = fields[i..].iter().position(|&b| b == 0).unwrap_or(fields.len() - i);
                if code == b'M' {
                    return format!("ERR: {}", String::from_utf8_lossy(&fields[i..i + len]));
                }
                i += len + 1;
            }
            "ERR".to_string()
        }
        b'Z' => "ReadyForQuery".to_string(),
        b'T' => "RowDescription".to_string(),
        b'D' => "DataRow".to_string(),
        b'1' => "ParseComplete".to_string(),
        b'2' => "BindComplete".to_string(),
        b'n' => "NoData".to_string(),
        b'I' => "EmptyQueryResponse".to_string(),
        _ => format!("(response 0x{:02x})", data[0]),
    }
}

/// Redis server responses: simple string, error, integer, bulk string, array.
fn parse_redis_response(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    let s = String::from_utf8_lossy(data);
    match data[0] {
        b'+' => {
            let end = s.find("\r\n").unwrap_or(s.len());
            s[1..end].to_string()
        }
        b'-' => {
            let end = s.find("\r\n").unwrap_or(s.len());
            format!("ERR: {}", &s[1..end])
        }
        b':' => {
            let end = s.find("\r\n").unwrap_or(s.len());
            format!("(integer) {}", &s[1..end])
        }
        b'$' => {
            if let Some(cr) = s.find("\r\n") {
                if let Ok(n) = s[1..cr].parse::<i64>() {
                    if n < 0 {
                        return "(nil)".to_string();
                    }
                    let start = cr + 2;
                    let end = (start + n as usize).min(s.len());
                    return s[start..end].to_string();
                }
            }
            "(bulk)".to_string()
        }
        b'*' => "(array)".to_string(),
        _ => s[..s.find("\r\n").unwrap_or(s.len().min(64))].to_string(),
    }
}

fn cstr_to_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

// ── Snapshot assembly ──────────────────────────────────────────────────────────

/// Collects events from the ring buffer within `window`, appends any pending
/// (unmatched) DB queries, and returns a sorted snapshot ready to write.
fn build_snapshot(
    ring: &Arc<Mutex<RingBuffer>>,
    pending_db: &Arc<Mutex<PendingDb>>,
    window: Duration,
    services: &[String],
) -> Snapshot {
    let mut events = ring.lock().unwrap().drain_window(window);

    {
        let pending = pending_db.lock().unwrap();
        for queue in pending.values() {
            for record in queue {
                events.push(Event::Db(record.clone()));
            }
        }
    }

    events.sort_by_key(|e| match e {
        Event::Http(h)    => h.timestamp_ns,
        Event::Syscall(s) => s.timestamp_ns,
        Event::Db(d)      => d.timestamp_ns,
    });

    let mut snapshot = Snapshot::new(services.to_vec());
    snapshot.events = events;
    snapshot
}

// ── Unix socket IPC ────────────────────────────────────────────────────────────

async fn run_socket_listener(
    ring: Arc<Mutex<RingBuffer>>,
    pending_db: Arc<Mutex<PendingDb>>,
    services: Vec<String>,
) {
    let _ = std::fs::remove_file(SOCKET_PATH);
    let listener = match UnixListener::bind(SOCKET_PATH) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("warn: could not bind Unix socket {SOCKET_PATH}: {e}");
            return;
        }
    };

    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let ring       = Arc::clone(&ring);
        let pending_db = Arc::clone(&pending_db);
        let services   = services.clone();
        tokio::spawn(async move {
            handle_flush_conn(stream, ring, pending_db, services).await;
        });
    }
}

async fn handle_flush_conn(
    stream: UnixStream,
    ring: Arc<Mutex<RingBuffer>>,
    pending_db: Arc<Mutex<PendingDb>>,
    services: Vec<String>,
) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    if reader.read_line(&mut line).await.is_err() {
        return;
    }

    // Protocol: "FLUSH <window_secs> <output_path>\n"
    let parts: Vec<&str> = line.trim().splitn(3, ' ').collect();
    if parts.len() < 3 || parts[0] != "FLUSH" {
        let _ = writer.write_all(b"ERR invalid command\n").await;
        return;
    }

    let window_secs: u64 = match parts[1].parse() {
        Ok(s) => s,
        Err(_) => {
            let _ = writer.write_all(b"ERR invalid window\n").await;
            return;
        }
    };
    let output_path = parts[2].to_string();

    let snapshot =
        build_snapshot(&ring, &pending_db, Duration::from_secs(window_secs), &services);
    let count = snapshot.events.len();

    match snapshot.write(Path::new(&output_path)) {
        Ok(()) => {
            let _ = writer.write_all(format!("OK {count}\n").as_bytes()).await;
        }
        Err(e) => {
            let _ = writer.write_all(format!("ERR {e}\n").as_bytes()).await;
        }
    }
}

fn parse_window_secs(window: &str) -> Result<u64> {
    if let Some(n) = window.strip_suffix('m') {
        Ok(n.parse::<u64>()? * 60)
    } else if let Some(n) = window.strip_suffix('s') {
        Ok(n.parse::<u64>()?)
    } else if let Some(n) = window.strip_suffix('h') {
        Ok(n.parse::<u64>()? * 3600)
    } else {
        window
            .parse::<u64>()
            .map_err(|e| anyhow::anyhow!("invalid window '{window}': {e}"))
    }
}
