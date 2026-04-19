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
    map.insert(5432u32,  0u8, 0)?; // Postgres
    map.insert(6379u32,  1u8, 0)?; // Redis
    map.insert(3306u32,  2u8, 0)?; // MySQL
    map.insert(27017u32, 3u8, 0)?; // MongoDB
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
        DbProtocol::MySQL    => "mysql",
        DbProtocol::MongoDB  => "mongodb",
    };

    if raw.is_response == 0 {
        let query = match raw.protocol {
            DbProtocol::Postgres => parse_postgres_query(payload),
            DbProtocol::Redis    => parse_redis_query(payload),
            DbProtocol::MySQL    => parse_mysql_query(payload),
            DbProtocol::MongoDB  => parse_mongodb_query(payload),
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
            DbProtocol::MySQL    => parse_mysql_response(payload),
            DbProtocol::MongoDB  => parse_mongodb_response(payload),
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
/// MySQL client wire protocol: 3-byte packet length (LE) + 1-byte seq + payload.
/// COM_QUERY (0x03): payload[0] == 0x03, remaining bytes are the SQL text.
/// COM_STMT_PREPARE (0x16): prepared statement SQL follows the command byte.
fn parse_mysql_query(data: &[u8]) -> String {
    if data.len() < 5 {
        return format!("(raw {} bytes)", data.len());
    }
    match data[4] {
        0x03 | 0x16 => String::from_utf8_lossy(&data[5..]).trim_end_matches('\0').trim().to_string(),
        cmd => format!("(cmd=0x{cmd:02x} {} bytes)", data.len()),
    }
}

/// MySQL server response: skip 4-byte packet header, inspect status byte.
/// 0x00 = OK (affected_rows and last_insert_id follow as length-encoded ints).
/// 0xFF = ERR (2-byte error code + '#' + 5-byte SQLSTATE + message).
/// 0xFE = EOF / AuthSwitch.
fn parse_mysql_response(data: &[u8]) -> String {
    if data.len() < 5 {
        return String::new();
    }
    match data[4] {
        0x00 => "OK".to_string(),
        0xfe => "EOF".to_string(),
        0xff if data.len() >= 13 => {
            // error code (2 bytes LE) + '#' + sqlstate (5) + message
            let code = u16::from_le_bytes([data[5], data[6]]);
            let msg_start = 13; // skip '#' + sqlstate
            let msg = String::from_utf8_lossy(&data[msg_start..]).trim_end_matches('\0').to_string();
            format!("ERR {code}: {msg}")
        }
        0xff => "ERR".to_string(),
        _ => format!("(result columns={})", data[4]),
    }
}

/// MongoDB OP_MSG (opcode 2013): header(16) + flags(4) + section_kind(1) + BSON doc.
/// The first BSON element key is the command name; its string value is the collection.
fn parse_mongodb_query(data: &[u8]) -> String {
    if data.len() < 16 {
        return format!("(raw {} bytes)", data.len());
    }
    let opcode = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    match opcode {
        2013 => {
            // OP_MSG: skip header(16) + flags(4) + section_kind(1) + bson_len(4) = offset 25
            if data.len() < 26 {
                return "(op_msg)".to_string();
            }
            // First BSON element: type(1) at offset 25, key cstring at offset 26
            let elem_type = data[25];
            let key_start = 26usize;
            let key_end = data[key_start..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| key_start + p)
                .unwrap_or(data.len());
            let cmd = String::from_utf8_lossy(&data[key_start..key_end]);
            // If string type (0x02), read collection name that follows
            if elem_type == 0x02 {
                let val_start = key_end + 1;
                if data.len() >= val_start + 5 {
                    let str_len = u32::from_le_bytes([
                        data[val_start], data[val_start+1],
                        data[val_start+2], data[val_start+3],
                    ]) as usize;
                    let s = val_start + 4;
                    let e = (s + str_len).min(data.len()).saturating_sub(1);
                    let coll = String::from_utf8_lossy(&data[s..e]);
                    return format!("{cmd} {coll}");
                }
            }
            cmd.to_string()
        }
        2004 => {
            // OP_QUERY (legacy): header(16) + flags(4) + collection cstring at offset 20
            if data.len() <= 20 {
                return "(op_query)".to_string();
            }
            let end = data[20..]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(data.len() - 20);
            format!("query {}", String::from_utf8_lossy(&data[20..20 + end]))
        }
        _ => format!("(opcode={opcode})"),
    }
}

/// MongoDB server responses: OP_REPLY reports numberReturned; OP_MSG carries an
/// "ok" field in the BSON body (1.0 = success, 0.0 = command error).
fn parse_mongodb_response(data: &[u8]) -> String {
    if data.len() < 16 {
        return String::new();
    }
    let opcode = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    match opcode {
        1 => {
            // OP_REPLY: numberReturned at bytes 32-35
            if data.len() >= 36 {
                let n = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
                format!("OP_REPLY docs={n}")
            } else {
                "OP_REPLY".to_string()
            }
        }
        2013 => {
            // OP_MSG: scan BSON body for "ok" double field (type 0x01)
            // body starts at offset 21 (header 16 + flags 4 + kind 1)
            if data.len() < 26 {
                return "OP_MSG".to_string();
            }
            let body = &data[25..]; // skip bson_length(4) already included at offset 21
            let mut i = 4usize; // skip bson_length
            while i + 1 < body.len() {
                let t = body[i];
                i += 1;
                let key_end = body[i..].iter().position(|&b| b == 0).unwrap_or(body.len() - i);
                let key = &body[i..i + key_end];
                i += key_end + 1;
                match t {
                    0x01 if key == b"ok" && i + 8 <= body.len() => {
                        let v = f64::from_le_bytes(body[i..i+8].try_into().unwrap_or([0;8]));
                        return if v == 1.0 { "ok".to_string() } else { "err".to_string() };
                    }
                    0x01 => i += 8,
                    0x10 => i += 4,
                    0x12 => i += 8,
                    0x08 => i += 1,
                    0x02 | 0x0D | 0x0E if i + 4 <= body.len() => {
                        let l = u32::from_le_bytes([body[i], body[i+1], body[i+2], body[i+3]]) as usize;
                        i += 4 + l;
                    }
                    _ => break,
                }
            }
            "OP_MSG".to_string()
        }
        _ => format!("(opcode={opcode})"),
    }
}

/// Parse a Postgres server response buffer, which may contain several back-to-back
/// messages in the 256-byte capture window.  For result sets we decode:
///   T (RowDescription) → extract column names
///   D (DataRow)        → decode field values for the first row
///   C (CommandComplete) → return the completion tag (e.g. "SELECT 5")
///
/// This is best-effort: small result sets (≤256 bytes total) are fully decoded;
/// larger ones surface only what fits in the capture window.
fn parse_postgres_response(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    let mut col_names: Vec<String> = Vec::new();
    let mut row_values: Vec<String> = Vec::new();
    let mut completion_tag = String::new();
    let mut pos = 0usize;

    while pos < data.len() {
        let msg_type = data[pos];
        if pos + 5 > data.len() {
            break;
        }
        let msg_len = u32::from_be_bytes([
            data[pos+1], data[pos+2], data[pos+3], data[pos+4],
        ]) as usize;
        let body_start = pos + 5;
        let body_end = (pos + 1 + msg_len).min(data.len());
        let body = &data[body_start..body_end];
        pos = pos + 1 + msg_len;

        match msg_type {
            b'T' if body.len() >= 2 => {
                // RowDescription: u16be field_count, then for each field:
                //   name(cstring) + tableOID(4) + attrNum(2) + typeOID(4)
                //   + typeSize(2) + typeMod(4) + format(2)  = 18 bytes of fixed fields
                let field_count = u16::from_be_bytes([body[0], body[1]]) as usize;
                let mut i = 2usize;
                for _ in 0..field_count {
                    let name_end = body[i..]
                        .iter()
                        .position(|&b| b == 0)
                        .map(|p| i + p)
                        .unwrap_or(body.len());
                    col_names.push(String::from_utf8_lossy(&body[i..name_end]).to_string());
                    i = name_end + 1 + 18; // skip null + fixed fields
                    if i > body.len() {
                        break;
                    }
                }
            }
            b'D' if body.len() >= 2 && row_values.is_empty() => {
                // DataRow: u16be field_count, then for each field:
                //   i32be field_len (-1 = NULL) + field_data
                let field_count = u16::from_be_bytes([body[0], body[1]]) as usize;
                let mut i = 2usize;
                for _ in 0..field_count {
                    if i + 4 > body.len() {
                        break;
                    }
                    let flen = i32::from_be_bytes([body[i], body[i+1], body[i+2], body[i+3]]);
                    i += 4;
                    if flen < 0 {
                        row_values.push("NULL".to_string());
                    } else {
                        let end = (i + flen as usize).min(body.len());
                        row_values.push(String::from_utf8_lossy(&body[i..end]).to_string());
                        i += flen as usize;
                    }
                }
            }
            b'C' => {
                let end = body.iter().position(|&b| b == 0).unwrap_or(body.len());
                completion_tag = String::from_utf8_lossy(&body[..end]).trim().to_string();
            }
            b'E' => {
                let mut i = 0usize;
                while i < body.len() {
                    let code = body[i];
                    i += 1;
                    let end = body[i..].iter().position(|&b| b == 0).unwrap_or(body.len() - i);
                    if code == b'M' {
                        return format!("ERR: {}", String::from_utf8_lossy(&body[i..i+end]));
                    }
                    i += end + 1;
                }
                return "ERR".to_string();
            }
            _ => {}
        }
    }

    // Compose the result string from whatever we decoded.
    if !row_values.is_empty() {
        let header = if col_names.is_empty() {
            String::new()
        } else {
            format!("({}): ", col_names.join(", "))
        };
        let row = row_values.join(", ");
        if !completion_tag.is_empty() {
            format!("{header}{row} [{completion_tag}]")
        } else {
            format!("{header}{row}")
        }
    } else if !completion_tag.is_empty() {
        completion_tag
    } else {
        format!("(response 0x{:02x})", data[0])
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
