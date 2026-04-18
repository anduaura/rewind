use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::AsyncPerfEventArray,
    programs::{KProbe, TracePoint},
    util::online_cpus,
    Bpf, BpfLoader,
};
use aya_log::BpfLogger;
use bytes::BytesMut;
use std::sync::{Arc, Mutex};
use tokio::signal;

use crate::cli::{FlushArgs, RecordArgs};
use crate::store::snapshot::{Event, HttpRecord, Snapshot, SyscallRecord};
use rewind_common::{Direction, HttpEvent, SyscallEvent};

// Embedded eBPF object file — built separately with:
//   cd rewind-ebpf && cargo build --target bpfel-unknown-none --release
//
// Path is relative to this source file:
//   src/capture/agent.rs → ../../../rewind-ebpf/target/...
#[cfg(not(test))]
static REWIND_EBPF: &[u8] = include_bytes_aligned!(
    "../../../rewind-ebpf/target/bpfel-unknown-none/release/rewind-ebpf"
);

// Fallback for test builds where the eBPF binary may not exist yet.
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

    // Load and initialise the eBPF program.
    let mut bpf = BpfLoader::new()
        .load(REWIND_EBPF)
        .context("failed to load eBPF object — did you run `make build-ebpf`?")?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        eprintln!("warn: eBPF logger not available: {e}");
    }

    attach_probes(&mut bpf)?;

    let http_task = spawn_http_drain(&mut bpf, Arc::clone(&events))?;
    let syscall_task = spawn_syscall_drain(&mut bpf, Arc::clone(&events))?;

    println!("Recording… press Ctrl+C to flush and exit");
    signal::ctrl_c().await?;

    http_task.abort();
    syscall_task.abort();

    let mut snapshot = Snapshot::new(args.services.clone());
    {
        let mut guard = events.lock().unwrap();
        guard.sort_by_key(|e| match e {
            Event::Http(h) => h.timestamp_ns,
            Event::Syscall(s) => s.timestamp_ns,
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

fn spawn_http_drain(
    bpf: &mut Bpf,
    events: Arc<Mutex<Vec<Event>>>,
) -> Result<tokio::task::JoinHandle<()>> {
    let mut perf_array =
        AsyncPerfEventArray::try_from(bpf.take_map("HTTP_EVENTS").context("HTTP_EVENTS map not found")?)?;

    let handle = tokio::spawn(async move {
        let cpus = online_cpus().unwrap_or_else(|_| vec![0]);
        let mut tasks = Vec::new();

        for cpu_id in cpus {
            let Ok(mut buf) = perf_array.open(cpu_id, Some(32)) else {
                continue;
            };
            let events = Arc::clone(&events);

            tasks.push(tokio::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(1024))
                    .collect::<Vec<_>>();

                loop {
                    let Ok(info) = buf.read_events(&mut buffers).await else {
                        break;
                    };
                    for buf in buffers.iter().take(info.read) {
                        let Ok(event) = parse_http_event(buf) else {
                            continue;
                        };
                        events.lock().unwrap().push(Event::Http(event));
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

fn spawn_syscall_drain(
    bpf: &mut Bpf,
    events: Arc<Mutex<Vec<Event>>>,
) -> Result<tokio::task::JoinHandle<()>> {
    let mut perf_array = AsyncPerfEventArray::try_from(
        bpf.take_map("SYSCALL_EVENTS").context("SYSCALL_EVENTS map not found")?,
    )?;

    let handle = tokio::spawn(async move {
        let cpus = online_cpus().unwrap_or_else(|_| vec![0]);
        let mut tasks = Vec::new();

        for cpu_id in cpus {
            let Ok(mut buf) = perf_array.open(cpu_id, Some(32)) else {
                continue;
            };
            let events = Arc::clone(&events);

            tasks.push(tokio::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(256))
                    .collect::<Vec<_>>();

                loop {
                    let Ok(info) = buf.read_events(&mut buffers).await else {
                        break;
                    };
                    for buf in buffers.iter().take(info.read) {
                        let Ok(event) = parse_syscall_event(buf) else {
                            continue;
                        };
                        events.lock().unwrap().push(Event::Syscall(event));
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

fn parse_http_event(buf: &BytesMut) -> Result<HttpRecord> {
    if buf.len() < std::mem::size_of::<HttpEvent>() {
        anyhow::bail!("buffer too small for HttpEvent");
    }
    let raw: HttpEvent =
        unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const HttpEvent) };

    let method = cstr_to_string(&raw.method);
    let path = cstr_to_string(&raw.path);
    let direction = match raw.direction {
        Direction::Inbound => "inbound",
        Direction::Outbound => "outbound",
    }
    .to_string();
    let status_code = if raw.status_code == 0 {
        None
    } else {
        Some(raw.status_code)
    };

    Ok(HttpRecord {
        timestamp_ns: raw.timestamp_ns,
        direction,
        method,
        path,
        status_code,
        service: String::new(), // populated by correlation pass (future)
        trace_id: None,
        body: None,
    })
}

fn parse_syscall_event(buf: &BytesMut) -> Result<SyscallRecord> {
    if buf.len() < std::mem::size_of::<SyscallEvent>() {
        anyhow::bail!("buffer too small for SyscallEvent");
    }
    let raw: SyscallEvent =
        unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const SyscallEvent) };

    let kind = match raw.kind {
        rewind_common::SyscallKind::ClockGettime => "clock_gettime",
        rewind_common::SyscallKind::Getrandom => "getrandom",
    }
    .to_string();

    Ok(SyscallRecord {
        timestamp_ns: raw.timestamp_ns,
        kind,
        return_value: raw.return_value,
        pid: raw.pid,
    })
}

fn cstr_to_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

pub async fn flush(args: FlushArgs) -> Result<()> {
    println!("rewind flush");
    println!("  window: {}", args.window);
    println!("  output: {}", args.output.display());
    // TODO: IPC to signal a running `rewind record` process to dump its ring buffer.
    println!("flush not yet implemented — start `rewind record` first");
    Ok(())
}
