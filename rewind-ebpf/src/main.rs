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

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel,
        bpf_probe_read_user_buf,
    },
    macros::{kprobe, kretprobe, map, tracepoint},
    maps::{HashMap, PerfEventArray},
    programs::{ProbeContext, TracePointContext},
};
use rewind_common::{DbEvent, DbProtocol, Direction, HttpEvent, SyscallEvent, SyscallKind};

#[map(name = "HTTP_EVENTS")]
static mut HTTP_EVENTS: PerfEventArray<HttpEvent> = PerfEventArray::new(0);

#[map(name = "SYSCALL_EVENTS")]
static mut SYSCALL_EVENTS: PerfEventArray<SyscallEvent> = PerfEventArray::new(0);

#[map(name = "DB_EVENTS")]
static mut DB_EVENTS: PerfEventArray<DbEvent> = PerfEventArray::new(0);

/// port → DbProtocol discriminant. Userspace seeds: 5432→0, 6379→1.
#[map(name = "WATCHED_PORTS")]
static WATCHED_PORTS: HashMap<u32, u8> = HashMap::with_max_entries(16, 0);

/// tid → msghdr pointer saved at tcp_recvmsg entry, read at return.
#[map(name = "RECV_ARGS")]
static mut RECV_ARGS: HashMap<u64, u64> = HashMap::with_max_entries(4096, 0);

// ─── tcp_sendmsg kprobe ───────────────────────────────────────────────────────

#[kprobe(name = "tcp_sendmsg")]
pub fn tcp_sendmsg(ctx: ProbeContext) -> u32 {
    match try_capture_send(ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

fn try_capture_send(ctx: ProbeContext) -> Result<(), i64> {
    // tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
    let sk: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let msg: u64 = unsafe { ctx.arg(1).ok_or(1i64)? };
    if msg == 0 {
        return Ok(());
    }

    // Navigate msghdr → iov_iter → iovec[0].iov_base.
    // Layout (x86_64, Linux 5.14+):
    //   msghdr.msg_iter @ +16, iov_iter.iov @ iov_iter+24 → msghdr+40
    //   iovec[0].iov_base @ iov+0, iovec[0].iov_len @ iov+8
    let iov: u64 = unsafe {
        bpf_probe_read_kernel((msg + 40) as *const u64).map_err(|e| e as i64)?
    };
    if iov == 0 {
        return Ok(());
    }
    let iov_base: u64 = unsafe {
        bpf_probe_read_kernel(iov as *const u64).map_err(|e| e as i64)?
    };
    let iov_len: u64 = unsafe {
        bpf_probe_read_kernel((iov + 8) as *const u64).map_err(|e| e as i64)?
    };
    if iov_base == 0 || iov_len == 0 {
        return Ok(());
    }

    let mut data = [0u8; 256];
    unsafe {
        bpf_probe_read_user_buf(iov_base as *const u8, &mut data).map_err(|e| e as i64)?;
    }
    let captured_len = (iov_len as usize).min(256) as u32;

    // ── HTTP ─────────────────────────────────────────────────────────────────
    let is_response = data.starts_with(b"HTTP/");
    let is_request = data.starts_with(b"GET ")
        || data.starts_with(b"POST ")
        || data.starts_with(b"PUT ")
        || data.starts_with(b"DELETE ")
        || data.starts_with(b"PATCH ")
        || data.starts_with(b"HEAD ")
        || data.starts_with(b"OPTIONS ");

    if is_request || is_response {
        emit_http_event(&ctx, &data, is_response);
        return Ok(());
    }

    // ── DB protocols ─────────────────────────────────────────────────────────
    // Read destination port from sock->sk_common.skc_dport (big-endian, offset 12).
    if sk != 0 {
        let dport_be: u16 = unsafe {
            bpf_probe_read_kernel((sk + 12) as *const u16).map_err(|e| e as i64)?
        };
        let dport = u16::from_be(dport_be);

        if let Some(&proto_id) = unsafe { WATCHED_PORTS.get(&(dport as u32)) } {
            emit_db_event(&ctx, &data, captured_len, dport, proto_id, 0 /* query */);
        }
    }

    Ok(())
}

fn emit_http_event(ctx: &ProbeContext, data: &[u8; 256], is_response: bool) {
    let mut event = HttpEvent {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        body_len: 0,
        pid: (unsafe { bpf_get_current_pid_tgid() } >> 32) as u32,
        status_code: 0,
        direction: if is_response { Direction::Inbound } else { Direction::Outbound },
        _pad: 0,
        method: [0u8; 8],
        path: [0u8; 128],
        headers_raw: [0u8; 128],
    };

    if !is_response {
        // Extract method.
        let mut i = 0usize;
        while i < 8 && data[i] != b' ' {
            event.method[i] = data[i];
            i += 1;
        }

        // Extract path.
        let path_start = i + 1;
        let mut j = 0usize;
        while j < 128 {
            let c = data[path_start + j];
            if c == b' ' || c == b'\r' || c == b'\n' || c == 0 {
                break;
            }
            event.path[j] = c;
            j += 1;
        }

        // Find end of request line and capture first 128 bytes of headers.
        // Scan for \r\n (end of "METHOD /path HTTP/1.x\r\n").
        let mut line_end = 0usize;
        while line_end < 200 {
            if data[line_end] == b'\r' && data[line_end + 1] == b'\n' {
                line_end += 2;
                break;
            }
            line_end += 1;
        }
        if line_end < 256 {
            let copy_len = (256 - line_end).min(128);
            let mut k = 0usize;
            while k < copy_len {
                event.headers_raw[k] = data[line_end + k];
                k += 1;
            }
        }
    } else {
        if data.len() >= 12 {
            let s = (data[9] as u16 - b'0' as u16) * 100
                + (data[10] as u16 - b'0' as u16) * 10
                + (data[11] as u16 - b'0' as u16);
            event.status_code = s;
        }
        event.method.copy_from_slice(b"HTTP    ");
    }

    unsafe { HTTP_EVENTS.output(ctx, &event, 0) };
}

fn emit_db_event(
    ctx: &ProbeContext,
    data: &[u8; 256],
    captured_len: u32,
    dport: u16,
    proto_id: u8,
    is_response: u8,
) {
    let mut event = DbEvent {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        pid: (unsafe { bpf_get_current_pid_tgid() } >> 32) as u32,
        dport,
        protocol: if proto_id == 0 { DbProtocol::Postgres } else { DbProtocol::Redis },
        is_response,
        payload_len: captured_len,
        payload: [0u8; 256],
    };
    event.payload.copy_from_slice(data);
    unsafe { DB_EVENTS.output(ctx, &event, 0) };
}

// ─── tcp_recvmsg kprobe + kretprobe (DB response capture) ────────────────────
//
// Pattern: save msghdr pointer at entry; read the filled buffer at return.

#[kprobe(name = "tcp_recvmsg_enter")]
pub fn tcp_recvmsg_enter(ctx: ProbeContext) -> u32 {
    // tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags, ...)
    let msg: u64 = match unsafe { ctx.arg::<u64>(1) } {
        Some(v) => v,
        None => return 0,
    };
    let tid = unsafe { bpf_get_current_pid_tgid() };
    unsafe { let _ = RECV_ARGS.insert(&tid, &msg, 0); }
    0
}

#[kretprobe(name = "tcp_recvmsg_ret")]
pub fn tcp_recvmsg_ret(ctx: ProbeContext) -> u32 {
    match try_capture_recv(ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

fn try_capture_recv(ctx: ProbeContext) -> Result<(), i64> {
    let tid = unsafe { bpf_get_current_pid_tgid() };

    let msg = match unsafe { RECV_ARGS.get(&tid) } {
        Some(&v) => v,
        None => return Ok(()),
    };
    unsafe { RECV_ARGS.remove(&tid).map_err(|e| e as i64)?; }

    if msg == 0 {
        return Ok(());
    }

    // Read the iov from the (now-filled) msghdr.
    let iov: u64 = unsafe {
        bpf_probe_read_kernel((msg + 40) as *const u64).map_err(|e| e as i64)?
    };
    if iov == 0 {
        return Ok(());
    }
    let iov_base: u64 = unsafe {
        bpf_probe_read_kernel(iov as *const u64).map_err(|e| e as i64)?
    };
    let iov_len: u64 = unsafe {
        bpf_probe_read_kernel((iov + 8) as *const u64).map_err(|e| e as i64)?
    };
    if iov_base == 0 || iov_len == 0 {
        return Ok(());
    }

    let mut data = [0u8; 256];
    unsafe {
        bpf_probe_read_user_buf(iov_base as *const u8, &mut data).map_err(|e| e as i64)?;
    }
    let captured_len = (iov_len as usize).min(256) as u32;

    // Detect protocol from payload heuristics (no sock pointer available here).
    // Postgres: message-type byte + 4-byte length (T/D/C/Z/E/1/2/n/I).
    // Redis:    RESP first byte (+/-/:/$/∗).
    // MySQL:    4-byte packet header (3-byte len LE + seq byte); seq==1 for the
    //           server's first response, followed by 0x00=OK/0xFF=ERR/0xFE=EOF.
    let (proto_id, looks_like_db) = match data[0] {
        b'T' | b'D' | b'C' | b'Z' | b'E' | b'1' | b'2' | b'n' | b'I' => (0u8, true),
        b'+' | b'-' | b':' | b'$' | b'*' => (1u8, true),
        _ => {
            if data[3] == 1 && (data[4] == 0x00 || data[4] == 0xff || data[4] == 0xfe) {
                (2u8, true) // MySQL
            } else {
                (0u8, false)
            }
        }
    };

    if looks_like_db {
        let dport: u16 = match proto_id {
            1 => 6379,
            2 => 3306,
            _ => 5432,
        };
        emit_db_event(&ctx, &data, captured_len, dport, proto_id, 1 /* response */);
    }

    Ok(())
}

// ─── sys_exit tracepoint ──────────────────────────────────────────────────────

#[tracepoint(name = "sys_exit")]
pub fn sys_exit(ctx: TracePointContext) -> u32 {
    match try_capture_syscall(ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

fn try_capture_syscall(ctx: TracePointContext) -> Result<(), i64> {
    let id: i64 = unsafe { ctx.read_at::<i64>(8).map_err(|e| e as i64)? };
    let ret: i64 = unsafe { ctx.read_at::<i64>(16).map_err(|e| e as i64)? };

    let kind = match id {
        228 => SyscallKind::ClockGettime,
        318 => SyscallKind::Getrandom,
        _ => return Ok(()),
    };

    let return_value = match kind {
        SyscallKind::ClockGettime => unsafe { bpf_ktime_get_ns() },
        SyscallKind::Getrandom => ret as u64,
    };

    let event = SyscallEvent {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        return_value,
        pid: (unsafe { bpf_get_current_pid_tgid() } >> 32) as u32,
        kind,
        _pad: [0u8; 3],
    };

    unsafe { SYSCALL_EVENTS.output(&ctx, &event, 0) };
    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
