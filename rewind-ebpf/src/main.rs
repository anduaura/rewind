#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_user_buf},
    macros::{kprobe, map, tracepoint},
    maps::PerfEventArray,
    programs::{ProbeContext, TracePointContext},
};
use rewind_common::{Direction, HttpEvent, SyscallEvent, SyscallKind};

#[map(name = "HTTP_EVENTS")]
static mut HTTP_EVENTS: PerfEventArray<HttpEvent> = PerfEventArray::new(0);

#[map(name = "SYSCALL_EVENTS")]
static mut SYSCALL_EVENTS: PerfEventArray<SyscallEvent> = PerfEventArray::new(0);

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
    let msg: u64 = unsafe { ctx.arg(1).ok_or(1i64)? };
    if msg == 0 {
        return Ok(());
    }

    // Navigate to the first iovec's data pointer.
    //
    // Layout (x86_64, Linux 5.14+):
    //   msghdr.msg_iter            @ msghdr + 16  (embedded struct, not a ptr)
    //   iov_iter.iov               @ iov_iter + 24 → msghdr + 40
    //   iovec[0].iov_base          @ iov + 0      (user-space data ptr)
    //
    // For kernels < 5.14 (no user_backed field), iov sits at iov_iter + 16
    // (msg + 32). Adjust IOV_ITER_IOV_OFFSET below if needed.
    const MSG_ITER_OFFSET: u64 = 16;
    const IOV_ITER_IOV_OFFSET: u64 = 24; // kernel 5.14+; use 16 on older kernels

    let iov: u64 = unsafe {
        bpf_probe_read_kernel((msg + MSG_ITER_OFFSET + IOV_ITER_IOV_OFFSET) as *const u64)
            .map_err(|e| e as i64)?
    };
    if iov == 0 {
        return Ok(());
    }

    // iov[0].iov_base is the first field of struct iovec (offset 0).
    let iov_base: u64 = unsafe {
        bpf_probe_read_kernel(iov as *const u64).map_err(|e| e as i64)?
    };
    if iov_base == 0 {
        return Ok(());
    }

    // Read the first 256 bytes of the message from user space.
    let mut data = [0u8; 256];
    unsafe {
        bpf_probe_read_user_buf(iov_base as *const u8, &mut data).map_err(|e| e as i64)?;
    }

    // Only proceed if this looks like HTTP traffic.
    // Responses start with "HTTP/"; requests start with a method verb.
    let is_response = data.starts_with(b"HTTP/");
    let is_request = data.starts_with(b"GET ")
        || data.starts_with(b"POST ")
        || data.starts_with(b"PUT ")
        || data.starts_with(b"DELETE ")
        || data.starts_with(b"PATCH ")
        || data.starts_with(b"HEAD ")
        || data.starts_with(b"OPTIONS ");

    if !is_request && !is_response {
        return Ok(());
    }

    let mut event = HttpEvent {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        body_len: 0,
        pid: (unsafe { bpf_get_current_pid_tgid() } >> 32) as u32,
        status_code: 0,
        direction: if is_request {
            Direction::Outbound
        } else {
            Direction::Inbound
        },
        _pad: 0,
        method: [0u8; 8],
        path: [0u8; 128],
    };

    if is_request {
        // Extract method: bytes before the first space, up to 8 chars.
        let mut i = 0usize;
        while i < 8 && data[i] != b' ' {
            event.method[i] = data[i];
            i += 1;
        }

        // Extract path: token between the first and second space.
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
    } else {
        // Response: parse status code from "HTTP/1.x NNN"
        //   0123456789...
        //   HTTP/1.1 200 OK\r\n
        //            ^ offset 9
        if data.len() >= 12 {
            let s = (data[9] as u16 - b'0' as u16) * 100
                + (data[10] as u16 - b'0' as u16) * 10
                + (data[11] as u16 - b'0' as u16);
            event.status_code = s;
        }
        event.method.copy_from_slice(b"HTTP    ");
    }

    unsafe {
        HTTP_EVENTS.output(&ctx, &event, 0);
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
    // sys_exit tracepoint format (x86_64):
    //   offset 0..8   common fields (type, flags, pid)
    //   offset 8      long id   — syscall number
    //   offset 16     long ret  — return value
    let id: i64 = unsafe { ctx.read_at::<i64>(8).map_err(|e| e as i64)? };
    let ret: i64 = unsafe { ctx.read_at::<i64>(16).map_err(|e| e as i64)? };

    // Only capture non-deterministic syscalls we care about.
    // x86_64 syscall numbers:
    //   228 = clock_gettime
    //   318 = getrandom
    let kind = match id {
        228 => SyscallKind::ClockGettime,
        318 => SyscallKind::Getrandom,
        _ => return Ok(()),
    };

    // For clock_gettime the timespec is written to a user-space pointer (arg 1),
    // not returned directly. Capturing bpf_ktime_get_ns() here gives a close
    // approximation for MVP; the exact value needs a paired sys_enter probe
    // that saves the tp pointer per-PID so we can read it here.
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

    unsafe {
        SYSCALL_EVENTS.output(&ctx, &event, 0);
    }

    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
