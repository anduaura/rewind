#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{kprobe, tracepoint},
    maps::PerfEventArray,
    programs::{ProbeContext, TracePointContext},
};
use rewind_common::{Direction, HttpEvent, SyscallEvent, SyscallKind};

#[map(name = "HTTP_EVENTS")]
static mut HTTP_EVENTS: PerfEventArray<HttpEvent> = PerfEventArray::new(0);

#[map(name = "SYSCALL_EVENTS")]
static mut SYSCALL_EVENTS: PerfEventArray<SyscallEvent> = PerfEventArray::new(0);

#[kprobe(name = "tcp_sendmsg")]
pub fn tcp_sendmsg(ctx: ProbeContext) -> u32 {
    match try_capture_send(ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

fn try_capture_send(ctx: ProbeContext) -> Result<(), i64> {
    // TODO: implement HTTP capture from tcp_sendmsg
    //
    // 1. Get sock* from ctx.arg(0) and msghdr* from ctx.arg(1)
    // 2. Read iov_base from msghdr->msg_iter->iov to get the data bytes
    // 3. Parse the first ~256 bytes for HTTP method and path:
    //    - Look for "GET /", "POST /", etc.
    //    - Extract method (up to first space) and path (up to next space or \r\n)
    // 4. Determine direction: inbound if the sock's local port matches a known
    //    service port; outbound otherwise
    // 5. Populate HttpEvent and submit:
    //    HTTP_EVENTS.output(&ctx, &event, 0);
    //
    // Note: bpf_probe_read_user / bpf_probe_read_kernel for pointer dereferences.
    // Path parsing must stay under the BPF stack limit (512 bytes).

    Ok(())
}

#[tracepoint(name = "sys_exit")]
pub fn sys_exit(ctx: TracePointContext) -> u32 {
    match try_capture_syscall(ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

fn try_capture_syscall(ctx: TracePointContext) -> Result<(), i64> {
    // TODO: implement syscall interception
    //
    // Tracepoint format for sys_exit:
    //   __syscall_nr: i64  (offset 8)
    //   ret:          i64  (offset 16)
    //
    // 1. Read syscall_nr from ctx.read_at::<i64>(8)?
    // 2. Filter: only clock_gettime (228) and getrandom (318)
    // 3. Read ret from ctx.read_at::<i64>(16)?
    // 4. Emit SyscallEvent with appropriate SyscallKind and return value:
    //    SYSCALL_EVENTS.output(&ctx, &event, 0);

    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
