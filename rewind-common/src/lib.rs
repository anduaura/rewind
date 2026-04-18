#![no_std]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Direction {
    Inbound = 0,
    Outbound = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SyscallKind {
    ClockGettime = 0,
    Getrandom = 1,
}

/// Emitted by the tcp_sendmsg kprobe for each HTTP request/response observed.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct HttpEvent {
    pub timestamp_ns: u64,
    pub body_len: u32,
    pub pid: u32,
    pub status_code: u16, // 0 for requests
    pub direction: Direction,
    pub _pad: u8,
    pub method: [u8; 8],   // e.g. b"GET\0\0\0\0\0"
    pub path: [u8; 128],
}

/// Emitted by the sys_exit tracepoint for clock_gettime and getrandom.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct SyscallEvent {
    pub timestamp_ns: u64,
    pub return_value: u64,
    pub pid: u32,
    pub kind: SyscallKind,
    pub _pad: [u8; 3],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for HttpEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SyscallEvent {}
