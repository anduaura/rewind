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
    pub method: [u8; 8],      // e.g. b"GET\0\0\0\0\0"
    pub path: [u8; 128],
    pub headers_raw: [u8; 128], // bytes immediately after the request line (\r\n)
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DbProtocol {
    Postgres = 0,
    Redis    = 1,
    MySQL    = 2,
    MongoDB  = 3,
    Kafka    = 4,
}

/// Emitted by the tcp_sendmsg / tcp_recvmsg probes for Postgres/Redis traffic.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct DbEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub dport: u16,          // 5432 = Postgres, 6379 = Redis
    pub protocol: DbProtocol,
    pub is_response: u8,     // 0 = query sent by service, 1 = response from DB
    pub payload_len: u32,    // bytes actually captured (≤ 256)
    pub payload: [u8; 256],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DbEvent {}

/// Emitted by the tcp_sendmsg kprobe for gRPC (HTTP/2) calls.
/// The path is the gRPC method path, e.g. `/helloworld.Greeter/SayHello`.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct GrpcEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub _pad: u32,
    pub path: [u8; 128],   // gRPC method path from :path pseudo-header
    pub raw_frame: [u8; 128], // first 128 bytes of the HEADERS frame payload
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for GrpcEvent {}
