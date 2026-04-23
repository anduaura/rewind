// CO-RE kernel struct definitions.
//
// These are the minimal kernel types needed by the rewind eBPF probes.
// Annotating them with `#[repr(C)]` and using `bpf_core_read!` instead of
// raw pointer arithmetic lets the BPF loader resolve field offsets at load
// time against the running kernel's BTF, making the probes portable across
// kernel versions (CO-RE: Compile Once, Run Everywhere).
//
// To regenerate from a running kernel:
//   bpftool btf dump file /sys/kernel/btf/vmlinux format c \
//     | aya-tool generate sock msghdr iov_iter iovec > src/vmlinux.rs
//
// The structs here cover Linux 5.14 – 6.8 layout on x86_64 and arm64.

#![allow(non_camel_case_types, non_snake_case, dead_code)]

use aya_ebpf::cty::{c_int, c_uint, c_ulong, c_ushort, c_void};

// ── sock / sock_common ────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sock_common {
    pub skc_daddr: u32,
    pub skc_rcv_saddr: u32,
    pub skc_hash: u32,
    pub skc_u16hashes: [u16; 2],
    /// Destination port in network byte order (big-endian).
    pub skc_dport: c_ushort,
    pub skc_num: u16,
    pub skc_family: c_ushort,
    // … remaining fields not needed
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sock {
    pub __sk_common: sock_common,
    // … remaining fields not needed
}

// ── iovec ─────────────────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Copy, Clone)]
pub struct iovec {
    pub iov_base: *mut c_void,
    pub iov_len: c_ulong,
}

// ── iov_iter ─────────────────────────────────────────────────────────────────
//
// The layout changed between kernel versions:
//   ≤ 5.13: iter_type (int) + iov_offset (size_t) + count (size_t) + iov (const iovec *)
//   5.14+:  iter_type (u8) + nofault (bool) + data_source (u8) + user_backed (bool)
//           + count (size_t) + UNION { iov / bvec / kvec / xarray }
//
// With CO-RE the BPF loader patches the field offset from the running kernel's
// BTF so we don't need to branch on kernel version here.

#[repr(C)]
#[derive(Copy, Clone)]
pub struct iov_iter {
    pub iter_type: c_uint,
    pub nofault: bool,
    pub data_source: u8,
    pub user_backed: bool,
    pub _pad: u8,
    pub count: c_ulong,
    /// Pointer to the first iovec element.
    pub iov: *const iovec,
}

// ── msghdr ────────────────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Copy, Clone)]
pub struct msghdr {
    pub msg_name: *mut c_void,
    pub msg_namelen: c_int,
    pub msg_iter: iov_iter,
    // … remaining fields not needed
}
