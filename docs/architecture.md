# Architecture

This document explains how rewind works internally — how it captures production traffic, what gets stored in a snapshot, and how replay achieves determinism.

## Overview

rewind has two phases: **record** and **replay**.

```
Production node                         Developer machine
─────────────────────────────────────   ────────────────────────────────
Container A   Container B               Docker Compose
  │             │                         Service A  Service B
  │ tcp_sendmsg │                           │           │
  └──────┬──────┘                           │           │
         │                                  │    mock   │
    eBPF probe ──── ring buffer            ─┤  network  ├─
         │             (memory)            ─┘   server  └─
         │                                  │
    rewind flush                       rewind replay
         │                                  │
         ▼                                  │
    incident.rwd ─────────────────────────►─┘
       (.rwd file)
```

## Capture

### eBPF probes

The agent loads two eBPF programs into the Linux kernel:

**`tcp_sendmsg` kprobe** — fires every time a process calls `write()` / `send()` on a TCP socket. The probe:

1. Reads the first 256 bytes from the `msghdr` `iov_iter` via `bpf_probe_read_user_buf`.
2. Detects the protocol from the first bytes:
   - HTTP: `GET `, `POST `, `PUT `, `DELETE `, `PATCH `, `HEAD `, `OPTIONS `, `HTTP/`
   - gRPC (HTTP/2): `PRI * HTTP/2` client preface, or bare HEADERS frames (type `0x01`)
   - DB: destination port in `sock.__sk_common.skc_dport` matched against `WATCHED_PORTS` map
3. For HTTP events: extracts method, path, status code, and first 128 bytes of headers. Does a second `bpf_probe_read_user_buf` at the body start offset for up to 512 body bytes.
4. For DB events: emits the raw payload for userspace to parse (Postgres, Redis, MySQL, MongoDB, Kafka wire protocols).
5. Puts the event onto a `PerfEventArray` (one per event type) for userspace to drain.

**`tcp_recvmsg` kprobe + kretprobe** — saves the `msghdr` pointer at `tcp_recvmsg` entry (kprobe), then reads the filled buffer at return (kretprobe). Used to capture DB responses: the probe heuristically identifies the DB protocol from the response payload and correlates it with the pending query.

**`sys_exit` tracepoint** — fires on every syscall exit. Captures `clock_gettime` (syscall 228) and `getrandom` (syscall 318) return values so the replay engine can override non-deterministic sources.

### CO-RE struct access

All kernel struct field reads use `addr_of!((*ptr).field)` with types defined in `rewind-ebpf/src/vmlinux.rs`. The BPF loader resolves field offsets against the running kernel's BTF at load time — the same binary works on Linux 5.10 through 6.x on x86_64 and arm64 without recompilation.

Previously, reads used hardcoded byte offsets (e.g. `(sk + 12) as *const u16` for `skc_dport`). These break silently on kernels with different struct layouts. CO-RE eliminates this class of bug.

### Ring buffer

The agent maintains an in-memory ring buffer (`src/capture/ring.rs`):
- Bounded at 200,000 events (~5 minutes at 1,000 req/s)
- Lock-protected `VecDeque<Event>` with a monotonic timestamp per entry
- When full, oldest events are discarded (flight recorder pattern)
- `drain_window(Duration)` returns all events within the requested time window

Nothing is written to disk until `rewind flush` is called. At 1,000 req/s, headers-only capture produces ~50–100 MB in memory; a triggered 5-minute flush compresses to ~5–10 MB on disk.

### Service attribution

The agent maps each PID to a service name using a three-layer strategy:

1. **Docker / crictl at startup** — `docker inspect` each named service, or `crictl ps --output json` for Kubernetes, to build a container-ID → service-name map.
2. **cgroup parsing at lookup time** — reads `/proc/<pid>/cgroup` and extracts the 12-hex-char container ID from Docker, containerd (`cri-containerd-`), or CRI-O (`crio-`) cgroup paths.
3. **`/proc/<pid>/environ` fallback** — reads `HOSTNAME` (which Kubernetes sets to the pod name) and strips ReplicaSet hash suffixes (`api-7d9f8b64c-xk2p9` → `api`).

Results are cached per-PID so each process incurs at most one `/proc` read.

### Snapshot format

A `.rwd` file is a JSON object (optionally encrypted with AES-256-GCM via the `age` library):

```json
{
  "version": 1,
  "recorded_at_ns": 1745489581000000000,
  "services": ["api", "worker"],
  "events": [
    {
      "Http": {
        "timestamp_ns": 1745489581001000000,
        "direction": "inbound",
        "method": "POST",
        "path": "/orders",
        "status_code": 201,
        "service": "api",
        "trace_id": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        "headers": [["content-type", "application/json"]],
        "body": "{\"user_id\": 1, \"item\": \"widget\"}"
      }
    },
    {
      "Db": {
        "timestamp_ns": 1745489581005000000,
        "protocol": "postgres",
        "query": "INSERT INTO orders (user_id, item) VALUES ($1, $2)",
        "response": "INSERT 0 1",
        "service": "api",
        "pid": 12345
      }
    },
    {
      "Syscall": {
        "timestamp_ns": 1745489581002000000,
        "kind": "clock_gettime",
        "return_value": 1745489581002000000,
        "pid": 12345
      }
    }
  ]
}
```

Events are sorted by timestamp. The `trace_id` field links events across services that used W3C `traceparent` headers.

## Replay

### Determinism sources

There are three sources of non-determinism in a distributed system that rewind controls:

| Source | How rewind controls it |
|---|---|
| Wall clock | `libfaketime` via `LD_PRELOAD` sets a fixed time in every container |
| Outbound network | A mock HTTP server intercepts all outbound calls and returns recorded responses |
| Random values | `clock_gettime` and `getrandom` return values are captured; currently not replayed (future work) |

### Clock override

rewind detects `libfaketime` on the host (checking standard installation paths) and volume-mounts it read-only into each container at `/run/rewind/libfaketime.so.1`. A docker-compose override file sets:

```yaml
environment:
  FAKETIME: "@2026-04-24 10:23:01"
  LD_PRELOAD: /run/rewind/libfaketime.so.1
volumes:
  - /usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1:/run/rewind/libfaketime.so.1:ro
```

No container image changes are required. If libfaketime is absent from the host, replay continues with a warning and the real wall clock.

### Mock network server

`src/replay/network.rs` is an axum-based HTTP server that:
1. Loads all outbound HTTP responses from the snapshot at startup.
2. For each incoming request, finds the matching recorded response by `method + path`. When the same endpoint was called multiple times, responses are consumed in order (FIFO).
3. Returns the recorded status code, headers (including `content-type`), and body.
4. Returns 502 with a diagnostic message if no matching response is found.

All containers route outbound HTTP through this server via `HTTP_PROXY` / `HTTPS_PROXY` environment variables in the compose override.

### Replay diff

After re-executing the triggering request, `src/replay/diff.rs` compares:
- HTTP status codes
- HTTP response bodies (recursive JSON field comparison with dot-path notation)

The diff output identifies exactly which fields diverged:

```
data.order_id  recorded="ord-42"  actual=(missing)
items[1].price recorded=9.99      actual=10.49
```

Exit code 0 on match, 1 on divergence — making replay a drop-in regression test in CI.

## Crate structure

```
rewind-common/          Shared no_std types
  src/lib.rs            HttpEvent, DbEvent, SyscallEvent, GrpcEvent
                        aya::Pod impls gated behind `user` feature

rewind-ebpf/            Kernel-space eBPF probes
  src/main.rs           tcp_sendmsg kprobe, tcp_recvmsg kprobe+kretprobe,
                        sys_exit tracepoint
  src/vmlinux.rs        CO-RE kernel struct definitions (sock, msghdr, iov_iter, …)

rewind/                 Userspace CLI
  src/
    main.rs             tokio entry point, subcommand routing
    cli.rs              clap arg structs
    capture/
      agent.rs          eBPF loader, perf array drain, ring buffer, Unix socket IPC
      ring.rs           RingBuffer (VecDeque + Instant, bounded)
      service_map.rs    PID → service name (Docker + Kubernetes)
    replay/
      engine.rs         Compose up, clock override, trigger re-execution, diff
      network.rs        axum mock server
      diff.rs           JSON field-by-field comparison
    store/
      snapshot.rs       .rwd read/write, Event types
    export.rs           OTLP + Jaeger JSON export
    diff.rs             Snapshot-to-snapshot comparison (rewind diff)
    report.rs           Markdown + HTML incident report
    timeline.rs         Mermaid + ASCII sequence diagram
    notify.rs           Slack + webhook notification
    search.rs           Snapshot directory search with filters
    metrics.rs          Prometheus /metrics + /healthz on :9090
    audit.rs            Structured JSON audit log
    scrub.rs            PII redaction
    crypto.rs           age encryption/decryption + secret management
    server.rs           Collection server (axum)
    compliance.rs       SOC 2 / GDPR evidence report
```

## Data flow

```
                   ┌─────────────────────────────────────────────────────┐
                   │                     Kernel                           │
                   │                                                       │
                   │  tcp_sendmsg ──► HTTP/DB detection ──► PerfEventArray│
                   │  tcp_recvmsg ──► DB response capture ──► PerfEventArray│
                   │  sys_exit    ──► clock_gettime/getrandom ──► PerfEventArray│
                   └────────────────────────┬────────────────────────────┘
                                            │ drain per CPU
                   ┌────────────────────────▼────────────────────────────┐
                   │                   Userspace (agent)                  │
                   │                                                       │
                   │  HTTP parser ──► HttpRecord ──┐                      │
                   │  DB correlator ──► DbRecord ──┤──► RingBuffer        │
                   │  Syscall parser ──► SyscallRecord ─┘  (200k events)  │
                   │  gRPC parser ──► GrpcRecord ──┘                      │
                   │                              │                        │
                   │          rewind flush ◄──────┘                       │
                   │                    │                                  │
                   └────────────────────┼─────────────────────────────────┘
                                        │
                                   incident.rwd
                                        │
                   ┌────────────────────▼─────────────────────────────────┐
                   │                  Replay engine                         │
                   │                                                         │
                   │  MockServer ◄── outbound responses                     │
                   │  docker compose up + clock override                    │
                   │  wait for /health                                       │
                   │  re-fire trigger ──► compare response ──► diff/exit   │
                   └────────────────────────────────────────────────────────┘
```

## What rewind cannot capture

- **Thread scheduling non-determinism** — Heisenbugs that depend on goroutine/thread interleaving are not reproducible with this approach.
- **In-process state** — Variables in memory that were set before the capture window are not captured. Replay starts with whatever state the Docker container initialises to.
- **Encrypted traffic terminating inside the container** — TLS is terminated by the application, so rewind sees plaintext on the socket. Traffic to external services using mTLS works only if the mock server can impersonate the TLS endpoint (not currently supported — use `--no-diff` and inspect manually).
- **Non-HTTP/TCP protocols** — UDP, Unix domain sockets, and shared memory are not captured.
