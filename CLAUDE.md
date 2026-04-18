# rewind

Deterministic replay of distributed system incidents. Record inter-service traffic and non-deterministic syscalls in production using eBPF, then replay the exact incident locally for debugging.

## What this is

Engineers debugging production incidents in microservices can't reproduce them locally — they have logs and traces but can't *re-execute* what happened. rewind solves this with a two-phase approach:

**Record:** An eBPF agent attaches to running containers (no code changes required) and captures:
- All inter-service HTTP/gRPC traffic (requests + responses + timestamps)
- Outbound DB calls (Postgres wire protocol, Redis RESP)
- Non-deterministic syscalls: `clock_gettime`, `getrandom`

**Replay:** Given the snapshot, the replay engine:
1. Overrides the system clock to match recording start time
2. Overrides random sources to return recorded values
3. Intercepts outbound network calls, returning recorded responses
4. Re-executes the triggering request — deterministically

The output is a `.rwd` snapshot file (JSON) containing the full causal chain of an incident.

## Why Rust

Chosen over Go specifically for `aya` — the Rust eBPF framework that lets you write eBPF programs in Rust instead of C. This means:
- Shared types between kernel-space probes and userspace handler (no C/Rust boundary)
- Single language across the entire codebase
- No struct layout mismatches between kernel and userspace

Go's `cilium/ebpf` is more mature but requires eBPF probes in C, creating a two-language codebase.

## Crate structure

Three crates in the repo:

- **rewind-common** — shared `no_std` types (`HttpEvent`, `SyscallEvent`, `Direction`, `SyscallKind`). Compiles for both kernel and userspace. `aya::Pod` impls gated behind the `user` feature flag.
- **rewind-ebpf** — kernel-space probes. Targets `bpfel-unknown-none`, excluded from the workspace, must be built separately with `cargo build --target bpfel-unknown-none`. Contains a `kprobe` on `tcp_sendmsg` and a `tracepoint` on `sys_exit`.
- **rewind** — userspace CLI. Uses tokio, clap, serde. Source layout:
  - `src/main.rs` — tokio entrypoint, routes subcommands
  - `src/cli.rs` — record / flush / replay / inspect via clap
  - `src/store/snapshot.rs` — Snapshot + Event types, `.rwd` file read/write
  - `src/capture/agent.rs` — eBPF loader + ring buffer drain (stubbed, needs impl)
  - `src/replay/engine.rs` — replay orchestration (stubbed, needs impl)
  - `src/replay/network.rs` — MockServer, intercepts outbound calls during replay (stubbed)

## Key design decisions

**Flight recorder pattern** — the agent runs always-on with a bounded in-memory ring buffer (e.g. last 5 minutes). It only writes to disk when triggered (`rewind flush`). Continuous write-to-disk at 1000 req/s would be GBs; a triggered 5-minute window compresses to ~5-10MB.

**Headers-only by default** — request/response bodies are captured only with `--capture-bodies`. Bodies are the main driver of snapshot size.

**DB query mocking over full snapshots** — eBPF already sees Postgres/Redis wire protocol traffic. Capturing DB query responses alongside HTTP traffic gives ~75% incident coverage without needing full DB snapshots. Full DB snapshots are an opt-in future feature.

**Replay is always local** — regardless of how many hosts were involved in capture, replay always runs on the developer's machine against Docker Compose. The complexity is in capture/correlation, not replay.

**Trace context for multi-service correlation** — eBPF extracts `traceparent`/`X-Request-ID` headers to stitch events across multiple agents into one coherent timeline. In Kubernetes, one agent runs per node as a DaemonSet.

## What's implemented vs stubbed

| Module | Status | Notes |
|---|---|---|
| `rewind-common` | Done | HttpEvent, SyscallEvent types with aya::Pod |
| `rewind-ebpf` | Done | tcp_sendmsg kprobe parses HTTP method/path/status; sys_exit captures clock_gettime + getrandom |
| `src/store/snapshot.rs` | Done | Full .rwd read/write, Event display |
| `src/cli.rs` | Done | All four subcommands wired |
| `src/capture/agent.rs` | Done | eBPF loader, per-CPU async perf array drain, event collection |
| `src/replay/engine.rs` | Stubbed | Strategy documented in comments, needs impl |
| `src/replay/network.rs` | Stubbed | MockServer skeleton, HTTP parsing is TODO |
| `examples/docker-compose-demo` | Done | api + worker Flask services; `make demo` wires everything |
| `Makefile` | Done | build-ebpf → build-userspace → demo targets |

## MVP milestone

Get `rewind record` capturing live HTTP between two Docker Compose services and writing a valid `.rwd` file.

Steps:
1. Implement `rewind-ebpf/src/main.rs` — fill in `try_capture_send` to read from `msghdr`, extract HTTP method/path, emit `HttpEvent` to the perf array
2. Implement `src/capture/agent.rs` — uncomment the eBPF loader, attach kprobes, spawn a tokio task draining the perf event ring buffer into `Vec<Event>`
3. Write a two-service Docker Compose demo in `examples/docker-compose-demo/`
4. Verify end-to-end: `rewind record --services api,worker` produces a readable `.rwd`

## Incident coverage (honest assessment)

- HTTP capture only: ~40-50% of production incidents
- + DB wire protocol capture: ~75%
- + Minimum viable row snapshot (just touched rows): ~90%
- + Full DB snapshot (opt-in): ~95%

Thread scheduling non-determinism (Heisenbugs) is not solvable with this approach.

## CLI design

    rewind record --services api,worker --output incident.rwd
    rewind flush --window 5m --output incident.rwd
    rewind replay incident.rwd --compose docker-compose.yml
    rewind inspect incident.rwd

## Comparable tools (and how rewind differs)

- **LogRocket** — frontend session replay (browser DOM). rewind is backend infrastructure.
- **Speedscale** — closest analog. Commercial, focused on load/regression testing, not incident debugging.
- **Mozilla rr** — deterministic replay for a single process. rewind targets distributed services.
- **GoReplay** — replays HTTP traffic but not deterministically (no state/time control).
- **Jepsen** — fault injection testing, not incident replay.

rewind's unique position: open source, kernel-level (zero instrumentation), focused on "reproduce this production incident locally."
