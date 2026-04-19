# rewind

Deterministic replay of distributed system incidents.

Record inter-service traffic and non-deterministic syscalls in production using eBPF — no code changes required. Then replay the exact incident locally for debugging.

## The problem

When a production incident happens in a microservices system, you have logs and traces but you can't *re-execute* what happened. The state is gone, the timing is gone, and "works on my machine" is the default outcome.

rewind captures the full causal chain of an incident and lets you replay it deterministically on your laptop.

## How it works

**Record** — an eBPF agent attaches to running containers and captures:
- All inter-service HTTP traffic (method, path, status, headers, timestamps)
- W3C `traceparent` headers for cross-service correlation
- Outbound DB calls: Postgres wire protocol, Redis RESP, MySQL wire protocol
- DB responses correlated with their queries
- Non-deterministic syscalls: `clock_gettime`, `getrandom`

**Replay** — given the snapshot, the replay engine:
1. Overrides the system clock to match recording start time
2. Seeds random sources with recorded values
3. Intercepts outbound network calls, returning recorded responses
4. Re-executes the triggering request — deterministically

The output is a `.rwd` file (JSON) containing the full causal chain.

## Quickstart

> **Requirements:** Linux 5.10+, nightly Rust, Docker + Compose, root/CAP_BPF for recording.

```bash
# 1. Build
make build-ebpf       # compile the eBPF probe (nightly + bpfel target)
make build-userspace  # compile the CLI (embeds the eBPF binary)

# 2. Attach to any Docker Compose stack — services auto-detected
sudo rewind attach

# 3. Trigger a request in another terminal, then flush to disk
rewind flush --window 5m --output incident.rwd

# 4. Inspect the snapshot
rewind inspect incident.rwd

# 5. Replay it
rewind replay incident.rwd --compose docker-compose.yml
```

Or run the bundled two-service demo end-to-end:

```bash
make demo
```

## CLI

```
rewind attach  [-f docker-compose.yml] [-o incident.rwd]
rewind record  --services api,worker  [-o incident.rwd]
rewind flush   --window 5m            [-o incident.rwd]
rewind replay  incident.rwd [--compose docker-compose.yml]
rewind inspect incident.rwd
rewind export  incident.rwd [-o spans.json]
```

### attach

The fastest way to start capturing. Reads `docker-compose.yml` in the current directory, extracts all service names, and starts recording — no `--services` flag required.

```bash
sudo rewind attach                    # reads ./docker-compose.yml
sudo rewind attach -f staging.yml     # explicit compose file
```

### record / flush

`record` runs always-on with a bounded in-memory ring buffer (200 k events, ~5 minutes of typical traffic). `flush` dumps the last N minutes to disk without stopping the agent — so you capture retrospectively after an alert fires, not prospectively.

```bash
# Terminal 1 — start the agent
sudo rewind record --services api,worker

# Terminal 2 — after an incident is observed, snapshot the last 2 minutes
rewind flush --window 2m --output incident.rwd
```

### export

Converts a `.rwd` snapshot to [OTLP JSON](https://opentelemetry.io/docs/specs/otlp/) trace spans. Each HTTP, DB, and syscall event becomes a span. Pipe directly to any OpenTelemetry collector.

```bash
rewind export incident.rwd | curl -sX POST http://localhost:4318/v1/traces \
    -H 'Content-Type: application/json' -d @-

# or write to file
rewind export incident.rwd --output spans.json
```

If the captured HTTP requests carried a W3C `traceparent` header, the trace-id is preserved in the exported spans — so rewind incidents appear in the same trace view as your existing distributed traces.

## Why eBPF

Zero instrumentation. The agent attaches to running containers without restarts, library changes, or sidecar injection. It works with any language and any framework.

## Why Rust

[aya](https://aya-rs.dev) — the Rust eBPF framework — lets you write kernel-space probes in Rust instead of C. This means shared types between the kernel probe and the userspace handler, a single language across the entire codebase, and no struct layout mismatches at the C/Rust boundary.

## Incident coverage

| What's captured | Incident coverage |
|---|---|
| HTTP traffic only | ~40–50% |
| + DB wire protocol (Postgres, Redis, MySQL) | ~75% |
| + Minimum row snapshot (touched rows only) | ~90% |
| + Full DB snapshot (opt-in) | ~95% |

Thread scheduling non-determinism (Heisenbugs) is not addressable with this approach.

## Benchmarks

```bash
make bench
```

Criterion benchmarks cover ring buffer throughput (push + drain) and snapshot I/O (read + write) at 100 / 1k / 10k events. Results are written to `rewind/target/criterion/`.

## Project layout

```
rewind-common/   shared no_std types (HttpEvent, DbEvent, SyscallEvent)
rewind-ebpf/     kernel-space eBPF probes (kprobes + tracepoint)
rewind/
  src/
    capture/     eBPF loader, ring buffer, Unix socket IPC
    replay/      replay engine + mock HTTP server
    store/       .rwd snapshot read/write
    export.rs    OTLP JSON export
  benches/       criterion benchmarks
examples/
  docker-compose-demo/   two-service Flask demo (api + worker + Postgres + Redis)
```

## Comparable tools

| Tool | What it does | How rewind differs |
|---|---|---|
| Mozilla rr | Deterministic replay for a single process | rewind targets distributed services |
| Speedscale | Traffic replay for load/regression testing | rewind is focused on incident debugging, not load testing |
| GoReplay | Replays HTTP traffic | Not deterministic — no state or time control |
| Jepsen | Fault injection testing | rewind replays real incidents, not synthetic faults |

rewind's position: open source, kernel-level (zero instrumentation), focused on *reproduce this production incident locally*.

## License

Apache License 2.0 — see [LICENSE](LICENSE) for the full text.
