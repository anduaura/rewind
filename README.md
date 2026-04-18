# rewind

Deterministic replay of distributed system incidents.

Record inter-service traffic and non-deterministic syscalls in production using eBPF — no code changes required. Then replay the exact incident locally for debugging.

## The problem

When a production incident happens in a microservices system, you have logs and traces but you can't *re-execute* what happened. The state is gone, the timing is gone, and "works on my machine" is the default outcome.

rewind captures the full causal chain of an incident and lets you replay it deterministically on your laptop.

## How it works

**Record** — an eBPF agent attaches to running containers and captures:
- All inter-service HTTP/gRPC traffic (requests + responses + timestamps)
- Outbound DB calls (Postgres wire protocol, Redis RESP)
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

# 2. Start the demo services
docker compose -f examples/docker-compose-demo/docker-compose.yml up -d

# 3. Record an incident
sudo ./target/release/rewind record --services api,worker --output incident.rwd
# ... trigger a request, then Ctrl+C to flush

# 4. Inspect the snapshot
./target/release/rewind inspect incident.rwd

# 5. Replay it
./target/release/rewind replay incident.rwd --compose examples/docker-compose-demo/docker-compose.yml
```

Or run everything with:

```bash
make demo
```

## CLI

```
rewind record  --services api,worker --output incident.rwd
rewind flush   --window 5m --output incident.rwd
rewind replay  incident.rwd --compose docker-compose.yml
rewind inspect incident.rwd
```

`record` runs always-on with a bounded in-memory ring buffer. `flush` dumps the last N minutes to disk — so you capture retrospectively after an alert fires, not prospectively.

## Why eBPF

Zero instrumentation. The agent attaches to running containers without restarts, library changes, or sidecar injection. It works with any language and any framework.

## Why Rust

[aya](https://aya-rs.dev) — the Rust eBPF framework — lets you write kernel-space probes in Rust instead of C. This means shared types between the kernel probe and the userspace handler, a single language across the entire codebase, and no struct layout mismatches at the C/Rust boundary.

## Incident coverage

| What's captured | Incident coverage |
|---|---|
| HTTP traffic only | ~40–50% |
| + DB wire protocol (Postgres, Redis) | ~75% |
| + Minimum row snapshot (touched rows only) | ~90% |
| + Full DB snapshot (opt-in) | ~95% |

Thread scheduling non-determinism (Heisenbugs) is not addressable with this approach.

## Project status

Early — the capture pipeline is implemented, replay is stubbed. See [CLAUDE.md](CLAUDE.md) for the detailed implementation status and next milestones.

## Comparable tools

| Tool | What it does | How rewind differs |
|---|---|---|
| Mozilla rr | Deterministic replay for a single process | rewind targets distributed services |
| Speedscale | Traffic replay for load/regression testing | rewind is focused on incident debugging, not load testing |
| GoReplay | Replays HTTP traffic | Not deterministic — no state or time control |
| Jepsen | Fault injection testing | rewind replays real incidents, not synthetic faults |

rewind's position: open source, kernel-level (zero instrumentation), focused on *reproduce this production incident locally*.

## License

MIT
