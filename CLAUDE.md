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
| `rewind-common` | Done | HttpEvent (+ headers_raw), SyscallEvent, DbEvent (+ is_response) types with aya::Pod; DbProtocol::MySQL added |
| `rewind-ebpf` | Done | tcp_sendmsg kprobe: HTTP (+ headers_raw capture) + Postgres + Redis + MySQL via WATCHED_PORTS; tcp_recvmsg kprobe+kretprobe (DB response capture incl. MySQL seq-byte heuristic); sys_exit captures clock_gettime + getrandom |
| `src/store/snapshot.rs` | Done | Full .rwd read/write, Event display; Event/HttpRecord/SyscallRecord are Clone |
| `src/cli.rs` | Done | All four subcommands wired |
| `src/capture/ring.rs` | Done | RingBuffer (VecDeque + Instant), bounded 200k events, drain_window(Duration) |
| `src/capture/agent.rs` | Done | eBPF loader, per-CPU async perf array drain, ring buffer, traceparent extraction, DB query/response correlation, Unix socket IPC for `rewind flush` |
| `src/replay/engine.rs` | Done | Compose up w/ clock+proxy override, MockServer spawn, trigger re-execution, health wait |
| `src/replay/network.rs` | Done | axum-based MockServer, method+path matching, in-order response consumption, 502 diagnostics |
| `src/export.rs` | Done | OTLP JSON export (`rewind export`); each event → span with traceId/spanId; pipe to any OTEL collector |
| `benches/` | Done | criterion benchmarks for ring buffer (push/drain) and snapshot I/O (read/write); `make bench` |
| `examples/docker-compose-demo` | Done | api + worker Flask services with Postgres + Redis; `make demo` wires everything |
| `Makefile` | Done | build-ebpf → build-userspace → bench → demo targets |
| `tests/` (unit) | Done | 48 unit tests: all DB/HTTP/Redis/gRPC parsers, ring buffer, snapshot roundtrip; `cargo test` |
| `.github/workflows/` | Done | CI (check + test + clippy + fmt on every PR); Release (musl binary + sha256 on tag push) |
| `helm/rewind/` | Done | Helm chart (DaemonSet + RBAC + ConfigMap); `helm install rewind helm/rewind` |
| `Dockerfile` | Done | Multi-stage musl build → distroless runtime image; pushed to ghcr.io on tag |
| `tests/` (integration) | Done | 11 CLI integration tests: inspect + export (OTLP + Jaeger) against fixture snapshot |
| `src/metrics.rs` | Done | Prometheus `/metrics` + `/healthz` on :9090; counters per event type, ring buffer utilization gauge |

## Roadmap

| # | Milestone | Status |
|---|---|---|
| 10 | MongoDB wire protocol | Done |
| 11 | Minimum viable row snapshot (Postgres DataRow decoding) | Done |
| 12 | gRPC capture (HTTP/2 HEADERS frame + HPACK path extraction) | Done |
| 13 | Kubernetes DaemonSet (`k8s/` manifests) | Done |
| 14 | Jaeger export (`rewind export --format jaeger`) | Done |
| 15 | Test suite (unit tests for parsers + snapshot roundtrip; 48 tests, `cargo test`) | Done |
| 16 | GitHub Actions CI (`cargo check`, `cargo test`, clippy, rustfmt on every PR) | Done |
| 17 | `v0.1.0` release workflow (musl binary + sha256 checksums on tag push) | Done |
| 18 | Helm chart for Kubernetes deployment (`helm/rewind/`) | Done |
| 19 | Docker image build + push workflow (ghcr.io on tag push) | Done |
| 20 | Kubernetes deployment guide (quickstart in README) | Done |
| 21 | Integration test (end-to-end capture → replay against demo Compose stack) | Done |
| 22 | eBPF overhead measurement + security/threat model documentation | Done |
| 23 | Cut `v0.1.0` tag — trigger release binary + Docker image publish | Done |
| 24 | Health probe + Prometheus metrics endpoint (`/healthz`, `/metrics` on :9090) | Done |
| 25 | PII scrubbing config (`--redact-headers`, path allow-list) | Done |
| 26 | Multi-arch Docker image (amd64 + arm64) | Done |

### Enterprise readiness milestones

| # | Milestone | Status |
|---|---|---|
| 27 | Snapshot encryption at rest (`--key`, AES-256-GCM via `age`; `REWIND_SNAPSHOT_KEY` env) | Done |
| 28 | Audit log — structured JSON record of every capture, flush, and replay event | Pending |
| 29 | Auto-trigger on alert — webhook endpoint so PagerDuty/Opsgenie can flush on incident open | Pending |
| 30 | Central collection server (`rewind server`) — agents push snapshots over gRPC; replaces `kubectl cp` | Pending |
| 31 | Snapshot retention + TTL cleanup — max-size and max-age policies to prevent disk fill on prod nodes | Pending |
| 32 | RBAC / access control — token-based auth on the collection server; teams scoped to their own services | Pending |
| 33 | VS Code extension — browse, inspect, and replay `.rwd` files directly from the editor | Pending |
| 34 | Replay diff — compare two replays side-by-side; surface divergences in DB responses and timing | Pending |
| 35 | SaaS collection plane — hosted server + web UI; teams push snapshots, share replay links, view timelines | Pending |
| 36 | seccomp/AppArmor profile — replace `privileged: true` with minimal capabilities + seccomp profile | Done |
| 37 | Cloud storage sink — `rewind push s3://\|gs://\|az://` for snapshot archival to object storage | Done |
| 38 | Grafana dashboard bundle — pre-built dashboards for the `/metrics` Prometheus endpoint | Done |
| 39 | Kafka capture — eBPF producer/consumer wire protocol (port 9092) capture | Done |
| 40 | Package distribution — Homebrew tap + apt/deb + rpm packages for frictionless installation | Done |

## Enterprise readiness goal

The long-term goal is for rewind to be the standard incident replay tool at companies running Kubernetes in regulated industries (finance, healthcare, SaaS). That requires:

**Security & compliance (milestones 27–28)**
Snapshots capture real production traffic. Encryption at rest (milestone 27) satisfies data-at-rest requirements for SOC 2 / ISO 27001. The audit log (milestone 28) gives compliance teams a tamper-evident record of who captured what and when — required for PCI-DSS and HIPAA environments.

**Operational integration (milestones 29–31)**
Incident replay is only useful if it happens automatically. Milestone 29 wires rewind into existing alerting pipelines (PagerDuty, Opsgenie) so a snapshot is triggered the moment an alert fires — no manual `rewind flush` required. The central collection server (milestone 30) eliminates the `kubectl cp` step and enables cross-node snapshot correlation. Retention policies (milestone 31) make the agent safe to run permanently without ops overhead.

**Team-scale access control (milestone 32)**
In multi-team organisations, teams must only see snapshots from their own services. Milestone 32 adds token-scoped access on the collection server, making rewind safe to deploy org-wide.

**Developer experience (milestones 33–34)**
The closer replay is to the developer's existing workflow, the higher adoption. A VS Code extension (milestone 33) lets engineers open a `.rwd` file like a test result. Replay diff (milestone 34) unlocks regression use-cases — run the same snapshot against two versions of a service and see exactly what changed.

**Commercial viability (milestone 35)**
The open-source agent + CLI remains free. The SaaS collection plane is the commercial offering: hosted storage, web UI, team management, SSO. This funds continued development while keeping the capture layer open.

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
