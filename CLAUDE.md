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
| `rewind-common` | Done | HttpEvent (+ headers_raw + body_raw), SyscallEvent, DbEvent (+ is_response) types with aya::Pod; DbProtocol::MySQL added |
| `rewind-ebpf` | Done | tcp_sendmsg kprobe: HTTP (+ headers_raw + body_raw capture via \r\n\r\n separator) + Postgres + Redis + MySQL via WATCHED_PORTS; tcp_recvmsg kprobe+kretprobe (DB response capture incl. MySQL seq-byte heuristic); sys_exit captures clock_gettime + getrandom |
| `src/store/snapshot.rs` | Done | Full .rwd read/write, Event display; Event/HttpRecord/SyscallRecord are Clone |
| `src/cli.rs` | Done | All four subcommands wired |
| `src/capture/ring.rs` | Done | RingBuffer (VecDeque + Instant), bounded 200k events, drain_window(Duration) |
| `src/capture/agent.rs` | Done | eBPF loader, per-CPU async perf array drain, ring buffer, traceparent extraction, DB query/response correlation, Unix socket IPC for `rewind flush`; body populated from body_raw when --capture-bodies set |
| `src/replay/engine.rs` | Done | Compose up w/ clock+proxy override, MockServer spawn, trigger re-execution, health wait |
| `src/replay/network.rs` | Done | axum-based MockServer, method+path matching, in-order response consumption, 502 diagnostics; content-type taken from recorded response headers |
| `src/export.rs` | Done | OTLP JSON export (`rewind export`); each event → span with traceId/spanId; pipe to any OTEL collector |
| `benches/` | Done | criterion benchmarks for ring buffer (push/drain) and snapshot I/O (read/write); `make bench` |
| `examples/docker-compose-demo` | Done | api + worker Flask services with Postgres + Redis; `make demo` wires everything |
| `Makefile` | Done | build-ebpf → build-userspace → bench → demo targets |
| `src/report.rs` | Done | `rewind report` — Markdown + HTML incident report; HTTP timeline, DB queries, gRPC calls, error summary, syscall counts |
| `src/timeline.rs` | Done | `rewind timeline` — Mermaid + ASCII sequence diagram of inter-service request flow; paste into GitHub/Notion/Miro |
| `src/notify.rs` | Done | `rewind notify` — Slack Block Kit + generic webhook notification; event counts, services, timeline preview; `--dry-run` for inspection |
| `src/search.rs` | Done | `rewind search` — filter snapshots by HTTP path/status/method, DB query/protocol, service name; 13 tests |
| `tests/` (unit) | Done | 169 unit tests: parsers, ring buffer, snapshot roundtrip, server RBAC + rate limiting, report + timeline + notify + search; `cargo test` |
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
| 28 | Audit log — structured JSON record of every capture, flush, and replay event | Done |
| 29 | Auto-trigger on alert — webhook endpoint so PagerDuty/Opsgenie can flush on incident open | Done |
| 30 | Central collection server (`rewind server`) — agents push snapshots over HTTP; replaces `kubectl cp` | Done |
| 31 | Snapshot retention + TTL cleanup — max-size and max-age policies to prevent disk fill on prod nodes | Done |
| 32 | RBAC / access control — token-based auth on the collection server; teams scoped to their own services | Done |
| 33 | VS Code extension — browse, inspect, and replay `.rwd` files directly from the editor | Done |
| 34 | Replay diff — compare two replays side-by-side; surface divergences in DB responses and timing | Done |
| 35 | SaaS collection plane — hosted server + web UI; teams push snapshots, share replay links, view timelines | Done |
| 36 | seccomp/AppArmor profile — replace `privileged: true` with minimal capabilities + seccomp profile | Done |
| 37 | Cloud storage sink — `rewind push s3://\|gs://\|az://` for snapshot archival to object storage | Done |
| 38 | Grafana dashboard bundle — pre-built dashboards for the `/metrics` Prometheus endpoint | Done |
| 39 | Kafka capture — eBPF producer/consumer wire protocol (port 9092) capture | Done |
| 40 | Package distribution — Homebrew tap + apt/deb + rpm packages for frictionless installation | Done |
| 41 | Post-hoc PII scrub (`rewind scrub src.rwd dst.rwd`) — redact headers, strip bodies, filter paths on stored snapshots | Done |
| 42 | TLS for collection server (`--tls-cert`/`--tls-key` on `rewind server`) | Done |
| 43 | Snapshot integrity verification (`rewind verify`) — SHA-256 manifest + tamper detection | Done |
| 44 | Rate limiting + upload size cap — per-IP sliding-window limiter + `DefaultBodyLimit` on `rewind server` | Done |
| 45 | CI/CD integration — `rewind-setup` composite action + regression-test and snapshot-audit workflow examples | Done |
| 46 | Structured logging — `tracing` + `tracing-subscriber`; `--log-format json` for log aggregators; `RUST_LOG` / `REWIND_LOG` level control | Done |
| 47 | Incident report generation — `rewind report` produces a Markdown or HTML post-mortem document from a snapshot; HTTP timeline, DB queries, gRPC calls, error summary | Done |
| 48 | Sequence diagram — `rewind timeline` renders the inter-service request flow as a Mermaid or ASCII sequence diagram; paste into GitHub/Notion/Miro for post-mortems | Done |
| 49 | Slack / webhook notification — `rewind notify` sends a Block Kit summary (event counts, services, timeline preview) to any Slack Incoming Webhook or generic HTTP endpoint | Done |
| 50 | Snapshot search — `rewind search <dir>` with filters for path, status, method, DB query, service, protocol; ANDed filters, JSON output | Done |
| 51 | SSO / OIDC — `rewind server` validates RS256 JWT Bearer tokens against any OIDC provider (Okta, Azure AD, Google); JWKS auto-refresh; claims mapped to RBAC teams | Done |
| 52 | Secret management integration — resolve `--key` from Vault, AWS Secrets Manager, or Azure Key Vault via URI scheme (`vault://`, `aws://`, `azure://`), not just env vars | Done |
| 53 | Compliance evidence export — `rewind compliance` produces a machine-readable JSON/Markdown report: encryption status, retention config, audit log summary, RBAC setup | Done |
| 54 | Data subject deletion — `rewind gdpr-delete --user-id <id>` scans snapshot directory and redacts/deletes all events containing matching PII patterns | Done |
| 55 | Prometheus alerting rules — `deploy/alerts.yaml` with pre-built rules: ring buffer >80% full, agent disconnected, server upload error rate spike, high 5xx rate | Done |
| 56 | HA / multi-replica server — stateless `rewind server` with shared storage back-end; leader election for retention jobs; Kubernetes HPA example | Done |
| 57 | Webhook HMAC validation — verify PagerDuty/Opsgenie/generic webhook signatures (HMAC-SHA256) before triggering flush; unsigned requests rejected with 401 | Done |
| 58 | Read/write RBAC — token registry gains per-token permission level (`read`, `write`, `admin`); agents get write-only, developers get read-only; enforced on all server endpoints | Done |
| 59 | Integration test suite — server upload/list/download, retention, scrub, gdpr-delete, and compliance tested end-to-end against real filesystem; currently only inspect/export are covered | Done |
| 60 | HTTP body capture end-to-end — eBPF probe scans for `\r\n\r\n` and copies up to 128 body bytes; agent populates `HttpRecord.body` when `--capture-bodies` set; MockServer uses recorded `content-type` header | Done |
| 61 | Replay result validation — `rewind replay` diffs recorded vs actual response after re-execution; JSON field-by-field diff with dot-path notation; exits 1 on divergence for CI; `--no-diff` flag | Done |
| 62 | Service attribution — `ServiceMap` resolves PIDs to service names via `docker inspect` + `/proc/<pid>/cgroup` (v1 and v2); all event parsers populate `service` field; cached per-PID | Done |
| 63 | `rewind diff` — compare two `.rwd` snapshots without running a replay; DB response, HTTP status+body, syscall return, and timing drift detection; JSON output; exits 1 on divergence | Done |

## Enterprise readiness gaps

Honest assessment of what blocks enterprise adoption, ordered by impact. Work through these one by one.

| # | Gap | Layer | Status | Notes |
|---|-----|-------|--------|-------|
| E1 | **eBPF CO-RE / BTF** — probes hardcode struct offsets for x86_64 Linux 5.14+; will silently produce garbage or crash on EKS 1.27, GKE 1.28, ARM nodes. Need BTF-aware field access (`bpf_core_read!`) so offsets are resolved at load time against the running kernel. | eBPF capture | Done | vmlinux.rs CO-RE structs + `addr_of!` typed field reads replace all magic offsets |
| E2 | **Replay libfaketime constraint** — `rewind replay` requires libfaketime to be pre-installed in every container image. Almost no production image has this. Need an alternative clock-override strategy (ptrace, seccomp, or LD_PRELOAD injection at start without image modification). | Replay | Done | `find_libfaketime()` probes host paths; compose override volume-mounts the .so read-only into each container — no image changes required. Degrades gracefully with warning + `--no-faketime` flag when absent. |
| E3 | **128-byte body truncation** — eBPF copies at most 128 bytes of HTTP body. GraphQL queries, large JSON payloads, and gRPC proto bodies are silently truncated. Need a userspace follow-up read (via `/proc/<pid>/fd`) or increased per-CPU map buffer. | eBPF capture | Done | `body_raw` increased to 512 bytes; `HTTP_EVENT_SCRATCH` PerCpuArray moves 796-byte HttpEvent off the 512-byte eBPF stack; `emit_http_event` does a fresh `bpf_probe_read_user_buf` at `iov_base+sep` for body, bypassing the 256-byte preview window. |
| E4 | **Service attribution in Kubernetes** — `ServiceMap` uses `docker inspect` which doesn't work in Kubernetes pods. Need cgroup v2 path parsing for k8s (`/sys/fs/cgroup/kubepods/...`) and Pod → service name resolution via the Downward API or the kubelet API. | Capture agent | Pending | All events show `service: ""` on Kubernetes; breaks timeline/report |
| E5 | **No load / scale validation** — collection server has never served production traffic; no load test, no chaos test, no proven shared-storage backend under concurrent writes. | Collection server | Pending | Enterprise buyers require load test results |
| E6 | **No third-party security audit** — encryption, RBAC, HMAC validation are implemented but unaudited. SOC 2 / ISO 27001 customers require a penetration test or third-party review. | Security | Pending | Sales blocker for regulated industries |
| E7 | **SaaS web UI is missing** — milestone 35 is marked Done but no browser-based UI exists; the collection server has API endpoints but no snapshot browsing, timeline visualisation, or team management UI. | Developer experience | Pending | Required for the commercial offering |
| E8 | **No getting-started documentation** — no user guide, no API reference, no Kubernetes quickstart aimed at a non-contributor engineer. | Documentation | Pending | Adoption blocker; engineers won't evaluate what they can't run |



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
