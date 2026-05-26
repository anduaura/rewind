# Getting started with rewind

This guide walks you through capturing and replaying your first production incident on a Docker Compose stack. It takes about 15 minutes.

## Prerequisites

| Requirement | Notes |
|---|---|
| Linux kernel 5.10+ | Ubuntu 22.04, Debian 12, RHEL 9, Amazon Linux 2023 all qualify |
| Docker + Docker Compose v2 | `docker compose version` must succeed |
| Root or `CAP_BPF` | The eBPF agent needs elevated privileges to attach to the kernel |
| Rust nightly + `bpfel-unknown-none` target | Only needed if building from source |

> **Platform note:** the eBPF probe (`rewind-ebpf`) only builds and runs on **Linux**. On macOS/Windows you can build the userspace CLI for `inspect`, `replay`, `report`, etc. against existing `.rwd` snapshots, but `make build-ebpf` and `rewind record`/`rewind attach` require a Linux host (bare metal, VM, or WSL2). For the demo flow below, use a Linux VM or run inside an Ubuntu container.

Check your kernel version:

```bash
uname -r   # must be 5.10 or later
```

## Install

### Option A — pre-built binary (recommended)

```bash
# Linux x86_64
curl -Lo rewind https://github.com/anduaura/rewind/releases/latest/download/rewind-x86_64-unknown-linux-musl
chmod +x rewind
sudo mv rewind /usr/local/bin/

# Verify
rewind --help
```

### Option B — from source

Building from source requires a Rust toolchain. If `cargo --version` already works, skip to step 2.

**1. Install Rust + the components rewind needs**

```bash
# Install rustup (Rust toolchain manager)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"          # adds cargo to PATH for the current shell

# Stable toolchain (for the userspace CLI)
rustup toolchain install stable

# Nightly toolchain + rust-src (needed for -Z build-std=core when compiling the eBPF probe)
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly

# Linux only — eBPF target + linker
rustup target add bpfel-unknown-none --toolchain nightly
cargo install bpf-linker             # installs the LLVM-based linker aya uses
```

On Debian/Ubuntu you'll also need a few system packages for `bpf-linker` to build:

```bash
sudo apt install -y build-essential pkg-config libssl-dev llvm clang
```

**2. Build**

```bash
git clone https://github.com/anduaura/rewind
cd rewind

# Linux: build the eBPF probe, then the CLI (which embeds the probe)
make build-ebpf
make build-userspace

# macOS / Windows: skip make build-ebpf and build the userspace CLI only.
# It can inspect, replay, report on, etc. existing .rwd snapshots, but cannot record.
cargo build --release -p rewind

# The binary is at target/release/rewind
sudo cp target/release/rewind /usr/local/bin/
```

**3. Verify**

```bash
rewind --help
```

> **`/bin/sh: cargo: command not found`** — rustup installs cargo into `~/.cargo/bin`, which is added to PATH on shell start. Either open a new terminal or run `source "$HOME/.cargo/env"` in the current one.

## Step 1 — start your application

rewind attaches to any running Docker Compose stack. Bring yours up normally:

```bash
cd /path/to/your/project
docker compose up -d
```

If you want to try rewind with a working example first, use the bundled demo:

```bash
cd /path/to/rewind-repo/examples/docker-compose-demo
docker compose up -d
# api service on :5001, worker on :5002, postgres on :5432, redis on :6379
```

## Step 2 — attach the agent

In a dedicated terminal (keep it running):

```bash
sudo rewind attach
# or, for the demo:
sudo rewind attach -f examples/docker-compose-demo/docker-compose.yml
```

Output:

```
Detected 2 service(s): api, worker
rewind record
  services: api, worker
  output:   incident.rwd
  metrics:  http://0.0.0.0:9090/metrics
Recording… press Ctrl+C to stop, or run `rewind flush` to snapshot
```

The agent is now capturing all HTTP traffic and DB calls from those services. It holds the last ~5 minutes of events in memory; nothing is written to disk yet.

> **Tip:** rewind works with `--services` too if you don't have a compose file:
> `sudo rewind record --services api,worker`

## Step 3 — trigger an incident

Send some requests to your application. For the demo:

```bash
# Happy path
curl http://localhost:5001/users/1

# Trigger an error (user not found)
curl http://localhost:5001/users/999

# Trigger a slow query
curl -X POST http://localhost:5001/orders -H 'Content-Type: application/json' \
     -d '{"user_id": 1, "item": "widget"}'
```

Now simulate noticing the incident a minute or two later.

## Step 4 — flush the snapshot

In a second terminal (while the agent is still running):

```bash
rewind flush --window 2m --output incident.rwd
```

This writes the last 2 minutes of captured events to `incident.rwd`. The agent keeps running — flush is non-destructive.

```
Flushed 47 events to incident.rwd
```

## Step 5 — inspect the snapshot

```bash
rewind inspect incident.rwd
```

```
snapshot: incident.rwd
recorded: 2026-04-24T10:23:01Z   events: 47   services: api, worker

HTTP events (12):
  [inbound ] POST /orders          → 201  api      10:23:01.001
  [outbound] GET  /internal/stock  → 200  api      10:23:01.012
  [inbound ] GET  /users/999       → 404  api      10:23:01.045
  ...

DB events (8):
  [postgres] SELECT * FROM users WHERE id=$1    → (id): 1, name: alice [SELECT 1]
  [redis   ] GET  session:abc123                → "eyJ..."
  ...

Syscall events (27):
  clock_gettime → 1745489581000000000
  getrandom     → 13044791234...
```

## Step 6 — replay

```bash
rewind replay incident.rwd --compose docker-compose.yml
```

rewind:
1. Detects libfaketime on the host and volume-mounts it into every container — no image changes needed
2. Starts a mock HTTP server that intercepts all outbound calls and returns the recorded responses
3. Brings up your services with the same wall-clock time as during recording
4. Re-fires the triggering request

```
rewind replay
  snapshot: incident.rwd
  compose:  docker-compose.yml
  events:   47
  trigger:  POST /orders
  mocking:  6 outbound responses
  baseline: status=201 body=captured
  clock:    @2026-04-24 10:23:01  (libfaketime from /usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1)

Starting services…
  Waiting for :5001 ready

Re-executing: POST http://127.0.0.1:5001/orders

── Replay diff ──────────────────────────────────────────────────────────
  status:    201 == 201  ✓
  body:      match  ✓
─────────────────────────────────────────────────────────────────────────
```

A zero-diff replay means the re-execution matches the recorded response exactly — the incident is fully deterministic and reproducible. Exit code 0.

If the replay diverges (you patched the code and changed behaviour), the diff shows what changed:

```
── Replay diff ──────────────────────────────────────────────────────────
  status:    201 == 500  ✗
  body diff:
    data.order_id  recorded="ord-42"  actual=(missing)
─────────────────────────────────────────────────────────────────────────
Error: replay diverged from recorded response
```

Exit code 1 — safe to use in CI.

## Working with snapshots

### Capture with request/response bodies

```bash
sudo rewind attach --capture-bodies
```

Bodies are truncated to 512 bytes per event. Enable only when you need to debug payload content.

### Encrypt at rest

```bash
sudo rewind attach --key mysecretpassphrase
# or via env var (preferred for CI):
export REWIND_SNAPSHOT_KEY=mysecretpassphrase
sudo rewind attach

# Inspect / replay an encrypted snapshot:
rewind inspect incident.rwd --key mysecretpassphrase
rewind replay incident.rwd --key mysecretpassphrase --compose docker-compose.yml
```

### Export to OpenTelemetry

```bash
rewind export incident.rwd | \
  curl -sX POST http://localhost:4318/v1/traces \
       -H 'Content-Type: application/json' -d @-
```

### Scrub PII before sharing

```bash
rewind scrub incident.rwd incident-scrubbed.rwd \
  --redact-headers authorization,cookie \
  --redact-body
```

### Generate an incident report

```bash
rewind report incident.rwd              # Markdown to stdout
rewind report incident.rwd --format html --output report.html
```

### Render a sequence diagram

```bash
rewind timeline incident.rwd            # Mermaid (paste into GitHub / Notion)
rewind timeline incident.rwd --format ascii
```

## Troubleshooting

### `cargo: command not found` when running `make build-ebpf`

Rust isn't installed (or not on PATH). Install rustup and reload the shell:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
cargo --version   # should now print
```

Then install the nightly toolchain and `bpfel-unknown-none` target as shown in [Option B — from source](#option-b--from-source).

### `error: "rust-src" is not installed for the toolchain "nightly"`

The eBPF build uses `-Z build-std=core`, which needs the Rust source. Add it:

```bash
rustup component add rust-src --toolchain nightly
```

### `error: linker 'bpf-linker' not found`

Install the linker aya uses to produce eBPF objects:

```bash
cargo install bpf-linker
```

If the install itself fails on Linux, install LLVM dev headers first: `sudo apt install -y llvm clang libssl-dev pkg-config build-essential`.

### `make build-ebpf` on macOS

The eBPF target only builds on Linux. Use a Linux VM, a dev container, or WSL2 on Windows. On macOS you can still `cargo build --release -p rewind` to get a CLI capable of `inspect`, `replay`, `report`, etc. on existing snapshots.

### `failed to load eBPF object`

The eBPF binary is embedded at compile time. If you installed a pre-built binary, this is already done. If building from source, run `make build-ebpf` before `make build-userspace`.

### `clock: skipped — libfaketime not found on host`

Install libfaketime on the machine running `rewind replay`:

```bash
# Ubuntu / Debian
sudo apt install faketime

# RHEL / Fedora
sudo dnf install libfaketime
```

Or pass `--no-faketime` to replay without clock override (most incidents still reproduce).

### `service did not become healthy`

The replay engine polls `GET /health` on the trigger service. If your service uses a different health endpoint or takes longer than 10 seconds to start, the replay will time out. Ensure `/health` returns 2xx when ready, or pre-start your services manually before running `rewind replay`.

### `snapshot contains no inbound trigger request`

rewind looks for an inbound HTTP event (a request received by your service, not one it made). If the incident was triggered by a background job or a timer rather than an inbound request, replay cannot re-execute it automatically. Use `rewind inspect` to see what was captured and identify the correct trigger.

## Next steps

- [Kubernetes deployment guide](kubernetes.md) — run rewind as a DaemonSet
- [Configuration reference](configuration.md) — all flags and environment variables
- [Architecture](architecture.md) — how the eBPF probes and replay engine work
