# Getting started with rewind

This guide walks you through capturing and replaying your first production incident on a Docker Compose stack. It takes about 15 minutes.

## Prerequisites

| Requirement | Notes |
|---|---|
| Linux kernel 5.10+ | Ubuntu 22.04, Debian 12, RHEL 9, Amazon Linux 2023 all qualify |
| Docker + Docker Compose v2 | `docker compose version` must succeed |
| Root or `CAP_BPF` | The eBPF agent needs elevated privileges to attach to the kernel |
| Rust nightly + `bpfel-unknown-none` target | Only needed if building from source |

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

```bash
git clone https://github.com/anduaura/rewind
cd rewind

# Build the eBPF probe (requires nightly Rust)
make build-ebpf

# Build the CLI (embeds the eBPF binary)
make build-userspace

# The binary is at rewind/target/release/rewind
sudo cp rewind/target/release/rewind /usr/local/bin/
```

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
