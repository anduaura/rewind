# eBPF agent overhead — measurement methodology + results

## Status of E22

`CLAUDE.md` lists milestone 22 ("eBPF overhead measurement + security/threat model documentation") as **Done**. The README has a table of overhead numbers. Every cell in that table is labelled *Expected*. None of those numbers were measured.

That gap is the bug. A YC partner who asks "how much overhead does the agent add?" should not be given an estimate. They should be given a number from `cargo run -p load_test` against a real stack on a real kernel.

This doc fixes the gap. Two parts:

1. **Methodology** — exact commands, fixtures, hardware, that anyone (founder, design partner, partner) can replicate.
2. **Results template** — table to fill in once the bench runs. Empty cells are honest about what we haven't measured.

## Why this matters more than it sounds

eBPF tools have a credibility problem in 2026. The first question every infra-buyer asks — and the first question every kernel-curious skeptic on HN asks — is "what does it cost me?" If the answer is hand-wavy, the conversation ends. If the answer is "p95 went from 12.3ms to 12.5ms, here's the flamegraph," the conversation continues.

This is also the only milestone in the YC pitch that's *trivial to ship* with no founder feature decisions. Just run the bench.

## Methodology

### Hardware target

Run on the most common production substrate, not a beefy dev laptop. Two configurations to publish:

1. **Cloud baseline** — c6i.large on AWS (2 vCPU, 4 GB, Intel Ice Lake). 80% of production microservices run on Intel cloud VMs in this size class.
2. **K8s baseline** — `n2-standard-4` on GKE (4 vCPU, 16 GB). Closer to what a real cluster node looks like.

ARM (`c7g.large`, `t2a-standard-2`) is a follow-up — note as "next" in the published results.

### Workload

Use the existing `examples/docker-compose-demo` (api + worker + postgres + redis). Drive it with the existing `rewind/src/bin/load_test.rs` plus a stand-alone wrk run.

```bash
# Terminal A — start the stack without rewind attached
make demo

# Terminal B — baseline load test, 60s, 50 connections, keep-alive
wrk -t4 -c50 -d60s --latency http://localhost:8000/orders \
  --script post.lua > baseline.txt

# Terminal C — repeat with agent attached
sudo rewind attach &
AGENT_PID=$!
wrk -t4 -c50 -d60s --latency http://localhost:8000/orders \
  --script post.lua > with-agent.txt
kill $AGENT_PID
```

Three runs of each, take the median, publish the spread.

### What to measure

Six numbers, all comparing baseline (no agent) to with-agent:

| Metric | Tool | What it tells the buyer |
|--------|------|------------------------|
| Request rate (req/s) | wrk | Throughput cost |
| p50 latency | wrk | Typical request impact |
| p95 latency | wrk | Tail latency impact (this is the one they care about) |
| p99 latency | wrk | Worst-case spike risk |
| CPU % (agent process) | `pidstat -p $AGENT_PID 1 60` | What the agent consumes |
| RSS memory (agent) | `pidstat -r -p $AGENT_PID 1 60` | What it costs you in memory |

Bonus number, in a separate run: peak ring-buffer occupancy at 1k req/s sustained. Tells you whether the 200k-event buffer holds 5 minutes at real load or only 30 seconds.

### Sustained-load variant

The above is a 60-second test. For the YC pitch, also run a 30-minute sustained test at moderate load (200 req/s) to check for memory creep or buffer-full event loss. Publish: "in 30 min sustained load, agent consumed X MB RSS (no growth), 0 events dropped."

### Eviction-rate test

Drive load up until the ring buffer starts evicting (oldest events dropped). Publish: "ring buffer holds 5m of traffic up to N req/s; above that, oldest events evicted to make room." This is the honest answer to "what happens at scale."

## Results template

Fill in once benched. Mark `—` for what isn't measured yet so the gaps are visible.

### c6i.large (AWS, Intel Ice Lake)

| Metric | Baseline | With agent | Delta |
|--------|---------:|-----------:|------:|
| Throughput (req/s) | _ | _ | _ |
| p50 latency (ms)   | _ | _ | _ |
| p95 latency (ms)   | _ | _ | _ |
| p99 latency (ms)   | _ | _ | _ |
| Agent CPU (% of 1 core) | n/a | _ | _ |
| Agent RSS (MB)     | n/a | _ | _ |

### n2-standard-4 (GKE)

| Metric | Baseline | With agent | Delta |
|--------|---------:|-----------:|------:|
| Throughput (req/s) | _ | _ | _ |
| p50 latency (ms)   | _ | _ | _ |
| p95 latency (ms)   | _ | _ | _ |
| p99 latency (ms)   | _ | _ | _ |
| Agent CPU (% of 1 core) | n/a | _ | _ |
| Agent RSS (MB)     | n/a | _ | _ |

### Sustained 30-min, 200 req/s

- Agent CPU steady-state: _
- Agent RSS at t=0: _
- Agent RSS at t=30min: _
- Events dropped: _
- Buffer occupancy at end: _ / 200k

### Eviction threshold

- Sustained req/s above which ring buffer evicts: _
- At 2× that rate, fraction of events lost: _

## Why a Mac session can't generate these

This methodology doc was written in a Mac session. eBPF requires Linux with `CAP_BPF` and a kernel ≥ 5.10. The methodology is reproducible — anyone with a Linux VM (or a GitHub Actions Linux runner with the right kernel) can run it in under 30 min and produce the numbers.

**Action item for the founder:** spin up one c6i.large, run the methodology, paste results into the template above. Publish the filled-in version as `docs/overhead-results-v0.1.md`. Reference from the README in place of the current "Expected" table.

## What to publish externally

Once the numbers exist, swap the README "Performance overhead" section. Replace:

```
| CPU overhead at 1000 req/s | < 0.5% of one core |
```

…with the measured numbers and a link to the methodology. Same for the rest of the table. Add a one-liner: "All numbers measured on c6i.large with kernel 6.5, methodology in [`docs/overhead-benchmark.md`](docs/overhead-benchmark.md). Reproduce with `make bench-overhead`."

That `make bench-overhead` target should automate the wrk/pidstat dance. New target — add to Makefile after the bench results are in.

## What the partner is actually looking for

The pitch line is:

> "At 1000 req/s, rewind adds <X>µs to p95 latency and consumes <Y> MB of RAM per node. Measured on c6i.large with Linux 6.5; reproducible in our repo."

Specific numbers, real hardware, reproducible. That sentence is the entire deliverable. The rest of this doc is just the work to write it honestly.
