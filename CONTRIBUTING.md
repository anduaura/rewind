# Contributing to rewind

Thanks for your interest. rewind is early-stage — the most useful contributions right now are bug reports, real-world testing feedback, and protocol additions (new DB wire formats, new syscalls to intercept).

## Before you start

Open an issue first for anything non-trivial so we can align on approach before you invest time writing code.

## Development setup

```bash
# Requirements: Linux 5.10+, nightly Rust (see rust-toolchain.toml), Docker + Compose

# Build the eBPF probe (nightly + bpfel-unknown-none target)
make build-ebpf

# Build the userspace CLI
make build-userspace

# Type-check without requiring the eBPF binary
cargo check

# Run benchmarks
make bench
```

## Project layout

```
rewind-common/   shared no_std types — edited when adding new event types
rewind-ebpf/     kernel-space probes — requires separate build, see Makefile
rewind/src/
  capture/       eBPF loader, ring buffer, IPC
  replay/        replay engine + mock HTTP server
  store/         .rwd snapshot serialisation
  export.rs      OTLP / Jaeger export
benches/         criterion benchmarks
k8s/             Kubernetes manifests
examples/        Docker Compose demo
```

## Adding a new database protocol

1. Add a variant to `DbProtocol` in `rewind-common/src/lib.rs`
2. Seed the port in `init_watched_ports()` in `rewind/src/capture/agent.rs`
3. Add `parse_<proto>_query()` and `parse_<proto>_response()` functions
4. Update all `match raw.protocol` arms (the compiler will tell you which ones)
5. Add the new protocol to the incident coverage table in `CLAUDE.md`

## Commit style

One logical change per commit. Message format:

```
Short imperative summary (≤72 chars)

Optional body explaining why, not what. Wrap at 72 chars.
```

## Licence

By submitting a pull request you agree that your contribution will be licensed under the Apache License 2.0 (see `LICENSE`).
