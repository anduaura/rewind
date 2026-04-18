EBPF_TARGET := bpfel-unknown-none
EBPF_BIN    := rewind-ebpf/target/$(EBPF_TARGET)/release/rewind-ebpf

.PHONY: all build build-ebpf build-userspace check fmt clean

all: build

## Build the eBPF probe then the userspace CLI.
build: build-ebpf build-userspace

## Compile the kernel-space eBPF object (requires nightly + bpf target).
build-ebpf:
	cd rewind-ebpf && \
	  cargo +nightly build \
	    --target $(EBPF_TARGET) \
	    --release \
	    -Z build-std=core

## Compile the userspace CLI (embeds the eBPF binary built above).
build-userspace: $(EBPF_BIN)
	cargo build --release

## Type-check userspace without embedding the eBPF binary.
check:
	cargo check

## Format all Rust source (workspace + ebpf crate).
fmt:
	cargo fmt
	cd rewind-ebpf && cargo fmt

## Run criterion benchmarks (ring buffer throughput, snapshot I/O).
bench:
	cd rewind && cargo bench

clean:
	cargo clean
	cd rewind-ebpf && cargo clean

## Run the demo: bring up two services and start recording.
## Requires Docker Compose and a root/CAP_BPF capable shell.
demo: build
	docker compose -f examples/docker-compose-demo/docker-compose.yml up -d
	@echo "Services up. Starting recorder (Ctrl+C to flush)…"
	sudo ./target/release/rewind record \
	  --services api,worker \
	  --output incident.rwd
