EBPF_TARGET := bpfel-unknown-none
EBPF_BIN    := rewind-ebpf/target/$(EBPF_TARGET)/release/rewind-ebpf

LOAD_URL    ?= http://127.0.0.1:9092
LOAD_TOKEN  ?=
LOAD_VUS    ?= 10
LOAD_SECS   ?= 30
LOAD_KB     ?= 10

.PHONY: all build build-ebpf build-userspace check fmt clean load-test load-test-k6

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

## Run the Rust load-test binary against a running rewind server.
##
##   make load-test LOAD_URL=http://collector:9092 LOAD_TOKEN=tok \
##                  LOAD_VUS=50 LOAD_SECS=60
##
## The server must already be running. Start one with:
##   rewind server --listen 127.0.0.1:9092 --storage /tmp/rwd-load --token tok
load-test:
	cargo build --bin load_test
	./target/debug/load_test \
	  --url $(LOAD_URL) \
	  $(if $(LOAD_TOKEN),--token $(LOAD_TOKEN),) \
	  --concurrency $(LOAD_VUS) \
	  --duration-secs $(LOAD_SECS) \
	  --snapshot-kb $(LOAD_KB)

## Run the k6 load test (requires k6 installed: https://k6.io/docs/get-started/installation/).
##
##   make load-test-k6 LOAD_URL=http://collector:9092 LOAD_TOKEN=tok SCENARIO=load
##
## Scenarios: smoke (default) | load | stress | spike
load-test-k6:
	BASE_URL=$(LOAD_URL) TOKEN=$(LOAD_TOKEN) SCENARIO=$(or $(SCENARIO),smoke) \
	  k6 run tests/load/k6-server.js

## Run the demo: bring up two services and start recording.
## Requires Docker Compose and a root/CAP_BPF capable shell.
demo: build
	docker compose -f examples/docker-compose-demo/docker-compose.yml up -d
	@echo "Services up. Starting recorder (Ctrl+C to flush)…"
	sudo ./target/release/rewind record \
	  --services api,worker \
	  --output incident.rwd
