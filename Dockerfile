# syntax=docker/dockerfile:1

# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM rust:1-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    musl-tools \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /build

# Cache dependencies before copying source
COPY rewind-common/Cargo.toml rewind-common/Cargo.toml
COPY rewind/Cargo.toml rewind/Cargo.toml
COPY Cargo.lock .

# Stub source files so cargo can resolve the dependency graph
RUN mkdir -p rewind-common/src rewind/src && \
    echo "pub fn stub() {}" > rewind-common/src/lib.rs && \
    echo "fn main() {}" > rewind/src/main.rs

# Fetch + compile dependencies (cached layer)
RUN cargo build --release --manifest-path rewind/Cargo.toml \
    --target x86_64-unknown-linux-musl 2>/dev/null || true

# Now copy real source and build
COPY rewind-common rewind-common
COPY rewind rewind

RUN cargo build --release --manifest-path rewind/Cargo.toml \
    --target x86_64-unknown-linux-musl

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder \
    /build/target/x86_64-unknown-linux-musl/release/rewind \
    /usr/local/bin/rewind

# Default output directory (override via --output or env in the DaemonSet)
VOLUME ["/var/lib/rewind/snapshots"]

ENTRYPOINT ["/usr/local/bin/rewind"]
CMD ["--help"]
