# syntax=docker/dockerfile:1

# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM rust:1-slim-bookworm AS builder

# TARGETARCH is injected by docker buildx: "amd64" or "arm64"
ARG TARGETARCH=amd64

RUN apt-get update && apt-get install -y --no-install-recommends \
    musl-tools \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Map Docker arch → Rust musl target triple, write to /rust-target
RUN case "$TARGETARCH" in \
      amd64) echo x86_64-unknown-linux-musl ;; \
      arm64) echo aarch64-unknown-linux-musl ;; \
      *) echo "unsupported TARGETARCH=$TARGETARCH" >&2 && exit 1 ;; \
    esac > /rust-target

RUN rustup target add "$(cat /rust-target)"

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
RUN RUST_TARGET=$(cat /rust-target) && \
    cargo build --release --manifest-path rewind/Cargo.toml \
    --target "$RUST_TARGET" 2>/dev/null || true

# Now copy real source and build
COPY rewind-common rewind-common
COPY rewind rewind

RUN RUST_TARGET=$(cat /rust-target) && \
    cargo build --release --manifest-path rewind/Cargo.toml \
    --target "$RUST_TARGET"

# Copy binary to a fixed path for the final stage
RUN RUST_TARGET=$(cat /rust-target) && \
    cp "target/${RUST_TARGET}/release/rewind" /rewind

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /rewind /usr/local/bin/rewind

# Default output directory (override via --output or env in the DaemonSet)
VOLUME ["/var/lib/rewind/snapshots"]

ENTRYPOINT ["/usr/local/bin/rewind"]
CMD ["--help"]
