# syntax=docker/dockerfile:1
# Multi-stage Dockerfile for h3llo BareUDP VPN (requires Docker Buildx).
# Cross-compiles static musl binaries on the build host (no QEMU emulation
# for Rust compilation), then copies them into a minimal Alpine runtime image
# matching the target platform.
#
# Supported platforms: linux/amd64, linux/arm64, linux/riscv64
#
# Uses cargo-chef for Docker layer caching of dependencies, plus BuildKit
# cache mounts to persist cargo registry and compilation artifacts across
# builds on the same host. The two mechanisms are complementary:
#   - cargo-chef: separates dependency compilation into a cached Docker layer
#   - cache mounts: persist compiled artifacts across layer cache misses
#
# Targets:
#   runtime (default) - Minimal Alpine production image
#   test              - Adds diagnostic tools for integration tests
#
# Usage:
#   docker buildx build --platform linux/amd64 --target runtime -t h3llo:latest --load .
#   docker buildx build --platform linux/arm64 --target runtime -t h3llo:arm64 --load .
#   docker buildx build --platform linux/amd64 --target test -t h3llo:test --load .

# Stage 1: Chef - Install cargo-chef on native build platform (no QEMU emulation)
FROM --platform=$BUILDPLATFORM rust:slim-trixie AS chef

# Map Docker TARGETARCH to Rust target triple and musl-cross toolchain name.
# TARGETARCH is set automatically by buildx (amd64, arm64, riscv64).
# Note: Rust uses riscv64gc (with gc), musl-cross uses riscv64 (without gc).
ARG TARGETARCH
RUN <<'EOF'
set -e
case "$TARGETARCH" in
  amd64)
    echo "x86_64-unknown-linux-musl"   > /tmp/rust-target
    echo "x86_64-unknown-linux-musl"   > /tmp/toolchain-name
    ;;
  arm64)
    echo "aarch64-unknown-linux-musl"  > /tmp/rust-target
    echo "aarch64-unknown-linux-musl"  > /tmp/toolchain-name
    ;;
  riscv64)
    echo "riscv64gc-unknown-linux-musl" > /tmp/rust-target
    echo "riscv64-unknown-linux-musl"   > /tmp/toolchain-name
    ;;
  *)
    echo "Unsupported TARGETARCH: $TARGETARCH" >&2
    exit 1
    ;;
esac
EOF

# Install boring-sys dependencies, curl/xz for downloading musl toolchain, and jq for parsing Cargo JSON output
RUN apt-get update && apt-get install -y \
    curl xz-utils jq \
    cmake make perl golang-go git \
    clang libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# Download musl cross-compilation toolchain for target architecture
# Source: https://github.com/cross-tools/musl-cross
# Pinned to release 20250929 for reproducible builds.
RUN TOOLCHAIN=$(cat /tmp/toolchain-name) && \
    curl -sSfL "https://github.com/cross-tools/musl-cross/releases/download/20250929/${TOOLCHAIN}.tar.xz" \
    | tar -xJf - -C /opt && \
    ln -sfn "/opt/${TOOLCHAIN}" /opt/cross-toolchain
ENV PATH="/opt/cross-toolchain/bin:$PATH"

# Add musl target and configure cross-compiler env vars
RUN RUST_TARGET=$(cat /tmp/rust-target) && \
    TOOLCHAIN=$(cat /tmp/toolchain-name) && \
    RUST_TARGET_ENV=$(echo "${RUST_TARGET}" | tr '-' '_') && \
    UPPER_TARGET=$(echo "${RUST_TARGET_ENV}" | tr '[:lower:]' '[:upper:]') && \
    rustup target add "${RUST_TARGET}" && \
    { \
      echo "export RUST_TARGET=\"${RUST_TARGET}\""; \
      echo "export TOOLCHAIN=\"${TOOLCHAIN}\""; \
      echo "export CC_${RUST_TARGET_ENV}=\"${TOOLCHAIN}-gcc\""; \
      echo "export CXX_${RUST_TARGET_ENV}=\"${TOOLCHAIN}-g++\""; \
      echo "export AR_${RUST_TARGET_ENV}=\"${TOOLCHAIN}-ar\""; \
      echo "export CARGO_TARGET_${UPPER_TARGET}_LINKER=\"${TOOLCHAIN}-gcc\""; \
      echo "export BORING_BSSL_SYSROOT=\"/opt/cross-toolchain/${TOOLCHAIN}/sysroot\""; \
    } > /tmp/cross-env.sh

RUN cargo install cargo-chef --locked
WORKDIR /app

# Stage 2: Planner - Generate dependency recipe
FROM --platform=$BUILDPLATFORM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo chef prepare --recipe-path recipe.json

# Stage 3: Builder - Build dependencies then application
FROM --platform=$BUILDPLATFORM chef AS builder
ARG TARGETARCH
COPY --from=planner /app/recipe.json recipe.json
# Build dependencies (cached as long as recipe.json unchanged)
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=registry-$TARGETARCH \
    --mount=type=cache,target=/usr/local/cargo/git,id=git-$TARGETARCH \
    --mount=type=cache,target=/app/target,sharing=locked,id=target-$TARGETARCH \
    . /tmp/cross-env.sh && \
    cargo chef cook --release --target "$RUST_TARGET" --recipe-path recipe.json
# Build application and test binaries.
# Cache mount contents are NOT stored in image layers — we must copy
# artifacts to /app/out/ within this same RUN instruction.
# Use --message-format=json to extract exact binary paths; glob-based
# extraction breaks when stale artifacts accumulate in cache mounts.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=registry-$TARGETARCH \
    --mount=type=cache,target=/usr/local/cargo/git,id=git-$TARGETARCH \
    --mount=type=cache,target=/app/target,sharing=locked,id=target-$TARGETARCH \
    . /tmp/cross-env.sh && \
    set -e && \
    cargo build --release --target "$RUST_TARGET" --bin h3llo && \
    TUN_BIN=$(cargo test --test integration-container-tun --release \
        --target "$RUST_TARGET" --no-run \
        --message-format=json \
        | jq -r 'select(.target.name == "integration-container-tun") | .executable // empty') && \
    ROUTE_BIN=$(cargo test --test integration-container-route --release \
        --target "$RUST_TARGET" --no-run \
        --message-format=json \
        | jq -r 'select(.target.name == "integration-container-route") | .executable // empty') && \
    test -n "$TUN_BIN" && test -n "$ROUTE_BIN" && \
    mkdir -p /app/out && \
    cp "/app/target/${RUST_TARGET}/release/h3llo" /app/out/ && \
    "${TOOLCHAIN}-strip" /app/out/h3llo && \
    cp "$TUN_BIN" /app/out/integration-container-tun && \
    cp "$ROUTE_BIN" /app/out/integration-container-route && \
    "${TOOLCHAIN}-strip" /app/out/integration-container-tun && \
    "${TOOLCHAIN}-strip" /app/out/integration-container-route

# Stage 4: Runtime - Minimal Alpine production image (target platform)
# This stage uses TARGETPLATFORM implicitly — Alpine pulls the correct arch.
FROM alpine:3.21 AS runtime
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/out/h3llo /usr/local/bin/h3llo
RUN mkdir -p /etc/h3llo
WORKDIR /etc/h3llo
ENTRYPOINT ["/usr/local/bin/h3llo"]
CMD ["-c", "/etc/h3llo/config.yaml"]

# Stage 5: Test - Adds diagnostic tools for integration tests
FROM runtime AS test
RUN apk add --no-cache iproute2 iputils-ping iperf3
# Include pre-built test binaries for Container Test Pattern
COPY --from=builder /app/out/integration-container-tun /usr/local/bin/
COPY --from=builder /app/out/integration-container-route /usr/local/bin/
