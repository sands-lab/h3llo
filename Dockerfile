# syntax=docker/dockerfile:1
# Multi-stage Dockerfile for h3llo BareUDP VPN (requires Docker Buildx)
# Debian builder + Alpine runtime for static musl binaries.
# Uses BuildKit cache mounts to persist cargo registry and compilation
# artifacts across builds on the same host.
#
# Targets:
#   runtime (default) - Minimal Alpine production image
#   test              - Adds diagnostic tools for integration tests
#
# Usage:
#   docker buildx build --target runtime -t h3llo:latest --load .
#   docker buildx build --target test -t h3llo:test --load .

# Stage 1: Toolchain - Debian with musl cross-compilation and boring-sys deps
FROM rust:slim-trixie AS toolchain

# Install boring-sys dependencies and curl/xz for downloading musl toolchain
RUN apt-get update && apt-get install -y \
    curl xz-utils \
    cmake make perl golang-go git \
    clang libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# Download musl cross-compilation toolchain from GitHub (auto-redirects to latest release)
# Source: https://github.com/cross-tools/musl-cross
RUN curl -sSfL https://github.com/cross-tools/musl-cross/releases/latest/download/x86_64-unknown-linux-musl.tar.xz \
    | tar -xJf - -C /opt
ENV PATH="/opt/x86_64-unknown-linux-musl/bin:$PATH"

# Add musl target
RUN rustup target add x86_64-unknown-linux-musl

# Configure compilers for musl target
ENV CC_x86_64_unknown_linux_musl=x86_64-unknown-linux-musl-gcc
ENV CXX_x86_64_unknown_linux_musl=x86_64-unknown-linux-musl-g++
ENV AR_x86_64_unknown_linux_musl=x86_64-unknown-linux-musl-ar
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-unknown-linux-musl-gcc

WORKDIR /app

# Stage 2: Builder - Build application and test binaries
FROM toolchain AS builder
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
# Cache mounts persist cargo registry/git and compilation artifacts across builds.
# Target dir is a cache mount so artifacts are NOT stored in image layers —
# we must copy them to /app/out/ within this same RUN instruction.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    --mount=type=cache,target=/app/target,sharing=locked \
    set -e && \
    cargo build --release --target x86_64-unknown-linux-musl --bin h3llo && \
    cargo test --test integration-container-tun --release --target x86_64-unknown-linux-musl --no-run && \
    cargo test --test integration-container-route --release --target x86_64-unknown-linux-musl --no-run && \
    mkdir -p /app/out && \
    cp /app/target/x86_64-unknown-linux-musl/release/h3llo /app/out/ && \
    strip /app/out/h3llo && \
    DEPS=/app/target/x86_64-unknown-linux-musl/release/deps && \
    test "$(find $DEPS -name 'integration_container_tun-*' -type f ! -name '*.d' | wc -l)" -eq 1 && \
    find $DEPS -name 'integration_container_tun-*' -type f ! -name '*.d' -exec cp {} /app/out/integration-container-tun \; && \
    test "$(find $DEPS -name 'integration_container_route-*' -type f ! -name '*.d' | wc -l)" -eq 1 && \
    find $DEPS -name 'integration_container_route-*' -type f ! -name '*.d' -exec cp {} /app/out/integration-container-route \; && \
    strip /app/out/*

# Stage 3: Runtime - Minimal Alpine production image
FROM alpine:3.21 AS runtime
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/out/h3llo /usr/local/bin/h3llo
RUN mkdir -p /etc/h3llo
WORKDIR /etc/h3llo
ENTRYPOINT ["/usr/local/bin/h3llo"]
CMD ["-c", "/etc/h3llo/config.yaml"]

# Stage 3a: Test - Adds diagnostic tools for integration tests
FROM runtime AS test
RUN apk add --no-cache iproute2 iputils-ping iperf3
# Include pre-built test binaries for Container Test Pattern
COPY --from=builder /app/out/integration-container-tun /usr/local/bin/
COPY --from=builder /app/out/integration-container-route /usr/local/bin/
