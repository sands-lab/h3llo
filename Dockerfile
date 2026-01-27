# Multi-stage Dockerfile for h3llo BareUDP VPN
# Optimized with cargo-chef for dependency caching
#
# Targets:
#   runtime (default) - Minimal production image
#   test              - Adds ping/iproute2 for integration tests
#
# Usage:
#   docker build --target runtime -t h3llo:latest .
#   docker build --target test -t h3llo:test .

# Stage 1: Chef - Install cargo-chef and prepare recipe
# Using rust:trixie (Debian 13) for GLIBC 2.41 compatibility with CI runner (2.39)
FROM rust:trixie AS chef
RUN cargo install cargo-chef --locked
WORKDIR /app

# Stage 2: Planner - Generate dependency recipe
FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo chef prepare --recipe-path recipe.json

# Stage 3: Builder - Build dependencies then application
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Build dependencies (cached as long as recipe.json unchanged)
RUN cargo chef cook --release --recipe-path recipe.json
# Build application
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --bin h3llo

# Stage 4: Runtime - Minimal production image
# Debian Trixie (13) provides GLIBC 2.41, compatible with GitHub Actions ubuntu-latest (2.39).
# This allows test binaries compiled natively on CI to execute inside containers.
FROM debian:trixie-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/h3llo /usr/local/bin/h3llo
RUN mkdir -p /etc/h3llo
WORKDIR /etc/h3llo
ENTRYPOINT ["/usr/local/bin/h3llo"]
CMD ["-c", "/etc/h3llo/config.yaml"]

# Stage 5: Test - Adds network diagnostic tools for integration tests
FROM runtime AS test
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 iputils-ping && rm -rf /var/lib/apt/lists/*
