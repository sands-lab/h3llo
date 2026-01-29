# Multi-stage Dockerfile for h3llo BareUDP VPN
# Static musl build for maximum portability
#
# Targets:
#   runtime (default) - Minimal Alpine production image
#   test              - Adds diagnostic tools for integration tests
#
# Usage:
#   docker build --target runtime -t h3llo:latest .
#   docker build --target test -t h3llo:test .

# Stage 1: Chef - Install cargo-chef with Alpine musl
FROM rust:alpine AS chef
# boring-sys (BoringSSL) requires C++ compiler, cmake, perl, go
# bindgen requires libclang (clang-dev)
RUN apk add --no-cache musl-dev g++ cmake make perl go git clang-dev
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
RUN cargo build --release --bin h3llo && \
    strip /app/target/release/h3llo

# Stage 4: Runtime - Minimal Alpine production image
FROM alpine:3.21 AS runtime
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/target/release/h3llo /usr/local/bin/h3llo
RUN mkdir -p /etc/h3llo
WORKDIR /etc/h3llo
ENTRYPOINT ["/usr/local/bin/h3llo"]
CMD ["-c", "/etc/h3llo/config.yaml"]

# Stage 5: Test - Adds diagnostic tools for integration tests
FROM runtime AS test
RUN apk add --no-cache iproute2 iputils-ping
