# Multi-stage Dockerfile for h3llo BareUDP VPN
# Debian builder + Alpine runtime for static musl binaries
#
# Targets:
#   runtime (default) - Minimal Alpine production image
#   test              - Adds diagnostic tools for integration tests
#
# Usage:
#   docker build --target runtime -t h3llo:latest .
#   docker build --target test -t h3llo:test .

# Stage 1: Chef - Install cargo-chef with Debian (supports libclang dynamic loading)
FROM rust:slim-trixie AS chef

# Install boring-sys dependencies and curl for downloading musl toolchain
RUN apt-get update && apt-get install -y \
    curl \
    cmake make perl golang-go git \
    clang libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# Download musl cross-compilation toolchain from musl.cc (includes g++)
RUN curl -sSfL https://musl.cc/x86_64-linux-musl-cross.tgz | tar -xzf - -C /opt
ENV PATH="/opt/x86_64-linux-musl-cross/bin:$PATH"

# Add musl target
RUN rustup target add x86_64-unknown-linux-musl

# Configure compilers for musl target
ENV CC_x86_64_unknown_linux_musl=x86_64-linux-musl-gcc
ENV CXX_x86_64_unknown_linux_musl=x86_64-linux-musl-g++
ENV AR_x86_64_unknown_linux_musl=x86_64-linux-musl-ar
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-linux-musl-gcc

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
RUN cargo chef cook --release --target x86_64-unknown-linux-musl --recipe-path recipe.json
# Build application
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --target x86_64-unknown-linux-musl --bin h3llo && \
    strip /app/target/x86_64-unknown-linux-musl/release/h3llo

# Stage 4: Runtime - Minimal Alpine production image
FROM alpine:3.21 AS runtime
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/h3llo /usr/local/bin/h3llo
RUN mkdir -p /etc/h3llo
WORKDIR /etc/h3llo
ENTRYPOINT ["/usr/local/bin/h3llo"]
CMD ["-c", "/etc/h3llo/config.yaml"]

# Stage 5: Test - Adds diagnostic tools for integration tests
FROM runtime AS test
RUN apk add --no-cache iproute2 iputils-ping
