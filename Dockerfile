# syntax=docker/dockerfile:1
# Packaging-only Dockerfile for h3llo BareUDP VPN.
#
# Build static musl binaries on the host first, then expose their directory as
# the named `binaries` build context:
#
#   MUSL_CROSS_VERSION=20250929 scripts/build-musl.sh amd64 .tmp/musl-amd64
#   docker buildx build --build-context binaries=.tmp/musl-amd64 \
#     --platform linux/amd64 --target runtime -t h3llo:latest --load .
#
# Supported platforms: linux/amd64, linux/arm64, linux/riscv64
#
# Targets:
#   runtime (default) - Minimal Alpine production image
#   export            - Bare binary for release asset extraction
#   test              - Adds diagnostic tools and container test binaries

FROM alpine:3.21 AS runtime
RUN apk add --no-cache ca-certificates
COPY --from=binaries /h3llo /usr/local/bin/h3llo
WORKDIR /etc/h3llo
# Eagerly return freed pages to the OS. Without this, mimalloc retains
# committed segments after freeing large (>=64KB) allocations, causing
# RSS to be ~10x the actual live heap. See docs/memory-leak-investigation.md.
ENV MIMALLOC_PURGE_DELAY=0
ENTRYPOINT ["/usr/local/bin/h3llo"]
CMD ["-c", "/etc/h3llo/config.yaml"]

FROM scratch AS export
COPY --from=binaries /h3llo /h3llo

FROM runtime AS test
RUN apk add --no-cache iproute2 iputils-ping iperf3
COPY --from=binaries /integration-container-tun /usr/local/bin/
COPY --from=binaries /integration-container-route /usr/local/bin/
