# Testing Guide

Practical testing guide for h3llo. Audience: Rust developers who need quick, repeatable checks across unit tests, mocked components, and multi-node integration tests.

- Layered: unit → local component (mocked network) → Docker integration (testcontainers-rs) → E2E.
- Decoupled: user-level transports (BareUDP, H3) do not need to be mocked.
- Repeatable: commands and snippets are ready to adapt into your test suite or CI jobs.

## Directory Structure

```
src/
  *.rs          # Inline #[cfg(test)] unit & component tests
tests/
  integration/
    main.rs
    native/
      mod.rs
      common/
        mod.rs    # Shared test utilities (image checks, container helpers)
      dns.rs    # CoreDNS integration (requires Docker)
      route.rs  # Route sync orchestrator (Container Test Pattern)
      tun.rs    # TUN device orchestrator (Container Test Pattern)
    container/
      mod.rs
      route.rs  # Standalone route test binary (harness = false)
      tun.rs    # Standalone TUN test binary (harness = false)
  e2e/
    main.rs
    common.rs     # Shared E2E utilities (Docker helpers, iperf3 parsing)
    bareudp.rs    # BareUDP E2E (requires Docker + privileged)
    h3.rs         # HTTP/3 E2E (requires Docker + privileged)
    multipath.rs  # Multipath E2E: dual-subnet mixed BareUDP + H3 (requires Docker + privileged)
    throughput.rs # iperf3 throughput tests (BareUDP + H3)
```

## Local Unit Tests

- Run fast loops with cargo: `cargo test --lib -- --nocapture` or narrow scope (`cargo test packet_handler`).
- User-level transports (BareUDP, H3) do not need to be mocked; test directly against production code.

## Local Component Tests (mocked network requests)

Single-process component checks that simulate QUIC/H3 without real sockets.
- Goal: validate routing/state machines/retries across modules while keeping test speed high.
- Approach: use in-memory channels or fake endpoints that share the same trait surface as production.

## Test Utilities Feature

The `test-utils` feature exposes internal testing utilities for integration tests:

```rust
// In Cargo.toml dev-dependencies or test file
// [dev-dependencies]
// h3llo = { path = ".", features = ["test-utils"] }

use h3llo::test_utils::{memory_tun, memory_tun_with_errors, MemoryTunRx, MemoryTunTx, FakeRouteProbe};

let (rx, tx, inject_tx, output_rx) = memory_tun("test0", 1500);
// inject_tx: send packets into TUN RX (simulates incoming)
// output_rx: receive packets from TUN TX (captures outgoing)

// Fault-injection variant: pre-configure send errors for testing error handling
let (rx, tx, inject_tx, output_rx) = memory_tun_with_errors("test0", 1500, vec![std::io::ErrorKind::WouldBlock]);

// Route probe test doubles:
let probe = FakeRouteProbe::noop();      // Returns empty interfaces (most common)
let probe = FakeRouteProbe::ok(vec!["eth0".to_string()]); // Returns specific interfaces
let probe = FakeRouteProbe::error(RouteProbeError::Probe("boom".into())); // Returns error
```

## Docker Integration Tests (testcontainers-rs)

Multi-node BareUDP testing using Docker containers with real TUN devices.

### Prerequisites

1. Docker daemon running
2. Docker Buildx installed (`docker buildx version` to verify)
3. QEMU user-mode emulation registered (for multi-arch builds):
   ```bash
   docker run --privileged --rm tonistiigi/binfmt --install all
   ```
4. Build the test image:
   ```bash
   docker buildx build --target test -t h3llo:test --load .
   ```
   **Rebuild required**: The test image embeds compiled h3llo and test binaries.
   You must rebuild after any change to `src/`, `tests/integration/container/`,
   `Cargo.toml`, or `Cargo.lock`.

   For a specific platform (cross-compilation):
   ```bash
   docker buildx build --platform linux/arm64 --target runtime -t h3llo:arm64 --load .
   ```

### Running Tests

```bash
# Run E2E tests (BareUDP multi-node, requires privileged containers)
cargo test --test e2e -- --ignored --nocapture

# Run integration tests (DNS + TUN container tests, requires Docker)
cargo test --test integration -- --ignored --nocapture
```

### Side-Effect Classification

Side effects requiring containerization:
- Creating TUN interfaces
- Modifying routing tables
- Operations requiring CAP_NET_ADMIN or elevated privileges

NOT side effects (safe for inline tests):
- Binding ephemeral localhost ports (`127.0.0.1:0`)
- In-memory channel communication
- Spawning async tasks

### Test Architecture

- testcontainers-rs manages container lifecycle automatically
- Containers run with `--privileged` for CAP_NET_ADMIN (TUN device access)
- Each test creates isolated containers with bind-mounted configs
- Cleanup is automatic when containers go out of scope

#### Concurrency Safety

Each E2E test creates a `TestContext` that generates a unique 8-hex suffix,
creates a dedicated Docker network (`h3llo-e2e-{suffix}`), and derives
globally-unique container names (`{role}-{suffix}`). Config files are
dynamically generated with FQDNs matching the unique container names.
This ensures tests are safe to run in parallel — both within a single
`cargo test` invocation and across concurrent CI runs. The Docker network
is cleaned up when `TestContext` is dropped.

### Container Test Logging Requirements

All Docker container tests MUST output container logs on failure:

1. **Container binary tests** (Container Test Pattern): Capture `stderr_to_vec()` before checking exit code; print on non-zero exit
2. **Container service tests** (e.g., CoreDNS): Include error context in panic messages when container startup fails
3. **E2E multi-node tests**: Capture both stdout and stderr from exec commands; print on assertion failure

This ensures CI failures are debuggable without manual reproduction.

### Shared Test Utilities

The `tests/integration/native/common/` module provides utilities shared across Container Test Pattern tests:

- `ensure_image_exists(image, tag)` - Check for Docker image before test
- `get_container_exit_code(container_id)` - Retrieve container exit code via docker inspect
- `TEST_IMAGE`, `TEST_TAG` - Default image constants ("h3llo", "test")
- `CONTAINER_TUN_BINARY`, `CONTAINER_ROUTE_BINARY` - Container paths for embedded test binaries

### E2E Test Scenarios (`tests/e2e/bareudp.rs`)

1. **Two-node BareUDP tunnel**: Verifies bidirectional VPN connectivity between two containers
2. **Source IP filtering**: Verifies unauthorized sources are rejected
3. **MTU boundary checks**: Verifies MTU-fitting packets pass and oversized packets with DF are dropped

### E2E Test Scenarios (`tests/e2e/h3.rs`)

1. **Two-node H3 tunnel**: Verifies bidirectional VPN connectivity over HTTP/3 with self-signed certificates

### E2E Test Scenarios (`tests/e2e/throughput.rs`)

1. **BareUDP TCP throughput**: Runs iperf3 through BareUDP tunnel, verifies measurable TCP throughput via JSON output parsing
2. **H3 TCP throughput**: Runs iperf3 through HTTP/3 tunnel with self-signed certificates, verifies measurable TCP throughput

Prerequisites: `iperf3` is included in the Docker test image. Run with:
```bash
cargo test --test e2e -- --ignored --nocapture throughput
```

### E2E Test Scenarios (`tests/e2e/multipath.rs`)

1. **Dual-subnet mixed transport**: Verifies two nodes routing 10.0.0.0/24 through BareUDP and 10.0.1.0/24 through HTTP/3 concurrently, with bidirectional ping validation.

### E2E Test Scenarios (`tests/e2e/forwarding.rs`)

1. **Three-node BareUDP forwarding**: Verifies userspace L3 forwarding through a relay node. Node A (10.0.0.1) pings Node C (10.0.0.3) via relay Node B (10.0.0.2), exercising the router actor's `handle_transport_batch` forwarding path with LPM routing and TTL decrement. Bidirectional forwarding (A→C, C→A) and direct peer connectivity verified as preconditions.

### Integration Test Scenarios (`tests/integration/native/dns.rs`)

DNS resolver validation against a containerized CoreDNS server with deterministic zone data.

- CoreDNS container with `file` plugin serves RFC-style zone with known A/AAAA records
- DnsResolver spawned in-process via port-mapped UDP
- No TUN, BareUDP, or CAP_NET_ADMIN required
- Test scenarios: single A, multi-record, AAAA-only, NXDOMAIN, timeout

#### Concurrency Safety

Each test creates its own `tempfile::tempdir()` for CoreDNS configuration and starts
an independent CoreDNS container with a unique port mapping. This design ensures tests
are safe to run in parallel (`cargo test` default behavior) without temp-dir collisions
or port conflicts.

### Container Test Pattern

When tests with real side effects are needed:
1. Write test as standalone binary in `tests/integration/container/`
2. Add `[[test]]` entry with `harness = false` in Cargo.toml
3. Test binaries are built into the Docker `test` image during `docker buildx build`
4. Native orchestrator in `tests/integration/native/` runs the pre-built binary
5. Uses `WaitFor::Exit` to wait for container exit and verify exit code

#### Static Binary Injection

Container test binaries are built inside Docker with the appropriate musl target to produce
fully static executables. Static musl binaries run on any Linux distribution without
runtime library dependencies, eliminating GLIBC version compatibility concerns.

Supported cross-compilation targets:
- `x86_64-unknown-linux-musl` (linux/amd64)
- `aarch64-unknown-linux-musl` (linux/arm64)
- `riscv64gc-unknown-linux-musl` (linux/riscv64)

The Dockerfile automatically selects the correct musl-cross toolchain from
[cross-tools/musl-cross](https://github.com/cross-tools/musl-cross) based on
the Docker `TARGETARCH` build argument.

The global allocator is set to mimalloc for musl builds to avoid potential performance
issues with musl's default allocator in multi-threaded workloads.

#### TUN Device Tests (`integration-container-tun`)

Container binary: `tests/integration/container/tun.rs`
Orchestrator: `tests/integration/native/tun.rs`

Verifies TUN device creation, multi-address assignment (IPv4+IPv6), MTU
configuration, and actual data transmission (send/receive) using
`h3llo::tun::make_tun()` inside a privileged container.

Data-path test uses a userspace ICMP echo responder:
1. Creates a TUN device via `make_tun()` and routes a remote IP through it
2. Spawns an async task that reads ICMP echo requests via `TunRx::recv_batch()`
3. Crafts ICMP echo replies (swap IPs, fix checksums) and writes them back via `TunTx::send_batch()`
4. Runs `ping` targeting the routed address
5. Successful ping confirms bidirectional TUN send/receive works

```bash
# Build test image with embedded binaries
docker buildx build --target test -t h3llo:test --load .

# Run TUN integration tests
cargo test --test integration -- tun --ignored --nocapture
```

#### Route Sync Tests (`integration-container-route`)

Container binary: `tests/integration/container/route.rs`
Orchestrator: `tests/integration/native/route.rs`

Verifies `sync_tun_routes` with real `AsyncRouteManager` (netlink API) inside
a privileged container. Creates dummy interfaces and performs binary-internal
verification via `handle.list()`.

Scenarios:
- **basic**: Installs routes on dummy0, verifies via kernel listing, then cleans up
- **default_split**: Verifies `0.0.0.0/0` is split into `0.0.0.0/1` + `128.0.0.0/1`

```bash
# Build test image with embedded binaries
docker buildx build --target test -t h3llo:test --load .

# Run route integration tests
cargo test --test integration -- route --ignored --nocapture
```

### Fault Injection

Inside containers, use `docker exec` or testcontainers' `exec()` API:
```bash
# Simulate link failure
docker exec <container> ip link set dev eth0 down

# Simulate recovery
docker exec <container> ip link set dev eth0 up
```

## SSL/TLS Certificates

Use on-the-fly self-signed certificates in tests to exercise TLS without external CA setup.
- Generation: use a Rust library (e.g., `rcgen`) to create short-lived certs at runtime; clean up after tests.
- Server config: point `cert`/`key` to generated files for H3; Bare UDP does not need certificates.
- Client config: prefer loading the test CA/cert; if unavailable, set `insecure = true` only for tests and still enforce hostname checks where possible.
- Hot reload: atomically replace both credential files, verify that a new connection trusts only the replacement certificate, and confirm an established connection remains open. Also replace only one half of the pair first to verify that mismatch validation retains the active certificate and recovers after the matching file arrives.

## Current Tests

- Linux CI: `cargo fmt -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test`, Docker integration tests.
- Unit: `src/config.rs` tests for defaults, H3/API config validation, peer transport exclusivity.
- Unit: `src/test_support/tokio_quiche_h3.rs` (test-only) tests for datagram encoding, error display, CONNECT-IP header validation, and listener spawn/shutdown.
- Unit: `src/h3session.rs` tests for QSI encode/decode, ConnectIpDatagramCodec framing (prepend/strip/roundtrip, rejection paths), ConnectFailure actor reason mapping, and CONNECT-IP constant verification.
- Unit: `src/h3engine.rs` tests for quiche transport config creation (valid and invalid CC), LoopExit result conversion, EngineMeta recv_info construction, and RunState initialization.
- Unit: `src/h3dialer.rs` tests for DialError display, From<ConnectFailure> conversion, and client quiche config validation (bad CA path, insecure mode CA bypass, default verify_peer). Integration tests for h3dialer client against the legacy `tokio_quiche_h3` test server (handshake, auth rejection, C2S/S2C/bidirectional datagrams, shutdown, trusted CA validation, untrusted cert rejection).
- Unit/integration: `src/h3listener.rs` tests ServerError display, server header/auth validation, watcher event filtering, initial certificate rejection, repeated credential replacement, mismatched certificate/private-key rejection and recovery, and preservation of established connections. Protocol coverage exercises the dispatcher against the legacy `tokio_quiche_h3` client fixture and `h3dialer.rs` client (handshake, auth rejection, C2S/S2C/bidirectional datagrams, and shutdown).
- Unit: `src/auth.rs` tests for Bearer Token generation and validation.
- Unit: `src/dns.rs` real-network DNS resolver tests.
- Unit: `src/bare.rs` real-network BareUDP tests.
- Unit: `src/orch.rs` tests for peer management, DNS snapshot handling, config updates, connection pruning, and routing refresh.
- Unit: `src/route.rs` tests for route sync logic with mock route managers (add/remove/split/dedup).
- Unit: `src/tun.rs` tests for routing table operations, memory TUN send/receive, and buffer allocation.
- Unit: `src/bind.rs` tests for UDP socket creation, route probing, and interface binding.
- Unit: `src/api.rs` tests for metrics encoding and snapshot collection.
- Unit: `src/actor.rs` tests for actor error classification and display formatting.
- Unit: `src/router.rs` tests for LPM routing table construction, TTL decrement with checksum update, batch splitting by destination, forwarding to peer and TUN, and drop reason classification (no-route, invalid IP version, TTL-expired, channel-closed).
- Unit: `src/udp.rs` tests for UDP socket sharing (Arc<UdpSocket>), RX source address tagging, TX destination delivery, GSO batch sending, mixed-size batches, and graceful shutdown on channel close.
- Unit: `src/metrics.rs` tests for PktCounters batch recording, single-packet recording, saturation arithmetic, multi-batch accumulation, CongestionStats recording and saturation, transport metrics logging with zero/nonzero drop counts, and Counters::send_and_record with success, channel-closed, and queue-full backpressure paths.
- Unit: `src/helpers.rs` tests for IP packet destination extraction and retry logic.
- Docker E2E: `tests/e2e/bareudp.rs` multi-node BareUDP connectivity, source IP filtering, and MTU boundary checks via testcontainers-rs.
- Docker E2E: `tests/e2e/h3.rs` multi-node HTTP/3 connectivity via testcontainers-rs.
- Docker E2E: `tests/e2e/multipath.rs` dual-subnet mixed transport (BareUDP + HTTP/3) via testcontainers-rs.
- Docker E2E: `tests/e2e/throughput.rs` iperf3 TCP throughput tests for BareUDP and HTTP/3 tunnels.
- Docker E2E: `tests/e2e/forwarding.rs` three-node BareUDP userspace forwarding via relay node.
- Docker Integration: `tests/integration/native/dns.rs` DNS resolver integration tests against CoreDNS container.
- Docker Integration: `tests/integration/native/tun.rs` TUN device creation and addressing via Container Test Pattern.
- Docker Integration: `tests/integration/native/route.rs` Route sync with real netlink API via Container Test Pattern.
- Other platforms: TODO for macOS/Windows when platform-specific code is introduced.

## WireGuard Throughput Baseline

Manual benchmark that measures WireGuard kernel-module throughput for comparison with h3llo tunnel performance. Uses network namespaces (no Docker overhead) following [WireGuard's own testing methodology](https://git.zx2c4.com/wireguard-linux/tree/tools/testing/selftests/wireguard/netns.sh).

### Prerequisites

- Linux host with WireGuard kernel module loaded (`modprobe wireguard`)
- `wg`, `iperf3`, `ip`, and `ping` commands available
- Root privileges (for network namespace and WireGuard interface creation)

### Running

```bash
sudo ./scripts/bench-wireguard.sh

# Pass extra iperf3 client flags (e.g., UDP mode, longer duration, JSON output):
sudo ./scripts/bench-wireguard.sh -t 30
sudo ./scripts/bench-wireguard.sh -u -b 1G
sudo ./scripts/bench-wireguard.sh -J          # JSON output for programmatic use
```

This benchmark is for manual comparison only and is NOT part of CI.
