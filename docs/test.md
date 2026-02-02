# Testing Guide

Practical testing guide for h3llo BareUDP VPN. Audience: Rust developers who need quick, repeatable checks across unit tests, mocked components, and multi-node integration tests.

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
      dns.rs    # CoreDNS integration (requires Docker)
      route.rs  # Route sync orchestrator (Container Test Pattern)
      tun.rs    # TUN device orchestrator (Container Test Pattern)
    container/
      mod.rs
      route.rs  # Standalone route test binary (harness = false)
      tun.rs    # Standalone TUN test binary (harness = false)
  e2e/
    main.rs
    bareudp.rs  # Full system E2E (requires Docker + privileged)
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

use h3llo::test_utils::{memory_tun, MemoryTunRx, MemoryTunTx, FakeRouteProbe};

let (rx, tx, inject_tx, output_rx) = memory_tun("test0", 1500);
// inject_tx: send packets into TUN RX (simulates incoming)
// output_rx: receive packets from TUN TX (captures outgoing)

// Route probe test doubles:
let probe = FakeRouteProbe::noop();      // Returns empty interfaces (most common)
let probe = FakeRouteProbe::ok(vec!["eth0".to_string()]); // Returns specific interfaces
let probe = FakeRouteProbe::error(RouteProbeError::Probe("boom".into())); // Returns error
```

## Docker Integration Tests (testcontainers-rs)

Multi-node BareUDP testing using Docker containers with real TUN devices.

### Prerequisites

1. Docker daemon running
2. Build the test image:
   ```bash
   docker build --target test -t h3llo:test .
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
3. Test binaries are built into the Docker `test` image during `docker build`
4. Native orchestrator in `tests/integration/native/` runs the pre-built binary
5. Uses `WaitFor::Exit` to wait for container exit and verify exit code

#### Static Binary Injection

Container test binaries are built inside Docker with `--target x86_64-unknown-linux-musl` to produce
fully static executables. Static musl binaries run on any Linux distribution without
runtime library dependencies, eliminating GLIBC version compatibility concerns.

The global allocator is set to mimalloc for musl builds to avoid potential performance
issues with musl's default allocator in multi-threaded workloads.

#### TUN Device Tests (`integration-container-tun`)

Container binary: `tests/integration/container/tun.rs`
Orchestrator: `tests/integration/native/tun.rs`

Verifies TUN device creation, multi-address assignment (IPv4+IPv6), MTU
configuration, and actual data transmission (send/receive) using
`h3llo::tun::from_config()` inside a privileged container.

Data-path test uses a userspace ICMP echo responder:
1. Creates a TUN device via `from_config()` and routes a remote IP through it
2. Spawns an async task that reads ICMP echo requests via `TunRx::recv()`
3. Crafts ICMP echo replies (swap IPs, fix checksums) and writes them back via `TunTx::send()`
4. Runs `ping` targeting the routed address
5. Successful ping confirms bidirectional TUN send/receive works

```bash
# Build test image with embedded binaries
docker build --target test -t h3llo:test .

# Run TUN integration tests
cargo test --test integration -- tun --ignored --nocapture
```

#### Route Sync Tests (`integration-container-route`)

Container binary: `tests/integration/container/route.rs`
Orchestrator: `tests/integration/native/route.rs`

Verifies `sync_tun_routes` with real `RouteManagerHandle` (netlink API) inside
a privileged container. Creates dummy interfaces and performs binary-internal
verification via `handle.list()`.

Scenarios:
- **basic**: Installs routes on dummy0, verifies via kernel listing, then cleans up
- **default_split**: Verifies `0.0.0.0/0` is split into `0.0.0.0/1` + `128.0.0.0/1`

```bash
# Build test image with embedded binaries
docker build --target test -t h3llo:test .

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

## Current Tests

- Linux CI: `cargo fmt -- --check`, `cargo clippy -- -D warnings`, `cargo test`, Docker integration tests.
- Unit: `src/config.rs` tests for defaults, admin/listener coupling, peer transport exclusivity.
- Unit: `src/h3.rs` tests for datagram encoding, error display, CONNECT-IP header validation, and listener spawn/shutdown.
- Unit: `src/auth.rs` tests for Basic Auth generation and validation.
- Unit: `src/dns.rs` real-network DNS resolver tests.
- Unit: `src/bare.rs` real-network BareUDP tests.
- Docker E2E: `tests/e2e/bareudp.rs` multi-node BareUDP connectivity, source IP filtering, and MTU boundary checks via testcontainers-rs.
- Docker Integration: `tests/integration/native/dns.rs` DNS resolver integration tests against CoreDNS container.
- Docker Integration: `tests/integration/native/tun.rs` TUN device creation and addressing via Container Test Pattern.
- Docker Integration: `tests/integration/native/route.rs` Route sync with real netlink API via Container Test Pattern.
- Other platforms: TODO for macOS/Windows when platform-specific code is introduced.
