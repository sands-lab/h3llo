# Testing Guide

Practical testing guide for h3llo BareUDP VPN. Audience: Rust developers who need quick, repeatable checks across unit tests, mocked components, and multi-node integration tests.

- Layered: unit → local component (mocked network) → Docker integration (testcontainers-rs) → E2E.
- Decoupled: abstract transport via traits so business logic is mockable without quiche.
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
    container/
      mod.rs    # Future: standalone test binaries for Docker
  e2e/
    main.rs
    bareudp.rs  # Full system E2E (requires Docker + privileged)
```

## Local Unit Tests

- Run fast loops with cargo: `cargo test --lib -- --nocapture` or narrow scope (`cargo test packet_handler`).
- Decouple transport: define a trait for H3/QUIC operations; production uses tokio-quiche, tests use in-memory mocks.

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

use h3llo::test_utils::{memory_tun, MemoryTunRx, MemoryTunTx};

let (rx, tx, inject_tx, output_rx) = memory_tun("test0", 1500);
// inject_tx: send packets into TUN RX (simulates incoming)
// output_rx: receive packets from TUN TX (captures outgoing)
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

# Run integration tests (DNS resolver, requires Docker)
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

### Container Test Pattern (Future)

When tests with real side effects are needed:
1. Write test as standalone binary in `tests/integration/container/`
2. Add `[[test]]` entry with `harness = false` in Cargo.toml
3. Native orchestrator in `tests/integration/native/` copies binary into Docker
4. Uses testcontainers `with_copy_to` for binary injection

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
- Unit: `src/config.rs` tests for defaults, admin/listener coupling, peer transport exclusivity, BareUDP endpoint requirement, and allowed IP presence.
- Docker E2E: `tests/e2e/bareudp.rs` multi-node BareUDP connectivity, source IP filtering, and MTU boundary checks via testcontainers-rs.
- Docker Integration: `tests/integration/native/dns.rs` DNS resolver integration tests against CoreDNS container.
- Other platforms: TODO for macOS/Windows when platform-specific code is introduced.
