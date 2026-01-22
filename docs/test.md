# Testing Guide

Practical testing guide for h3llo BareUDP VPN. Audience: Rust developers who need quick, repeatable checks across unit tests, mocked components, and multi-node integration tests.

- Layered: unit → local component (mocked network) → Docker integration (testcontainers-rs).
- Decoupled: abstract transport via traits so business logic is mockable without quiche.
- Repeatable: commands and snippets are ready to adapt into your test suite or CI jobs.

## Local Unit Tests

- Run fast loops with cargo: `cargo test --lib --tests -- --nocapture` or narrow scope (`cargo test packet_handler`).
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
   docker build -t h3llo:test .
   ```

### Running Tests

```bash
# Run Docker integration tests
cargo test --test bareudp_e2e -- --ignored --nocapture
```

### Test Architecture

- testcontainers-rs manages container lifecycle automatically
- Containers run with `--privileged` for CAP_NET_ADMIN (TUN device access)
- Each test creates isolated containers with bind-mounted configs
- Cleanup is automatic when containers go out of scope

### Test Scenarios

1. **Two-node BareUDP tunnel**: Verifies bidirectional VPN connectivity between two containers
2. **Source IP filtering**: Verifies unauthorized sources are rejected
3. **MTU boundary checks**: Verifies MTU-fitting packets pass and oversized packets with DF are dropped

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
- Integration: `tests/config_integration.rs` loads valid/invalid YAML samples to assert validation behavior.
- Docker: `tests/bareudp_e2e.rs` multi-node BareUDP connectivity, source IP filtering, and MTU boundary checks via testcontainers-rs.
- Other platforms: TODO for macOS/Windows when platform-specific code is introduced.
