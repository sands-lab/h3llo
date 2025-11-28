# Testing Guide

Practical testing guide for tokio-quiche based services. Audience: Rust developers who need quick, repeatable checks across unit, mocked components, multi-node component tests, and full end-to-end scenarios. Emphasis on executable examples over QUIC theory.

- Layered: unit → local component (mocked network) → multi-node component (testcontainers + faults) → multi-node end-to-end.
- Decoupled: abstract transport via traits so business logic is mockable without quiche.
- Repeatable: commands and snippets are ready to adapt into your test suite or CI jobs.

## Local Unit Tests

- Run fast loops with cargo: `cargo test --lib --tests -- --nocapture` or narrow scope (`cargo test packet_handler`).
- Decouple transport: define a trait for H3/QUIC operations; production uses tokio-quiche, tests use in-memory mocks.

## Local Component Tests (mocked network requests)

Single-process component checks that simulate QUIC/H3 without real sockets.
- Goal: validate routing/state machines/retries across modules while keeping test speed high.
- Approach: use in-memory channels or fake endpoints that share the same trait surface as production.

## Multi-node Component Tests (testcontainers-rs)

Use testcontainers-rs to launch multiple containers on a custom Docker network with static IPs, treating each container as a node. Inject network and process faults inside tests.
- Network setup: create a user-defined network with a fixed subnet; connect containers with `--ip` to guarantee stable addresses.
- Lifecycle: create network → start containers → connect network/IP → run probes → clean up.
- Fault injection: inside containers, toggle links via `ip link set dev eth0 down/up`; simulate crashes with `docker stop` and restarts with `docker start`.

Practical flow (sketch; adapt to your testcontainers-rs usage):
- Ensure the custom network exists (one-time setup in CI) with a fixed subnet such as `172.30.0.0/24`.
- Start containers from the h3llo image; assign deterministic names.
- Connect each container to the network with the intended static IPs.
- Inside the test, run health probes between nodes over H3/Bare UDP.
- Inject faults by executing inside containers: `ip link set dev eth0 down/up` for transient loss; `docker stop/start <container>` for crash/restart.

## Multi-node End-to-End Tests

Exercise full data and control paths across multiple nodes.
- H3 over QUIC: verify HTTP/3 request/response and HEADERS + DATAGRAM interplay.
- Bare UDP: verify custom QUIC/Bare UDP payload flows (one-way or bidirectional).
- Hybrid: configure over H3, push bulk data over Bare UDP, and assert fallback/retry behavior.

## SSL/TLS Certificates

Use on-the-fly self-signed certificates in tests to exercise TLS without external CA setup.
- Generation: use a Rust library (e.g., `rcgen`) to create short-lived certs at runtime; clean up after tests.
- Server config: point `cert`/`key` to generated files for H3; Bare UDP does not need certificates.
- Client config: prefer loading the test CA/cert; if unavailable, set `insecure = true` only for tests and still enforce hostname checks where possible.
