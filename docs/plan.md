# Development Plan

Iterative delivery of h3llo by building one module at a time, gating each step with tests, then composing modules into components and the full system.

## Principles and Gates

Guiding rules for the plan execution and progress updates.

- [x] Step 1: Implement one module at a time and gate progress with passing tests.
- [x] Step 2: Prefer unit and mocked component tests aligned with [docs/test.md](test.md).
- [x] Step 3: Keep module interfaces minimal and explicit to simplify composition.
- [x] Step 4: Keep progress visible by updating this plan when status changes.

## Module Order and Expected Tests

Primary build order with the minimum test coverage for each module.

- [x] Step 1: Implement config and validation: YAML load/validate, defaults, peer exclusivity; add unit tests for success/failure cases and merge rules.
- [x] Step 2: Implement DNS and socket binding: default-route probing, per-socket binding, single-resolver policy; add mocked tests for single/multiple answers, errors, and re-resolution.
- [x] Step 3: Implement TUN management: creation, address/MTU setup, read/write loops with backpressure; add loopback or mocked tests for enqueue/dequeue correctness.
- [x] Step 4: Implement internal routing (LPM): add/remove, longest-prefix match, atomic swaps; add unit tests for overlapping prefixes and disabled peers.
- [x] Step 5: Implement BareUDP transport: single resolution, source-IP filter, raw packet pass-through; add tests for allowed/blocked sources and multi-IP warning behavior.
- [x] Step 6: Implement system route sync: route_manager-based sync, idempotent replace, warning-on-failure; add mocked tests for command sequencing and error handling.
- [x] Step 7: Implement runtime orchestration (BareUDP-first): task lifecycle, structured errors, start/stop order for a BareUDP-only stack; add integration tests for clean startup/shutdown and restartability.
- [x] Step 8: Implement identity and auth: Bearer Token generation/validation for CONNECT-IP per RFC 6750; add unit tests for valid/invalid combinations and edge cases.
- [x] Step 9: Implement HTTP/3 transport: listen/dial with DATAGRAM, Context ID 0, reconnection and smooth handover; add loopback/component tests for send/receive and reconnect.
- [x] Step 10: Implement control plane (GET/POST/DELETE): snapshot export, peer replace/delete, trigger routing/transport refresh; add handler tests for auth, payload validation, and metrics exposition.
- [x] Step 11: Implement runtime orchestration (Hybrid): mix H3 and BareUDP; add integration tests for clean startup/shutdown and restartability with both transports.

## BareUDP VPN Delivery

Concrete implementation steps to ship a BareUDP-only VPN on top of the existing modules.

- [x] Step 1: Add a CLI entrypoint that loads config, initializes logging, and selects the BareUDP-only runtime.
- [x] Step 2: Validate `local.bare.listen` and `peers[].bare.endpoint` as `udp://host:port`, and parse into `SocketAddr`.
- [x] Step 3: Build a BareUDP orchestrator wiring TUN Rx/Tx, routing table, and per-peer UDP Tx queues.
- [x] Step 4: Refactor BareUDP Tx to allow destination updates or socket rebuilds when endpoints change.
- [x] Step 5: Wire `local.table` to system route sync using TUN addresses and `allowedIPs`.
- [x] Step 6: Add a metrics aggregation loop that periodically emits transport counters via `metrics_push_interval`.
- [x] Step 7: Add a two-node BareUDP integration test (static IP) plus MTU boundary checks.
- [x] Step 8: Document a BareUDP-only quick start in [docs/configuration.md](configuration.md) and [README.md](../README.md).

## Component Integration and Tests

Compose modules into higher-level components with focused integration tests.

- [x] Step 1: Assemble BareUDP data plane: TUN + LPM + BareUDP with source-IP filtering and single-resolution constraint.
- [x] Step 2: Align route sync: internal vs system route alignment with mocked platform commands.
- [x] Step 3: Exercise H3 data plane: TUN + LPM + HTTP/3 end-to-end (loopback/two-node local), reconnection under load.
- [ ] Step 4: Validate config + routing + control plane: repeated POSTs (idempotent/replace) and rollback-on-failure behavior.
- [x] Step 5: Extend hybrid routing: mixed H3/BareUDP peers, overlapping allowedIPs with longest-prefix selection and dynamic switches.

## System Integration Tests

Full end-to-end scenarios across multiple nodes.

- [x] Step 1: Run two-node BareUDP: static IP reachability, invalid source drop, MTU boundary checks.
- [ ] Step 2: Exercise two-node HTTP/3 end-to-end: ping/iperf (BareUDP + H3 iperf3 done), cert rotation, auth failures, path errors, reconnection.
- [ ] Step 3: Validate mixed mode: POST-driven transport/peer changes with zero-downtime goal and route drift checks.
- [ ] Step 4: Verify observability: structured logs and metrics hooks emit expected events under the above scenarios.
