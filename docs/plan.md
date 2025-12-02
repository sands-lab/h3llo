# Development Plan

Iterative delivery of h3llo by building one module at a time, gating each step with tests, then composing modules into components and finally the full system.

## Principles and Gates
- Sequence: implement one module, add/update its tests, run them, and proceed only when green.
- Tests first: favor fast unit and mocked component tests; align with docs/test.md’s layered approach.
- Interfaces: each module exposes clear interfaces to keep later composition minimal.
- Progress logging: as you move through the plan, promptly record the current completion status here to keep progress visible.

## Module Order and Expected Tests
- Config and validation: YAML load/validate, defaults, peer exclusivity; unit tests for success/failure cases and merge rules.
- DNS and socket binding: default-route probing, per-socket binding, single-resolver policy; mocked tests for single/multiple IP answers, errors, and re-resolution.
- TUN management: creation, address/MTU setup, read/write loops with backpressure; loopback/mocked tests for enqueue/dequeue correctness.
- Internal routing (LPM): add/remove, longest-prefix match, atomic swaps; unit tests for overlapping prefixes and disabled peers.
- BareUDP transport: single resolution, source-IP filter, raw packet pass-through; tests for allowed/blocked sources and multi-IP panic behavior.
- System route sync: platform command wrapper, idempotent replace, warning-on-failure; mocked tests for command sequencing and error handling.
- Runtime orchestration (BareUDP-first): task lifecycle, structured errors, start/stop order for a BareUDP-only stack; integration tests for clean startup/shutdown and restartability.
- Identity and auth: Basic Auth generation/validation (CONNECT vs GET/POST pairs); unit tests for valid/invalid combinations and edge cases.
- HTTP/3 transport: listen/dial with DATAGRAM, Context ID 0, reconnection and smooth handover; loopback/component tests for send/receive and reconnect.
- Control plane (GET/POST): snapshot export, partial peer merge, trigger routing/transport refresh; handler tests for auth, payload validation, and `null` clearing.
- Runtime orchestration (Hybrid): extend orchestration to mix H3 and BareUDP; integration tests for clean startup/shutdown and restartability with both transports.

## Component Integration and Tests
- BareUDP data plane: TUN + LPM + BareUDP with source-IP filtering and single-resolution constraint.
- Route sync: internal vs system route alignment with mocked platform commands.
- H3 data plane: TUN + LPM + HTTP/3 end-to-end (loopback/two-node local), reconnection under load.
- Config + Routing + Control-plane: repeated POSTs (idempotent/merge), rollback-on-failure behavior.
- Hybrid routing: mixed H3/BareUDP peers, overlapping allowedIPs with longest-prefix selection and dynamic switches.

## System Integration Tests
- Two-node BareUDP: static IP reachability, invalid source drop, MTU boundary checks.
- Two-node HTTP/3 end-to-end: ping/iperf, cert rotation, auth failures, path errors, reconnection.
- Mixed mode: POST-driven transport/peer changes with zero-downtime goal and route drift checks.
- Observability: structured logs and metrics hooks emit expected events under the above scenarios.

## Progress Log
- Config and validation: crate scaffolded with YAML parsing, defaults, and validation checks; unit and integration tests added; Linux CI workflow configured.
- Plan reordered to deliver a BareUDP-only VPN first, then add HTTP/3 features.
- TUN management: implemented tun-rs based creation, address/MTU setup, read/write loops with backpressure, oversize drop counting, periodic metrics events, and unit tests with in-memory doubles.
