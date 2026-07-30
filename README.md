# h3llo: HTTP/3-based Low-latency Overlay

[![CI](https://github.com/Tonny-Gu/h3llo/actions/workflows/ci.yml/badge.svg)](https://github.com/Tonny-Gu/h3llo/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Tonny-Gu/h3llo/graph/badge.svg?token=B06V3MZ768)](https://codecov.io/gh/Tonny-Gu/h3llo)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

h3llo is a lightweight overlay network that rides on standard HTTP/3 (MASQUE/CONNECT-IP, [RFC 9484](https://datatracker.ietf.org/doc/html/rfc9484)) with an optional BareUDP fast path. It aims for WireGuard-like latency, flexible topologies, and zero-downtime reconfiguration.

## Feature Highlights

- Low-latency overlay: WireGuard-like performance with symmetric or asymmetric peer layouts.
- Zero-downtime updates: atomic peer/routing refresh without disrupting active traffic.
- Automatic TLS rotation: certificate and private-key changes apply to new H3 connections without restarting the listener or closing established connections.
- Two protocols: encrypted HTTP/3 by default; BareUDP as an opt-in, high-throughput plaintext path for trusted networks.
- Routing aware: longest-prefix routing per peer; optional system route updates.
- Multi-path: route different subnets through different peers; DNS multi-answer builds multiple connections per peer for automatic failover.

## Quick Start

Below is a minimal two-node example. If you know `wg-quick`, the structure should feel familiar. Provide valid QUIC/TLS assets for `cert`/`key` (self-signed is fine if both peers trust the same CA); see docs for certificate options.

```yaml
# Configuration on node1
local:
  h3:
    listen: https://[::]:443/path
    cert: ./cert.pem
    key: ./key.pem
  tun:
    ifname: h3llo0
    addrs:
      - 192.168.180.1/24
peers:
- id: example-node-2
  h3:
    token: example-token-12ch
  tun:
    allowed_ips:
      - 192.168.180.2/32
```
```yaml
# Configuration on node2
local:
  tun:
    ifname: h3llo0
    addrs:
      - 192.168.180.2/24
peers:
- id: example-node-1
  h3:
    token: example-token-12ch
    endpoint: https://node1.example.com:443/path
  tun:
    allowed_ips:
      - 192.168.180.1/32
```

Save the configuration as `host/config.yaml`, then start the h3llo container:

```bash
docker run -d --name h3llo --restart always --network host --cap-add NET_ADMIN --device /dev/net/tun -v host/config.yaml:/etc/h3llo/config.yaml nekonuts/h3llo
```

Multi-architecture images are available for `linux/amd64`, `linux/arm64`, and `linux/riscv64`. Docker automatically pulls the correct image for your platform.

## Configuration Overview

High-level connection/auth/routing summary; see [docs/protocol.md](docs/protocol.md) for auth/transport semantics and [docs/internals.md](docs/internals.md) for runtime behavior.

### Architecture

- Client/server-style: One side only listens (`listen`); the other only dials via `endpoint`. Suitable for hub-and-spoke.
- Peer-to-peer: Both sides listen and dial each other for symmetry; connection details live in [docs/internals.md](docs/internals.md).

### Authentication and Security

- Identity: every peer needs a unique `id` (non-empty).
- Bearer Token auth for CONNECT uses `Authorization: Bearer <token>` where token is `peers[target].h3.token`; the server matches the token against its `peers[].h3.token` collection to identify the peer. Every HTTP/3 peer entry must set `h3.token` (>= 12 chars) even when `endpoint` is absent, and tokens may differ per peer/direction. Full rules live in [docs/protocol.md](docs/protocol.md). QUIC/TLS certificates are required for HTTP/3.
- Management API: an optional localhost-bound HTTP/1.1 server (`local.api`) for runtime peer configuration. See [docs/protocol.md](docs/protocol.md) for endpoint details.

### Routing

- System routes: optional table updates steer matching `allowed_ips` into the h3llo TUN.
- Internal routing: longest-prefix matching across peers; route update flow is documented in [docs/internals.md](docs/internals.md).

## BareUDP Mode

BareUDP is an opt-in plaintext fast path for controlled networks where confidentiality is not required; security constraints, DNS handling, and MTU guidance are covered in [docs/protocol.md](docs/protocol.md).

## Interoperability

- CDNs: most CDNs lack HTTP/3 origin fetch, so Layer-7 forwarding usually fails.
- Cloudflare WARP: authentication differs; use [usque](https://github.com/Diniboy1123/usque) if you need an open-source MASQUE WARP client.

## Compatibility and Limitations

- Requires end-to-end HTTP/3; no HTTP/2 or HTTP/1.1 fallback.
- MASQUE optional Capsule Types are not implemented (`ROUTE_ADVERTISEMENT`, `ADDRESS_REQUEST`, `ADDRESS_ASSIGN`), and URI templates for `target` / `ipproto` are unsupported.
- BareUDP is plaintext; only use in trusted environments.
- CDN Layer-7 forwarding without HTTP/3 origin fetch is unsupported; Cloudflare WARP auth is incompatible.
- Platform tiers: Linux is first-class and the primary target; macOS and Windows are second-tier with best-effort support; BSD derivatives are third-tier with planned extensions only.

## Further Reading

- Protocol details: [docs/protocol.md](docs/protocol.md)
- Configuration examples: [docs/configuration.md](docs/configuration.md)
- Implementation notes: [docs/internals.md](docs/internals.md)
- Performance optimizations: [docs/performance.md](docs/performance.md)
