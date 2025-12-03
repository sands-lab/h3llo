# h3llo: HTTP/3-based Low-latency Overlay

h3llo is a lightweight overlay network that rides on standard HTTP/3 (MASQUE/CONNECT-IP, [RFC 9484](https://datatracker.ietf.org/doc/html/rfc9484)) with an optional BareUDP fast path. It aims for WireGuard-like latency, flexible topologies, and zero-downtime reconfiguration.

## Feature Highlights

- Low-latency overlay: WireGuard-like performance with symmetric or asymmetric peer layouts.
- Zero-downtime updates: atomic peer/routing refresh without disrupting active traffic.
- Two protocols: encrypted HTTP/3 by default; BareUDP as an opt-in, high-throughput plaintext path for trusted networks.
- Routing aware: longest-prefix routing per peer; optional system route updates.

## Quick Start

Below is a minimal two-node example. If you know `wg-quick`, the structure should feel familiar. Provide valid QUIC/TLS assets for `cert`/`key` (self-signed is fine if both peers trust the same CA); see docs for certificate options.

```yaml
# Configuration on node1
local:
  id: example-node-1
  h3:
    listen: https://[::]:443/path
    cert: ./cert.pem
    key: ./key.pem
    secret: example-node-1-secret
  tun:
    ifname: h3llo0
    addr:
      - 192.168.180.1/32
peers:
- id: example-node-2
  h3:
  tun:
    allowedIPs:
      - 192.168.180.2/32
```
```yaml
# Configuration on node2
local:
  id: example-node-2
  tun:
    ifname: h3llo0
    addr:
      - 192.168.180.2/32
peers:
- id: example-node-1
  h3:
    secret: example-node-1-secret
    endpoints:
      - https://node1.example.com:443/path
  tun:
    allowedIPs:
      - 192.168.180.1/32
```

Save the configuration as `host/config.yaml`, then start the h3llo container:

```bash
docker run -d --name h3llo --restart always --network host --cap-add=NET_ADMIN -v host/config.yaml:/config.yaml h3llo/h3llo -c /config.yaml
```

## Configuration Overview

High-level connection/auth/routing summary; see `docs/protocol.md` for auth/transport semantics and `docs/internals.md` for runtime behavior.

### Architecture

- Client/server-style: One side only listens (`listen`); the other only dials via `endpoints`. Suitable for hub-and-spoke.
- Peer-to-peer: Both sides listen and dial each other for symmetry; multipath/connection selection details live in `docs/internals.md`.

### Authentication and Security

- Identity: every node needs a unique `id` (>= 6 chars).
- Basic Auth uses `local.id` + `local.h3.secret` (secret must be longer than 8 characters when `local.h3.listen` is set) for CONNECT and `local.h3.admin` (`name`/`pass`) for control-plane GET/POST. Provide `peers[].h3.secret` only on dialing nodes (when `peers[].h3.endpoints` is set) and keep it equal to the remote `local.h3.secret`; listen-only peers can omit both `endpoints` and `secret`. Full derivation and control-plane enablement live in `docs/protocol.md`. QUIC/TLS certificates are required for HTTP/3.

### Routing

- System routes: optional table updates steer matching `allowedIPs` into the h3llo TUN.
- Internal routing: longest-prefix matching across peers; route update flow is documented in `docs/internals.md`.

## BareUDP Mode

BareUDP is an opt-in plaintext fast path for controlled networks where confidentiality is not required; security constraints, DNS handling, and MTU guidance are covered in `docs/protocol.md`.

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

- Protocol details: `docs/protocol.md`
- Configuration examples: `docs/configuration.md`
- Implementation notes: `docs/internals.md`
