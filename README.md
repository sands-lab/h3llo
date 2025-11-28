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
  id: example-node-01
  h3:
    listen: https://[::]:443/path
    cert: ./cert.pem
    key: ./key.pem
  tun:
    ifname: h3llo0
    addr:
    - 192.168.180.1/32
peers:
- id: example-node-02
  h3:
  tun:
    allowedIPs:
    - 192.168.180.2/32
```
```yaml
# Configuration on node2
local:
  id: example-node-02
  tun:
    ifname: h3llo0
    addr:
    - 192.168.180.2/32
peers:
- id: example-node-01
  h3:
    endpoint: https://node1.example.com:443/path
  tun:
    allowedIPs:
    - 192.168.180.1/32
```

Save the configuration as `host/config.yaml`, then start the h3llo container:

```bash
docker run -d --name h3llo --restart always --network host --cap-add=NET_ADMIN -v host/config.yaml:/config.yaml h3llo/h3llo -c /config.yaml
```

## Configuration Overview

How nodes connect, authenticate, and route traffic at a glance; see `docs/` for schemas and edge cases.

### Architecture

- Client/server-style: One side only listens (`listen`); the other only dials (`endpoint`). Suitable for hub-and-spoke.
- Peer-to-peer: Both sides listen and dial each other for symmetry; h3llo maintains two connections and selects one at random.

### Authentication and Security

- Identity and Basic Auth: every node needs a unique `id` (>= 6 chars). h3llo derives HTTP Basic Auth automatically on the HTTP path: CONNECT uses `username = client local.id`, `password = server local.id`; control-plane GET/POST enable only when `local.h3.admin` (longer than 8 characters) is configured and use `username = local.h3.admin`, `password = server local.id`. HTTP requests do not filter source IPs (BareUDP relies on source-IP filtering instead).
- Transport security: QUIC/TLS is mandatory; provide valid `cert`/`key` pairs to avoid MitM.
- HTTP path: `listen`/`endpoint` include a path; any path works as long as both ends match.

### Routing

- System routes: optional table updates steer matching `allowedIPs` into the h3llo TUN.
- Internal routing: longest-prefix matching selects the peer for each packet when multiple peers exist.

## BareUDP Mode

BareUDP is an opt-in plaintext fast path for controlled networks where confidentiality is not required. Prefer HTTP/3 for encrypted transport; use BareUDP only when you accept the throughput/latency vs. security trade-off. BareUDP is not NAT-friendly—ensure both peers have mutually reachable static IPs.

## Interoperability

- CDNs: most CDNs lack HTTP/3 origin fetch, so Layer-7 forwarding usually fails.
- Cloudflare WARP: authentication differs; use [usque](https://github.com/Diniboy1123/usque) if you need an open-source MASQUE WARP client.

## Compatibility and Limitations

- Requires end-to-end HTTP/3; no HTTP/2 or HTTP/1.1 fallback.
- MASQUE optional Capsule Types are not implemented (`ROUTE_ADVERTISEMENT`, `ADDRESS_REQUEST`, `ADDRESS_ASSIGN`), and URI templates for `target` / `ipproto` are unsupported.
- BareUDP is plaintext; only use in trusted environments.
- CDN Layer-7 forwarding without HTTP/3 origin fetch is unsupported; Cloudflare WARP auth is incompatible.

## Further Reading

- Protocol details: `docs/protocol.md`
- Configuration examples: `docs/configuration.md`
- Implementation notes: `docs/internals.md`
