# h3llo: HTTP/3-based Low-latency Overlay

h3llo is a lightweight overlay network that rides on standard HTTP/3 (MASQUE/CONNECT-IP, [RFC 9484](https://datatracker.ietf.org/doc/html/rfc9484)) with an optional BareUDP fast path. It aims for WireGuard-like latency, flexible topologies, and zero-downtime reconfiguration.

## Feature Highlights

- Low-latency overlay: WireGuard-like performance with symmetric or asymmetric peer layouts.
- Zero-downtime updates: atomic peer/routing refresh without disrupting active traffic.
- Two protocols: encrypted HTTP/3 by default; BareUDP as an opt-in, high-throughput plaintext path for trusted networks.
- Routing aware: longest-prefix routing per peer; optional system route updates.

## Quick Start

Below is a minimal two-node example. If you know `wg-quick`, the structure should feel familiar.

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
  example-node-02:
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
  example-node-01:
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

This section sketches how nodes connect, authenticate, and route traffic; see `docs/` for full schemas.

### Architecture

- Client/server-style: One side only listens (`listen`); the other only dials (`endpoint`). Suitable for hub-and-spoke.
- Peer-to-peer: Both sides listen and dial each other for symmetry; h3llo maintains two connections and selects one at random.

### Authentication and Security

- Identity: every node needs a unique `id` (string length >= 6); peers validate each other with these IDs.
- Transport security: QUIC/TLS is mandatory; provide valid `cert`/`key` pairs to avoid MitM.
- HTTP path: `listen`/`endpoint` include a path; any path works as long as both ends match.

### Routing

- System routes: optional table updates steer matching `allowedIPs` into the h3llo TUN.
- Internal routing: longest-prefix matching selects the peer for each packet when multiple peers exist.

## BareUDP Mode

BareUDP is an opt-in plaintext fast path for controlled networks where confidentiality is not required. Prefer HTTP/3 for encrypted transport; use BareUDP only when you accept the throughput/latency vs. security trade-off.

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
