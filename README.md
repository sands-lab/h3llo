# h3llo: HTTP/3-based Low-latency Overlay

h3llo is a lightweight, low-latency VPN built on the MASQUE/CONNECT-IP protocol([RFC 9484](https://datatracker.ietf.org/doc/html/rfc9484)) over standard HTTP/3 and the BareUDP protocol.

## Feature Highlights

- WireGuard-like low latency over HTTP/3 + CONNECT-IP.
- Dynamic reconfiguration designed for zero downtime.
- Flexible peer-to-peer or client/server-like topology.
- Dual data planes: encrypted HTTP/3 as default; BareUDP as an unencrypted option for controlled networks.

## Quick Start

Below is an example configuration with two nodes. If you are familiar with `wg-quick`, the layout should feel similar.

```yaml
# Configuration on node1
local:
  uuid: e41a6f46-c132-4d0e-9b38-34ed4a000001
  h3:
    listen: https://[::]:443/path
    cert: ./cert.pem
    key: ./key.pem
  tun:
    ifname: h3llo0
    addr:
    - 192.168.180.1/32
peers:
  e41a6f46-c132-4d0e-9b38-34ed4a000002:
    tun:
      allowedIPs:
      - 192.168.180.2/32
```
```yaml
# Configuration on node2
local:
  uuid: e41a6f46-c132-4d0e-9b38-34ed4a000002
  tun:
    ifname: h3llo0
    addr:
    - 192.168.180.2/32
peers:
  e41a6f46-c132-4d0e-9b38-34ed4a000001:
    h3:
      endpoint: https://node1.example.com:443/path
    tun:
      allowedIPs:
      - 192.168.180.1/32
```

Save the configuration as `host/config.yaml`, then start the h3llo Docker container with a single command:

```bash
docker run -d --name h3llo --restart always --network host --cap-add=NET_ADMIN -v host/config.yaml:/config.yaml h3llo/h3llo -c /config.yaml
```

## Configuration

### Architecture

Similar to WireGuard, each h3llo node is a peer; there is no strict client/server split. It also supports a client/server-like topology for convenience.

**Client/server-style.** In the example above, `node1` only exposes an HTTP/3 listen address, while `node2` defines no listen address and only sets `endpoint` for `node1`. This is enough for the two nodes to connect.

**Peer-to-peer.** If both `node1` and `node2` expose listen addresses and also set each other's `endpoint` under `peers`, the configuration is fully symmetric. h3llo will create two connections and pick one randomly for use.

### Authentication and Security

Each node needs a unique `uuid` for identity and verification. h3llo relies on QUIC's built-in TLS for transport security, so provide valid SSL credentials (`cert` and `key`) to avoid MitM attacks.

The h3llo URI (`listen` and `endpoint`) includes an HTTP path. Any valid path works, as long as both sides match.

### Routing

h3llo updates the system routing table based on `allowedIPs` under `peers`, ensuring packets whose destination IP falls within `allowedIPs` are sent into the h3llo TUN interface.

When multiple peers exist, h3llo performs longest-prefix matching on destination IPs to route packets to the correct peer.

## BareUDP Mode

In addition to HTTP/3 + CONNECT-IP, h3llo supports BareUDP for VPN use in controlled networks. Data transported with BareUDP is not encrypted.

## Interoperability

### With CDNs

Major CDNs currently do not support HTTP/3 origin fetch, so h3llo will likely not work with CDN Layer-7 forwarding for now.

### With Cloudflare WARP

h3llo uses a different authentication method than WARP. Consider using [usque](https://github.com/Diniboy1123/usque), an open-source MASQUE WARP client.

## Compatibility and Limitations

- Requires end-to-end HTTP/3; no HTTP/2 or HTTP/1.1 fallback.
- Optional MASQUE Capsule Types are not implemented (e.g., `ROUTE_ADVERTISEMENT`, `ADDRESS_REQUEST`, `ADDRESS_ASSIGN`), and URI templates for `target` / `ipproto` are not supported.
- BareUDP carries traffic in plaintext; only use in trusted, controlled networks.
- CDN Layer-7 forwarding that lacks HTTP/3 origin fetch is not supported; authentication is not compatible with Cloudflare WARP.

For protocol details and full configuration examples, see the `docs/` directory.
