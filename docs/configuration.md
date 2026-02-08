## Full configuration

This page shows a full configuration sample, then explains each field and its default.

```yaml
local:
  table: true # optional, default: true (manage system routes)
  dns: # optional
    server: udp://1.1.1.1:53 # optional, default: udp://1.1.1.1:53
    refresh: 60 # optional, default: 60 (seconds; 0 disables; minimum 1s, recommended 30s+)
    bindif: eth0 # optional, default: auto-detect; warn and fallback to unbound on failure
  h3: # optional; enables HTTP/3 transport
    listen: https://[::]:443/path # optional; omit for dial-only H3 mode
    cert: ./cert.pem # required when local.h3.listen is set
    key: ./key.pem # required when local.h3.listen is set
    admin: # optional; enables control-plane API when set (requires both name and pass, each longer than 8 characters)
      name: admin-username
      pass: admin-password
  bare: # optional
    listen: udp://[::]:6635 # required when local.bare is set
  tun: # required
    ifname: h3llo0 # optional, default: h3llo0
    addrs: # required (CIDR notation with prefix length)
      - 192.168.180.2/24 # required; supports subnets (e.g., /24) or host addresses (/32, /128)
    mtu: 1393 # optional, default: 1393 (see docs/protocol.md for MTU sizing)
peers: # optional, default: []
- id: example-node-1
  enabled: true # optional, default: true
  h3: # optional, conflicts with peers.bare; endpoint optional (listen-only if omitted)
    token: example-token-12ch # required whenever peers[].h3 is set (minimum 12 characters)
    endpoint: https://node1.example.com:443/path # optional; omit for listen-only
    ca: ./ca.pem # optional
    insecure: false # optional, default: false
    bindif: eth0 # optional; omit to auto-detect
  bare: # optional, conflicts with peers.h3
    endpoint: udp://node1.example.com:6635 # required when peers.bare is set
    bindif: eth0 # optional; auto-detect when absent; warn and fallback to unbound on failure
  tun: # required
    allowedIPs: # required
      - 192.168.180.1/32 # required
```

## Field notes

- `peers` (default `[]`): Optional peer list; omit entirely when running standalone.
- `local.h3` (optional): Enables HTTP/3 transport. When `local.h3.listen` is set, `cert` and `key` are required. When `listen` is omitted, the node operates in dial-only mode (can connect to peers but not accept inbound connections).
- `local.bare` (optional): When present, `local.bare.listen` is required.
- `local.table` (default `true`): Update the system routing table to steer matching traffic into the h3llo TUN. When `false`, h3llo does not touch system routes; the OS still installs host routes (`/32` or `/128`) for `local.tun.addrs`.
- `local.h3.admin.name` / `local.h3.admin.pass` (optional; both longer than 8 characters): Control-plane Basic Auth credentials bound to HTTP/3. Enable GET/POST APIs only when both are set; authentication matrix is described in [docs/protocol.md](protocol.md).
- `local.dns.server` (default `udp://1.1.1.1:53`): DNS server address as a UDP URI with an IP literal and port; outbound binding/recursive-routing guards are detailed in [docs/internals.md](internals.md).
- `local.dns.refresh` (default `60`): DNS refresh timer in seconds (`0` disables). Minimum is `1` second; `30`+ recommended for production to avoid excessive queries. The resolver batches hostnames per tick (see [docs/internals.md](internals.md)).
- `local.dns.bindif` (optional): Outbound interface for DNS resolution; prefer it when present in probe results, otherwise warn and fall back to a probed interface. Auto-detects at most one interface when omitted. Binding behavior and fallbacks are in [docs/internals.md](internals.md).
- `local.h3.listen`: HTTP/3 listen address (scheme/host/port/path) for inbound peers when H3 is enabled; required when `local.h3` is set.
- `local.h3.cert` / `local.h3.key`: Certificate and private key for QUIC/TLS, enabling encryption and peer authentication.
- `local.bare.listen`: BareUDP listen address when using the plaintext fast path; required to start BareUDP and optional alongside `local.h3`.
- `local.tun.ifname` (default `h3llo0`): Name of the TUN interface created by h3llo.
- `local.tun.addrs` (required): IP prefixes in CIDR notation (e.g., `192.168.180.1/24`, `2001:db8::1/64`) for the TUN interface. Supports IPv4, IPv6, dual-stack, and multiple prefixes. Extra system routes come from `peers[].tun.allowedIPs` when `local.table=true`.
- `local.tun.mtu` (default `1393`): MTU for the TUN interface; see [docs/protocol.md](protocol.md) for sizing guidance.
- `peers[]`: Remote peer entries.
- `peers[].id`: Remote peer identifier; must be unique within the configuration and non-empty.
- `peers[].h3.token`: Remote peer authentication token; required (and must be at least 12 characters) whenever `peers[].h3` is set, including listen-only entries with empty `endpoints`. Must be unique across all peers. Bearer Token auth for CONNECT uses `Authorization: Bearer <token>`; server matches tokens to identify peers.
- `peers[].enabled` (default `true`): Whether this peer entry is active.
- `peers[].h3.endpoint` (optional): HTTP/3 dialing address (scheme/host/port/path); omit to wait for inbound HTTP/3 from the peer. Mutually exclusive with `peers[].bare`.
- `peers[].h3.bindif` (optional): Interface for HTTP/3 dialer. When omitted, auto-detects at most one interface. Probe/bind fallbacks and recursive-routing warnings are described in [docs/internals.md](internals.md).
- `peers[].h3.ca`: Custom CA bundle path for validating the peer’s certificate (useful for self-signed certs); otherwise the system trust store is used.
- `peers[].h3.insecure` (default `false`): Skip TLS certificate validation (not recommended; prefer `ca`).
- `peers[].bare.endpoint`: BareUDP dialing address; mutually exclusive with peers[].h3. DNS handling, source-IP filtering, and multi-answer behavior are detailed in [docs/protocol.md](protocol.md).
- `peers[].bare.bindif` (optional): Interface for BareUDP dialing. Auto-detect when absent; binding and fallback behavior is in [docs/internals.md](internals.md).
- `peers[].tun.allowedIPs` (required): Prefixes routed via this peer; longest-prefix wins when multiple peers overlap.

## Notes

- Transport selection: `local.h3` and `local.bare` can both be configured so the node offers HTTP/3 and BareUDP concurrently; each `peers[]` entry must pick exactly one of H3 or BareUDP.
- Dynamic updates: Require both `local.h3.listen` and `local.h3.admin` (with `name` and `pass` set and longer than 8 characters); when absent, the control-plane API remains disabled. Update semantics are described in [docs/protocol.md](protocol.md); dynamic POST allows updating `local.h3.admin` and `peers` (other `local` fields are rejected).
- Routing scope with `local.table=false`: POST still refreshes internal routes and peer transports, but system routes remain untouched (only host routes from `local.tun.addrs` stay).
- H3 dialing optionality: If `peers[].h3` is present but `peers[].h3.endpoint` is omitted, the node waits for the peer to initiate an HTTP/3 connection (listener-only posture).
- DNS resolution and binding behavior: summarized above; resolver cadence, binding probes, and recursion guards are detailed in [docs/internals.md](internals.md).
- BareUDP constraints: plaintext, NAT-unfriendly, and source-IP-filtered; DNS and binding/refresh rules are documented in [docs/protocol.md](protocol.md) and [docs/internals.md](internals.md).
