## Full configuration

This page shows a full configuration sample, then explains each field and its default.

```yaml
local:
  id: example-node-2 # required
  table: true # optional, default: true (manage system routes)
  dns: # optional
    server: udp://1.1.1.1:53 # optional, default: udp://1.1.1.1:53
    refresh: 60 # optional, default: 60 (seconds; 0 disables; minimum 1s, recommended 30s+)
    bindif: eth0 # optional, default: auto-detect; warn and fallback to unbound on failure
  h3: # optional; when present, all fields below are required unless noted
    listen: https://[::]:443/path # required when local.h3 is set
    cert: ./cert.pem # required when local.h3 is set
    key: ./key.pem # required when local.h3 is set
    admin: # optional; enables control-plane API when set (requires both name and pass, each longer than 8 characters)
      name: admin-username
      pass: admin-password
  bare: # optional
    listen: udp://[::]:6635 # required when local.bare is set
  tun: # required
    ifname: h3llo0 # optional, default: h3llo0
    addrs: # required (host addresses only; /32 or /128 applied automatically)
      - 192.168.180.2 # required
    mtu: 1410 # optional, default: 1410 (see docs/protocol.md for MTU sizing)
peers: # optional, default: []
- id: example-node-1
  enabled: true # optional, default: true
  h3: # optional, conflicts with peers.bare; endpoints optional (listen-only if omitted)
    secret: example-secret # required whenever peers[].h3 is set (including listen-only)
    endpoints:
      - https://node1.example.com:443/path # optional; deduped; order does not imply priority
    retry: 10 # optional, default: 10 (seconds between reconnect attempts)
    ca: ./ca.pem # optional
    insecure: false # optional, default: false
    bindifs:
      - eth0 # optional; omit to auto-detect at most one interface; when set, list must not be empty
  bare: # optional, conflicts with peers.h3
    endpoint: udp://node1.example.com:6635 # required when peers.bare is set
    bindif: eth0 # optional; auto-detect when absent; warn and fallback to unbound on failure
  tun: # required
    allowedIPs: # required
      - 192.168.180.1/32 # required
```

## Field notes

- `local.id`: Unique node identifier validated by peers; must be globally unique; use a string of at least 6 characters.
- `peers` (default `[]`): Optional peer list; omit entirely when running standalone.
- `local.h3` / `local.bare` (optional): Omit to disable the corresponding listener. When `local.h3` is present, `local.h3.listen`, `local.h3.cert`, and `local.h3.key` are required and must be non-empty. When `local.bare` is present, `local.bare.listen` is required.
- `local.table` (default `true`): Update the system routing table to steer matching traffic into the h3llo TUN. When `false`, h3llo does not touch system routes; the OS still installs host routes (`/32` or `/128`) for `local.tun.addrs`.
- `local.h3.admin.name` / `local.h3.admin.pass` (optional; both longer than 8 characters): Control-plane Basic Auth credentials bound to HTTP/3. Enable GET/POST APIs only when both are set; authentication matrix is described in `docs/protocol.md`.
- `local.dns.server` (default `udp://1.1.1.1:53`): DNS server address as a UDP URI with an IP literal and port; outbound binding/recursive-routing guards are detailed in `docs/internals.md`.
- `local.dns.refresh` (default `60`): DNS refresh timer in seconds (`0` disables). Minimum is `1` second; `30`+ recommended for production to avoid excessive queries. The resolver batches hostnames per tick (see `docs/internals.md`).
- `local.dns.bindif` (optional): Outbound interface for DNS resolution; prefer it when present in probe results, otherwise warn and fall back to a probed interface. Auto-detects at most one interface when omitted. Binding behavior and fallbacks are in `docs/internals.md`.
- `local.h3.listen`: HTTP/3 listen address (scheme/host/port/path) for inbound peers when H3 is enabled; required when `local.h3` is set.
- `local.h3.cert` / `local.h3.key`: Certificate and private key for QUIC/TLS, enabling encryption and peer authentication.
- `local.bare.listen`: BareUDP listen address when using the plaintext fast path; required to start BareUDP and optional alongside `local.h3`.
- `local.tun.ifname` (default `h3llo0`): Name of the TUN interface created by h3llo.
- `local.tun.addrs` (required): Host IP assignments (IPv4/IPv6, dual-stack, multiple addresses) for the TUN interface; h3llo applies `/32` or `/128` automatically. Extra system routes come from `peers[].tun.allowedIPs` when `local.table=true`.
- `local.tun.mtu` (default `1410`): MTU for the TUN interface; see `docs/protocol.md` for sizing guidance.
- `peers[]`: Remote peer entries.
- `peers[].id`: Remote node ID; must match the peer’s `local.id`.
- `peers[].h3.secret`: Remote peer authentication secret; required (and must be longer than 8 characters) whenever `peers[].h3` is set, including listen-only entries with empty `endpoints`. HTTP Basic Auth for CONNECT uses `username = remote local.id` and `password = peers[username].h3.secret` on the server side; clients send `password = peers[target].h3.secret`.
- `peers[].enabled` (default `true`): Whether this peer entry is active.
- `peers[].h3.endpoints` (optional, deduped): List of HTTP/3 dialing addresses (scheme/host/port/path); omit or leave empty to wait for inbound HTTP/3 from the peer. Mutually exclusive with peers[].bare; dialing/multipath details are in `docs/internals.md`.
- `peers[].h3.retry` (default `10`): Seconds between reconnect attempts when dialing fails (including TLS/handshake errors); selection and rebuild behavior is in `docs/internals.md`.
- `peers[].h3.bindifs` (optional): Interface list for HTTP/3 dialers. When omitted, auto-detects at most one interface; when set, the list must include at least one interface. Probe/bind fallbacks and recursive-routing warnings are described in `docs/internals.md`.
- `peers[].h3.ca`: Custom CA bundle path for validating the peer’s certificate (useful for self-signed certs); otherwise the system trust store is used.
- `peers[].h3.insecure` (default `false`): Skip TLS certificate validation (not recommended; prefer `ca`).
- `peers[].bare.endpoint`: BareUDP dialing address; mutually exclusive with peers[].h3. DNS handling, source-IP filtering, and multi-answer behavior are detailed in `docs/protocol.md`.
- `peers[].bare.bindif` (optional): Interface for BareUDP dialing. Auto-detect when absent; binding and fallback behavior is in `docs/internals.md`.
- `peers[].tun.allowedIPs` (required): Prefixes routed via this peer; longest-prefix wins when multiple peers overlap.

## Notes

- Transport selection: `local.h3` and `local.bare` can both be configured so the node offers HTTP/3 and BareUDP concurrently; each `peers[]` entry must pick exactly one of H3 or BareUDP.
- Dynamic updates: Require both `local.h3.listen` and `local.h3.admin` (with `name` and `pass` set and longer than 8 characters); when absent, the control-plane API remains disabled. Update semantics are described in `docs/protocol.md`; dynamic POST allows updating `local.h3.admin` and `peers` (other `local` fields are rejected).
- Routing scope with `local.table=false`: POST still refreshes internal routes and peer transports, but system routes remain untouched (only host routes from `local.tun.addrs` stay).
- H3 dialing optionality: If `peers[].h3` is present but `peers[].h3.endpoints` is empty or omitted, the node waits for the peer to initiate an HTTP/3 connection (listener-only posture). Connection set/selection rules live in `docs/internals.md`.
- DNS resolution and binding behavior: summarized above; resolver cadence, binding probes, and recursion guards are detailed in `docs/internals.md`.
- BareUDP constraints: plaintext, NAT-unfriendly, and source-IP-filtered; DNS and binding/refresh rules are documented in `docs/protocol.md` and `docs/internals.md`.
