## Full configuration

This page shows a full configuration sample, then explains each field and its default.

```yaml
local:
  id: example-node-02
  table: true # optional, default: true (manage system routes)
  dns: # optional
    server: 1.1.1.1 # optional, default: 1.1.1.1
    refresh: 60 # optional, default: 60 (seconds; 0 disables; minimum 30 when nonzero)
    bindif: eth0 # optional, default: auto-detect; warn and fallback to unbound on failure
  h3: # optional
    listen: https://[::]:443/path
    admin: admin-username # optional, enables control-plane API when set (must be longer than 8 characters)
    cert: ./cert.pem
    key: ./key.pem
  bare: # optional
    listen: udp://[::]:6635
  tun:
    ifname: h3llo0 # optional, default: h3llo0
    addr:
    - 192.168.180.2/32
    mtu: 1410 # optional, default: 1410 (see docs/protocol.md for MTU sizing)
peers:
- id: example-node-01
  enabled: true # optional, default: true
  h3: # optional, conflicts with peers.bare; endpoints optional (listen-only if omitted)
    endpoints:
    - https://node1.example.com:443/path # optional; deduped; order does not imply priority
    retry: 10 # optional, default: 10 (seconds between reconnect attempts)
    ca: ./ca.pem # optional
    insecure: false # optional, default: false
    bindifs:
    - eth0 # optional; when absent, auto-detects at most one interface; use list only when provided
  bare: # optional, conflicts with peers.h3
    endpoint: udp://node1.example.com:6635
    bindif: eth0 # optional; auto-detect when absent; warn and fallback to unbound on failure
  tun:
    allowedIPs:
    - 192.168.180.1/32
```

## Field notes

- `local.id`: Unique node identifier validated by peers; must be globally unique; use a string of at least 6 characters.
- `local.table` (default `true`): Update the system routing table to steer matching traffic into the h3llo TUN. When `false`, h3llo does not touch system routes; the OS still installs connected routes for `local.tun.addr` (for example, `192.168.180.1/24` adds `192.168.180.0/24`).
- `local.dns.server` (default `1.1.1.1`): DNS server address (IPv4 or IPv6 literal) used to resolve peer hostnames; outbound binding/recursive-routing guards are detailed in `docs/internals.md`.
- `local.dns.refresh` (default `60`): DNS refresh timer in seconds (`0` disables). Nonzero values are clamped to a minimum of `30`; the resolver batches hostnames per tick (see `docs/internals.md`).
- `local.dns.bindif` (optional): Outbound interface for DNS resolution; auto-detects at most one interface when omitted. Binding behavior and fallbacks are in `docs/internals.md`.
- `local.h3.listen`: HTTP/3 listen address (scheme/host/port/path) for inbound peers when H3 is enabled.
- `local.h3.admin`: Optional control-plane username; must be longer than 8 characters. Enables GET/POST APIs when set; authentication matrix is described in `docs/protocol.md`.
- `local.h3.cert` / `local.h3.key`: Certificate and private key for QUIC/TLS, enabling encryption and peer authentication.
- `local.bare.listen`: BareUDP listen address when using the plaintext fast path; required to start BareUDP and optional alongside `local.h3`.
- `local.tun.ifname` (default `h3llo0`): Name of the TUN interface created by h3llo.
- `local.tun.addr`: IP/prefix assignments (IPv4/IPv6, dual-stack, multiple prefixes) for the TUN interface. h3llo only relies on the connected routes created with the TUN; extra system routes come from `peers[].tun.allowedIPs` when `local.table=true`.
- `local.tun.mtu` (default `1410`): MTU for the TUN interface; see `docs/protocol.md` for sizing guidance.
- `peers[]`: Remote peer entries.
- `peers[].id`: Remote node ID; must match the peer’s local.id.
- `peers[].enabled` (default `true`): Whether this peer entry is active.
- `peers[].h3.endpoints` (optional, deduped): List of HTTP/3 dialing addresses (scheme/host/port/path); omit or leave empty to wait for inbound HTTP/3 from the peer. Mutually exclusive with peers[].bare; dialing/multipath details are in `docs/internals.md`.
- `peers[].h3.retry` (default `10`): Seconds between reconnect attempts when dialing fails (including TLS/handshake errors); selection and rebuild behavior is in `docs/internals.md`.
- `peers[].h3.bindifs` (optional): Interface list for HTTP/3 dialers. When omitted or empty, auto-detects at most one interface. Probe/bind fallbacks and recursive-routing warnings are described in `docs/internals.md`.
- `peers[].h3.ca`: Custom CA bundle path for validating the peer’s certificate (useful for self-signed certs); otherwise the system trust store is used.
- `peers[].h3.insecure` (default `false`): Skip TLS certificate validation (not recommended; prefer `ca`).
- `peers[].bare.endpoint`: BareUDP dialing address; mutually exclusive with peers[].h3. DNS handling, source-IP filtering, and multi-answer behavior are detailed in `docs/protocol.md`.
- `peers[].bare.bindif` (optional): Interface for BareUDP dialing. Auto-detect when absent; binding and fallback behavior is in `docs/internals.md`.
- `peers[].tun.allowedIPs`: Prefixes routed via this peer; longest-prefix wins when multiple peers overlap.

## Notes

- Transport selection: `local.h3` and `local.bare` can both be configured so the node offers HTTP/3 and BareUDP concurrently; each `peers[]` entry must pick exactly one of H3 or BareUDP.
- Dynamic updates: Require both `local.h3.listen` and `local.h3.admin`; when `local.h3.admin` is absent, the control-plane API remains disabled. Update semantics are described in `docs/protocol.md`.
- Routing scope with `local.table=false`: POST still refreshes internal routes and peer transports, but system routes remain untouched (only connected routes from `local.tun.addr` stay).
- H3 dialing optionality: If `peers[].h3` is present but `peers[].h3.endpoints` is empty or omitted, the node waits for the peer to initiate an HTTP/3 connection (listener-only posture). Connection set/selection rules live in `docs/internals.md`.
- DNS resolution and binding behavior: summarized above; resolver cadence, binding probes, and recursion guards are detailed in `docs/internals.md`.
- BareUDP constraints: plaintext, NAT-unfriendly, and source-IP-filtered; DNS and binding/refresh rules are documented in `docs/protocol.md` and `docs/internals.md`.
