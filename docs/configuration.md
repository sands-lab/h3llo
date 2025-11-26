## Full configuration

This page shows a full configuration sample, then explains each field and its default.

```yaml
local:
  id: example-node-02
  table: true # optional, default: true (manage system routes)
  h3: # optional
    listen: https://[::]:443/path
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
  h3: # optional, conflicts with peers.bare; endpoint optional (listen-only if omitted)
    endpoint: https://node1.example.com:443/path # optional
    ca: ./ca.pem # optional
    insecure: false # optional, default: false
  bare: # optional, conflicts with peers.h3
    endpoint: udp://node1.example.com:6635
  tun:
    allowedIPs:
    - 192.168.180.1/32
```

## Field notes

- `local.id`: Unique node identifier validated by peers; must be globally unique; use a string of at least 6 characters.
- `local.table` (default `true`): Update the system routing table to steer matching traffic into the h3llo TUN. When `false`, h3llo does not touch system routes; the OS still installs connected routes for `local.tun.addr` (for example, `192.168.180.1/24` adds `192.168.180.0/24`).
- `local.h3.listen`: HTTP/3 listen address (scheme/host/port/path) for inbound peers when H3 is enabled.
- `local.h3.cert` / `local.h3.key`: Certificate and private key for QUIC/TLS, enabling encryption and peer authentication.
- `local.bare.listen`: BareUDP listen address when using the plaintext fast path; required to start BareUDP and optional alongside `local.h3`.
- `local.tun.ifname` (default `h3llo0`): Name of the TUN interface created by h3llo.
- `local.tun.addr`: IP/prefix assignments (IPv4/IPv6, dual-stack, multiple prefixes) for the TUN interface. h3llo only relies on the connected routes created with the TUN; extra system routes come from `peers[].tun.allowedIPs` when `local.table=true`.
- `local.tun.mtu` (default `1410`): MTU for the TUN interface; see `docs/protocol.md` for sizing guidance.
- `peers[]`: Remote peer entries.
- `peers[].id`: Remote node ID; must match the peer’s local.id.
- `peers[].enabled` (default `true`): Whether this peer entry is active.
- `peers[].h3.endpoint` (optional): HTTP/3 dialing address (scheme/host/port/path); omit to wait for inbound HTTP/3 from the peer. Mutually exclusive with peers[].bare.
- `peers[].h3.ca`: Custom CA bundle path for validating the peer’s certificate (useful for self-signed certs); otherwise the system trust store is used.
- `peers[].h3.insecure` (default `false`): Skip TLS certificate validation (not recommended; prefer `ca`).
- `peers[].bare.endpoint`: BareUDP dialing address; mutually exclusive with peers[].h3. If DNS resolution returns multiple IPs on the common resolver path, h3llo panics; DNS changes after startup are not detected (undefined behavior).
- `peers[].tun.allowedIPs`: Prefixes routed via this peer; longest-prefix wins when multiple peers overlap.

## Notes

Use both transports on the local side if needed; choose exactly one per peer entry.

- Transport selection: `local.h3` and `local.bare` can both be configured so the node offers HTTP/3 and BareUDP concurrently.
- Peer exclusivity: For each `peers[]`, configure exactly one of `peers[].h3` or `peers[].bare`; do not leave both empty and do not enable both.
- Dynamic updates: Require `local.h3.listen`; when `local.table=true`, dynamic updates also synchronize system routes.
- H3 endpoint optionality: If `peers[].h3` is present but `peers[].h3.endpoint` is omitted, the node waits for the peer to initiate an HTTP/3 connection (listener-only posture).
- BareUDP constraints:
  - Activation: BareUDP only starts when `local.bare.listen` is configured; omitting it keeps BareUDP disabled even if peers specify BareUDP endpoints.
  - Stable resolution only: the hostname in `peers[].bare.endpoint` must not change over time (DDNS or rotating IPs are unsupported); BareUDP does not re-resolve endpoints after startup.
  - Single address: do not use hostnames that resolve to multiple IPs; if resolution returns multiple IPs, h3llo panics.
  - NAT-unfriendly: requires mutually reachable static IP addresses; do not expect BareUDP to traverse NAT.
  - Explicit on both ends: specify `peers[].bare.endpoint` on both peers when using BareUDP; BareUDP will not auto-discover.
  - Plaintext pass-through: BareUDP sends each IP packet from the TUN as the UDP payload to the peer’s BareUDP listener and injects received payloads directly into the local TUN. No encryption or authentication is applied.
  - Source IP filter only: The BareUDP listener drops UDP packets whose source IP does not match configured BareUDP peer endpoints. Because source IPs can be spoofed, avoid exposing BareUDP listeners to the public Internet; prefer HTTP/3 for untrusted networks.
