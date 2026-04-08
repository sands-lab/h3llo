## Full configuration

This page shows a full configuration sample, then explains each field and its default.

```yaml
local:
  table: true # optional, default: true (manage system routes)
  dns: # optional
    server: udp://1.1.1.1:53 # optional, default: udp://1.1.1.1:53
    bindif: eth0 # optional, default: auto-detect; warn and fallback to unbound on failure
  h3: # optional; enables HTTP/3 transport
    listen: https://[::]:443/path # required when local.h3 is set
    cert: ./cert.pem # required when local.h3 is set
    key: ./key.pem # required when local.h3 is set
  bare: # optional
    listen: udp://[::]:6635 # required when local.bare is set
  api: # optional; enables management API
    listen: http://127.0.0.1:9090/ # required when local.api is set (default port 9090)
  tun: # required
    ifname: h3llo0 # optional, default: h3llo0
    addrs: # required (CIDR notation with prefix length)
      - 192.168.180.2/24 # required; supports subnets (e.g., /24) or host addresses (/32, /128)
    mtu: 1291 # optional, default: 1291 (tokio-quiche default max_udp_payload 1350 − 59 CONNECT-IP overhead)
tuning: # optional, all fields have defaults
  packet_queue_depth: 256 # optional, default: 256
  socket_buffer_size: 16 # optional, default: 16 (MiB; 0 to use system default)
  tun_tx_queue_len: 1000 # optional, default: 1000 (packets; Linux only)
  tun_enable_offload: false # optional, default: false (TUN GSO/GRO; Linux only)
  udp_enable_offload: false # optional, default: false (UDP TX GSO; RX GRO always active; Linux only)
  reconcile_interval: 10s # optional, default: 10s
  reconnect_backoff_min: 3s # optional, default: 3s
  reconnect_backoff_max: 60s # optional, default: 60s
  metrics_push_interval: 1s # optional, default: 1s
  metrics_log_interval: 3s # optional, default: 3s
  dns_query_timeout: 2s # optional, default: 2s
  dns_refresh_interval: 2m # optional, default: 2m (0s disables)
  dns_snapshot_delay: 100ms # optional, default: 100ms
  dns_min_ttl: 5m # optional, default: 5m (should be >= 2× dns_refresh_interval)
  dns_query_interval: 50ms # optional, default: 50ms (minimum delay between DNS query sends)
  h3_handshake_timeout: 5s # optional, default: 5s
  h3_max_idle_timeout: 60s # optional, default: 60s
  h3_keepalive_interval: 20s # optional, default: 20s (must be < h3_max_idle_timeout)
  h3_cc_algorithm: none # optional, default: none (accepted: none, reno, cubic, bbr, bbr2)
  h3_enable_pacing: false # optional, default: false
  h3_insecure_skip_verify: false # optional, default: false (skip TLS verification; testing only)
  h3_trusted_ca: /path/to/ca.pem # optional, default: none (PEM CA cert file for TLS verification)
peers: # optional, default: []
- id: example-node-1
  h3: # optional, conflicts with peers.bare; endpoint optional (listen-only if omitted)
    token: example-token-12ch # required whenever peers[].h3 is set (minimum 12 characters)
    endpoint: https://node1.example.com:443/path # optional; omit for listen-only
    sni: node1.example.com # optional; TLS SNI override (defaults to endpoint hostname)
    bindif: eth0 # optional; omit to auto-detect
  bare: # optional, conflicts with peers.h3
    endpoint: udp://node1.example.com:6635 # required when peers.bare is set
    bindif: eth0 # optional; auto-detect when absent; warn and fallback to unbound on failure
  tun: # required
    allowed_ips: # required
      - 192.168.180.1/32 # required
```

## Field notes

- `peers` (default `[]`): Optional peer list; omit entirely when running standalone.
- `local.h3` (optional): Enables HTTP/3 transport. When set, `listen`, `cert`, and `key` are all required.
- `local.bare` (optional): When present, `local.bare.listen` is required.
- `local.table` (default `true`): Update the system routing table to steer matching traffic into the h3llo TUN. When `false`, h3llo does not touch system routes; the OS still installs host routes (`/32` or `/128`) for `local.tun.addrs`.
- `local.api` (optional): Enables the management API. When set, `local.api.listen` is required (parsed as `http://` URI, default port 9090). The API binds to a localhost address and relies on OS-level access control. See [docs/protocol.md](protocol.md) for endpoint details.
- `local.dns.server` (default `udp://1.1.1.1:53`): DNS server address as a UDP URI with an IP literal and port; outbound binding/recursive-routing guards are detailed in [docs/internals.md](internals.md).
- `local.dns.bindif` (optional): Outbound interface for DNS resolution; prefer it when present in probe results, otherwise warn and fall back to a probed interface. Auto-detects at most one interface when omitted. Binding behavior and fallbacks are in [docs/internals.md](internals.md).
- `local.h3.listen`: HTTP/3 listen address (scheme/host/port/path); required when `local.h3` is set.
- `local.h3.cert` / `local.h3.key`: Certificate and private key for QUIC/TLS; required when `local.h3` is set.
- `local.bare.listen`: BareUDP listen address when using the plaintext fast path; required to start BareUDP and optional alongside `local.h3`.
- `local.tun.ifname` (default `h3llo0`): Name of the TUN interface created by h3llo.
- `local.tun.addrs` (required): IP prefixes in CIDR notation (e.g., `192.168.180.1/24`, `2001:db8::1/64`) for the TUN interface. Supports IPv4, IPv6, dual-stack, and multiple prefixes. Extra system routes come from `peers[].tun.allowed_ips` when `local.table=true`.
- `local.tun.mtu` (default `1291`): MTU for the TUN interface, derived from tokio-quiche's default `max_udp_payload_size` (1350) minus CONNECT-IP overhead (59). The limit is configurable in quiche. See [docs/protocol.md](protocol.md) for sizing guidance. When H3 peers are configured and MTU exceeds 1413, a warning is emitted because IPv4 CONNECT-IP payloads may exceed the QUIC DATAGRAM writable size.
- `tuning` (optional): All fields have defaults; omit the entire section to use defaults.
- `tuning.packet_queue_depth` (default `256`): Bounded channel capacity for data-plane packet queues between actors. Counts batch messages, not individual packets; each batch carries one device I/O operation's worth of packets.
- `tuning.socket_buffer_size` (default `16`): Socket buffer size in megabytes, applied to all UDP sockets via SO_RCVBUF and SO_SNDBUF. Set to `0` to skip buffer configuration and use system defaults. On Linux, the effective buffer size may be clamped by `net.core.rmem_max` / `net.core.wmem_max`; setting failures are logged as warnings without aborting.
- `tuning.tun_tx_queue_len` (default `1000`): TUN interface transmit queue length in packets. Controls how many packets the kernel queues for transmission. Applied on Linux only; ignored on other platforms.
- `tuning.tun_enable_offload` (default `false`): Enable GSO/GRO offload on the TUN device for batched I/O. When disabled, TUN reads and writes fall back to single-packet operations. Linux only; ignored on other platforms. Disabled by default due to compatibility issues with certain kernel versions and virtualization layers. Enable for better performance and verify with thorough testing.
- `tuning.udp_enable_offload` (default `false`): Enable UDP offload for transports. Effect varies by transport: **BareUDP TX** — controls GSO; when enabled, batches packets into a single `sendmsg` via `UDP_SEGMENT`; when disabled, per-packet sends. **BareUDP RX** — no effect; GRO is always active (quinn-udp unconditionally enables `UDP_GRO`, and the receive buffer is always sized for coalesced datagrams). **HTTP/3** (client and listener) — controls both GSO and GRO via `apply_max_capabilities()`. Linux only; ignored on other platforms. Disabled by default due to compatibility issues with certain NIC drivers and platforms — e.g., incorrect checksums (see [troubleshooting](troubleshoot.md#bareudp-checksum-errors-with-nic-tx-offload)) or GSO `EINVAL` on aarch64 (see [troubleshooting](troubleshoot.md#gso-udp_segment-sendto-einval-on-aarch64)). Enable for better performance and verify with thorough testing.
- `tuning.reconcile_interval` (default `10s`): Interval between periodic reconciliation cycles (prune stale bounds + attempt reconnection). Controls how often the orchestrator scans all peers for stale bounds and uncovered IPs.
- `tuning.reconnect_backoff_min` (default `3s`): Minimum backoff duration between reconnection attempts for a specific IP. The backoff grows exponentially from this base value after each failed attempt. When H3 peers are configured, a warning is emitted if this value is not greater than `tuning.h3_handshake_timeout` (default `5s`) to prevent overlapping handshake attempts.
- `tuning.reconnect_backoff_max` (default `60s`): Maximum backoff duration for reconnection attempts per IP. The exponential backoff is capped at this ceiling. Must be greater than or equal to `reconnect_backoff_min`.
- `tuning.metrics_push_interval` (default `1s`): Interval between periodic metric push emissions from actors to the orchestrator.
- `tuning.metrics_log_interval` (default `3s`): Interval between periodic `debug!`-level logging of QUIC and transport metrics by the orchestrator. Independent of `metrics_push_interval`, which controls actor emission cadence.
- `tuning.dns_query_timeout` (default `2s`): Timeout before a DNS query is considered failed and retried.
- `tuning.dns_refresh_interval` (default `2m`): DNS refresh interval (`0s` disables). The resolver re-queries all registered hostnames at this interval (see [docs/internals.md](internals.md)). **Warning:** `dns_min_ttl` should be at least `2× dns_refresh_interval`; otherwise cached IPs may expire before the next refresh cycle re-queries them, causing repeated connection pruning and reconnection.
- `tuning.dns_snapshot_delay` (default `100ms`): Delay after the first DNS state change before emitting a snapshot to the orchestrator. Coalesces bursts of DNS replies into a single event.
- `tuning.dns_min_ttl` (default `5m`): Minimum TTL floor for DNS records. Responses with shorter TTL are raised to this value. Recursive DNS servers return the *remaining* cache TTL, which can be near zero when the upstream record is about to expire; without a sufficient floor the IP expires locally before the next refresh cycle, triggering connection churn. **Warning:** Should be at least `2× dns_refresh_interval` (a warning is emitted at startup when this invariant is violated).
- `tuning.dns_query_interval` (default `50ms`): Interval between consecutive outbound DNS query sends. Serializes queries to prevent public DNS resolvers (e.g., 1.1.1.1) from rate-limiting or truncating responses due to query bursts. Applies globally across all hostnames and record types.
- `tuning.h3_handshake_timeout` (default `5s`): Timeout for an HTTP/3 handshake to complete.
- `tuning.h3_max_idle_timeout` (default `60s`): QUIC idle timeout; connections idle longer than this are closed.
- `tuning.h3_keepalive_interval` (default `20s`): QUIC keepalive interval; sends PING frames to prevent idle timeout. Must be less than `h3_max_idle_timeout`.
- `tuning.h3_cc_algorithm` (default `none`): QUIC congestion control algorithm. Accepted values: `none`, `reno`, `cubic`, `bbr`, `bbr2`. Applied to both client (dial) and server (listener) QUIC connections.
- `tuning.h3_enable_pacing` (default `false`): Enable QUIC packet pacing to smooth bursty sends. Requires OS-level support (e.g., `SO_TXTIME` on Linux). Applied to both client and server QUIC connections.
- `tuning.h3_insecure_skip_verify` (default `false`): Skip TLS certificate verification globally for all H3 connections. Intended for testing with self-signed certificates only. **Not recommended for production.**
- `tuning.h3_trusted_ca` (optional, default `none`): Path to a PEM-encoded CA certificate file. When set, the certificates in this file are added to the trust store alongside the platform's system CA certificates for H3 client TLS verification. Useful for private PKI or self-signed CA deployments. Ignored when `h3_insecure_skip_verify` is `true`.
- `peers[]`: Remote peer entries.
- `peers[].id`: Remote peer identifier; must be unique within the configuration and non-empty.
- `peers[].h3.token`: Remote peer authentication token; required (and must be at least 12 characters) whenever `peers[].h3` is set, including listen-only entries with empty `endpoints`. Must be unique across all peers. Bearer Token auth for CONNECT uses `Authorization: Bearer <token>`; server matches tokens to identify peers.
- `peers[].h3.endpoint` (optional): HTTP/3 dialing address (scheme/host/port/path); omit to wait for inbound HTTP/3 from the peer. Mutually exclusive with `peers[].bare`.
- `peers[].h3.sni` (optional): TLS Server Name Indication (SNI) override for the QUIC/TLS handshake. When set, this value is sent as the SNI instead of the hostname from `peers[].h3.endpoint`. The HTTP/3 `:authority` pseudo-header is derived from the `endpoint` authority (`host`, or `host:port` when a non-default HTTPS port is used) and is not affected by `sni`. Useful for reverse proxy traversal, CDN-fronted deployments, or when `endpoint` uses an IP address but the server certificate contains a DNS name.
- `peers[].h3.bindif` (optional): Interface for HTTP/3 dialer. When omitted, auto-detects at most one interface. Probe/bind fallbacks and recursive-routing warnings are described in [docs/internals.md](internals.md).
- `peers[].bare.endpoint`: BareUDP dialing address; mutually exclusive with peers[].h3. DNS handling, source-IP filtering, and multi-answer behavior are detailed in [docs/protocol.md](protocol.md).
- `peers[].bare.bindif` (optional): Interface for BareUDP dialing. Auto-detect when absent; binding and fallback behavior is in [docs/internals.md](internals.md).
- `peers[].tun.allowed_ips` (required): Prefixes routed via this peer; longest-prefix wins when multiple peers overlap.

## Notes

- Transport selection: `local.h3` and `local.bare` can both be configured so the node offers HTTP/3 and BareUDP concurrently; each `peers[]` entry must pick exactly one of H3 or BareUDP. Neither transport is required; a node with only `local.api` configured can serve as a management endpoint.
- Dynamic updates: Require `local.api` to be configured; when absent, the management API is disabled. Update semantics are described in [docs/protocol.md](protocol.md); POST only accepts the `peers` key (other top-level keys are rejected with `400 Bad Request`).
- Routing scope with `local.table=false`: POST still refreshes internal routes and peer transports, but system routes remain untouched (only host routes from `local.tun.addrs` stay).
- H3 dialing optionality: If `peers[].h3` is present but `peers[].h3.endpoint` is omitted, the node waits for the peer to initiate an HTTP/3 connection (listener-only posture).
- DNS resolution and binding behavior: summarized above; resolver cadence, binding probes, and recursion guards are detailed in [docs/internals.md](internals.md).
- BareUDP constraints: plaintext, NAT-unfriendly, and source-IP-filtered; DNS and binding/refresh rules are documented in [docs/protocol.md](protocol.md) and [docs/internals.md](internals.md).
