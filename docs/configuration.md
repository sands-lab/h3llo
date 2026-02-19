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
    mtu: 1350 # optional, default: 1350 (tokio-quiche default DATAGRAM upper limit)
tuning: # optional, all fields have defaults
  packet_queue_depth: 256 # optional, default: 256
  socket_buffer_size: 16 # optional, default: 16 (MiB; 0 to use system default)
  tun_tx_queue_len: 1000 # optional, default: 1000 (packets; Linux only)
  tun_enable_offload: false # optional, default: false (TUN GSO/GRO; Linux only)
  udp_enable_offload: false # optional, default: false (UDP GSO/GRO; Linux only)
  reconcile_interval: 10 # optional, default: 10 (seconds)
  reconnect_backoff_min: 3 # optional, default: 3 (seconds)
  reconnect_backoff_max: 60 # optional, default: 60 (seconds)
  metrics_push_interval: 1000 # optional, default: 1000 (milliseconds)
  metrics_log_interval: 3 # optional, default: 3 (seconds)
  dns_query_timeout: 2 # optional, default: 2 (seconds)
  dns_refresh_interval: 300 # optional, default: 300 (seconds; 0 disables)
  dns_snapshot_delay: 100 # optional, default: 100 (milliseconds)
  dns_min_ttl: 60 # optional, default: 60 (seconds)
  dns_query_interval: 50 # optional, default: 50 (milliseconds; minimum delay between DNS query sends)
  h3_handshake_timeout: 5 # optional, default: 5 (seconds)
  h3_max_idle_timeout: 60 # optional, default: 60 (seconds)
  h3_keepalive_interval: 20 # optional, default: 20 (seconds; must be < h3_max_idle_timeout)
  h3_cc_algorithm: none # optional, default: none (accepted: none, reno, cubic, bbr, bbr2)
  h3_enable_pacing: false # optional, default: false
  h3_insecure_skip_verify: false # optional, default: false (skip TLS verification; testing only)
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
- `local.tun.mtu` (default `1350`): MTU for the TUN interface, capped to tokio-quiche's default maximum DATAGRAM size (the limit is configurable in quiche). See [docs/protocol.md](protocol.md) for sizing guidance. When H3 peers are configured and MTU exceeds 1413, a warning is emitted because IPv4 CONNECT-IP payloads may exceed the QUIC DATAGRAM writable size.
- `tuning` (optional): All fields have defaults; omit the entire section to use defaults.
- `tuning.packet_queue_depth` (default `256`): Bounded channel capacity for data-plane packet queues between actors. Counts batch messages, not individual packets; each batch carries one device I/O operation's worth of packets.
- `tuning.socket_buffer_size` (default `16`): Socket buffer size in megabytes, applied to all UDP sockets via SO_RCVBUF and SO_SNDBUF. Set to `0` to skip buffer configuration and use system defaults. On Linux, the effective buffer size may be clamped by `net.core.rmem_max` / `net.core.wmem_max`; setting failures are logged as warnings without aborting.
- `tuning.tun_tx_queue_len` (default `1000`): TUN interface transmit queue length in packets. Controls how many packets the kernel queues for transmission. Applied on Linux only; ignored on other platforms.
- `tuning.tun_enable_offload` (default `false`): Enable GSO/GRO offload on the TUN device for batched I/O. When disabled, TUN reads and writes fall back to single-packet operations. Linux only; ignored on other platforms. Disabled by default due to compatibility issues with certain kernel versions and virtualization layers. Enable for better performance and verify with thorough testing.
- `tuning.udp_enable_offload` (default `false`): Enable GSO/GRO offload for BareUDP and HTTP/3 transports (both client and listener). When disabled, GSO/GRO segment counts are capped to 1, resulting in per-packet I/O. Linux only; ignored on other platforms. Disabled by default due to compatibility issues with certain NIC drivers and platforms — e.g., incorrect checksums (see [troubleshooting](troubleshoot.md#bareudp-checksum-errors-with-nic-tx-offload)) or GSO `EINVAL` on aarch64 (see [troubleshooting](troubleshoot.md#gso-udp_segment-sendto-einval-on-aarch64)). Enable for better performance and verify with thorough testing.
- `tuning.reconcile_interval` (default `10`): Seconds between periodic reconciliation cycles (prune stale bounds + attempt reconnection). Controls how often the orchestrator scans all peers for stale bounds and uncovered IPs.
- `tuning.reconnect_backoff_min` (default `3`): Minimum backoff duration in seconds between reconnection attempts for a specific IP. The backoff grows exponentially from this base value after each failed attempt. When H3 peers are configured, a warning is emitted if this value is not greater than `tuning.h3_handshake_timeout` (default `5`) to prevent overlapping handshake attempts.
- `tuning.reconnect_backoff_max` (default `60`): Maximum backoff duration in seconds for reconnection attempts per IP. The exponential backoff is capped at this ceiling. Must be greater than or equal to `reconnect_backoff_min`.
- `tuning.metrics_push_interval` (default `1000`): Milliseconds between periodic metric push emissions from actors to the orchestrator.
- `tuning.metrics_log_interval` (default `3`): Seconds between periodic `debug!`-level logging of QUIC and transport metrics by the orchestrator. Independent of `metrics_push_interval`, which controls actor emission cadence.
- `tuning.dns_query_timeout` (default `2`): Seconds before a DNS query is considered timed out and retried.
- `tuning.dns_refresh_interval` (default `300`): DNS refresh timer in seconds (`0` disables). The resolver re-queries all registered hostnames at this interval (see [docs/internals.md](internals.md)).
- `tuning.dns_snapshot_delay` (default `100`): Milliseconds to wait after the first DNS state change before emitting a snapshot to the orchestrator. Coalesces bursts of DNS replies into a single event.
- `tuning.dns_min_ttl` (default `60`): Minimum TTL floor in seconds for DNS records. Responses with shorter TTL are raised to this value to prevent excessive re-queries.
- `tuning.dns_query_interval` (default `50`): Interval in milliseconds between consecutive outbound DNS query sends. Serializes queries to prevent public DNS resolvers (e.g., 1.1.1.1) from rate-limiting or truncating responses due to query bursts. Applies globally across all hostnames and record types.
- `tuning.h3_handshake_timeout` (default `5`): Seconds to wait for an HTTP/3 handshake to complete.
- `tuning.h3_max_idle_timeout` (default `60`): QUIC idle timeout in seconds; connections idle longer than this are closed.
- `tuning.h3_keepalive_interval` (default `20`): QUIC keepalive interval in seconds; sends PING frames to prevent idle timeout. Must be less than `h3_max_idle_timeout`.
- `tuning.h3_cc_algorithm` (default `none`): QUIC congestion control algorithm. Accepted values: `none`, `reno`, `cubic`, `bbr`, `bbr2`. Applied to both client (dial) and server (listener) QUIC connections.
- `tuning.h3_enable_pacing` (default `false`): Enable QUIC packet pacing to smooth bursty sends. Requires OS-level support (e.g., `SO_TXTIME` on Linux). Applied to both client and server QUIC connections.
- `tuning.h3_insecure_skip_verify` (default `false`): Skip TLS certificate verification globally for all H3 connections. Intended for testing with self-signed certificates only. **Not recommended for production.**
- `peers[]`: Remote peer entries.
- `peers[].id`: Remote peer identifier; must be unique within the configuration and non-empty.
- `peers[].h3.token`: Remote peer authentication token; required (and must be at least 12 characters) whenever `peers[].h3` is set, including listen-only entries with empty `endpoints`. Must be unique across all peers. Bearer Token auth for CONNECT uses `Authorization: Bearer <token>`; server matches tokens to identify peers.
- `peers[].h3.endpoint` (optional): HTTP/3 dialing address (scheme/host/port/path); omit to wait for inbound HTTP/3 from the peer. Mutually exclusive with `peers[].bare`.
- `peers[].h3.sni` (optional): TLS Server Name Indication (SNI) override for the QUIC/TLS handshake. When set, this value is sent as the SNI instead of the hostname from `peers[].h3.endpoint`. The HTTP/3 `:authority` pseudo-header is derived from the `endpoint` authority (`host`, or `host:port` when a non-default HTTPS port is used) and is not affected by `sni`. Useful for reverse proxy traversal, CDN-fronted deployments, or when `endpoint` uses an IP address but the server certificate contains a DNS name.
- `peers[].h3.bindif` (optional): Interface for HTTP/3 dialer. When omitted, auto-detects at most one interface. Probe/bind fallbacks and recursive-routing warnings are described in [docs/internals.md](internals.md).
- Custom CA certificate bundles are not currently supported. The underlying QUIC library (tokio-quiche) does not expose an API for configuring custom CA certificates; all TLS verification uses the system trust store.
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
