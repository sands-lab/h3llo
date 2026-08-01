# Troubleshooting

This page covers general debugging methodology, then lists known issues with symptoms and fixes.

## General Troubleshooting Method

When the tunnel is not working, follow this sequence to isolate the problem.

### 1. Check container / process status

```bash
docker ps --filter name=h3llo          # is the container running?
docker logs h3llo-bench 2>&1 | tail -20 # any startup errors?
```

If the container exits immediately, check the log for initialization errors (TUN creation, config parsing, TLS cert loading). See [Common Issues](#common-issues) for specific error messages.

### 2. Enable debug logging

h3llo's default log filter is `warn,h3llo=info` — it shows warnings and errors from all
dependencies plus info-level messages from h3llo itself. Set `RUST_LOG=h3llo=debug` to expose
QUIC handshake steps, socket binding, and packet counters:

```bash
docker run -d --name h3llo-debug \
  -e RUST_LOG=h3llo=debug \
  ... h3llo:test
```

This enables debug-level output from h3llo while keeping third-party crates at the default `warn`.

Key log lines to look for:

| Log line | Meaning |
|----------|---------|
| `H3 listener state created` | QUIC listen socket bound successfully |
| `dialing H3 endpoint` | Outbound QUIC handshake started |
| `H3 connection established` | QUIC handshake completed |
| `CONNECT-IP accepted` | H3 CONNECT-IP session active, tunnel ready |
| `multiple interfaces found` | Interface auto-detection ambiguity (see [Multi-NIC binding](#silent-h3quic-connection-failure-on-multi-nic-hosts)) |

If none of the connection log lines appear, the handshake is failing silently — check `bindif`, TLS certs, and network reachability.

#### Third-party library logging

h3llo depends on libraries that emit their own log messages. By default, only `warn` and `error`
from these libraries are shown. To enable more verbose output from a specific library, add its
tracing target name to `RUST_LOG`:

| Library | Target name | Framework | What it logs |
|---------|-------------|-----------|--------------|
| hickory-proto | `hickory_proto` | tracing | DNS resolution: query failures, NXDOMAIN, truncation |
| h2 | `h2` | tracing | HTTP/2 framing (used internally by hyper) |
| hyper-util | `hyper_util` | tracing | HTTP server lifecycle |
| quinn-udp | `quinn_udp` | tracing | UDP socket send/receive operations |
| quiche | `quiche` | log (bridged) | QUIC protocol core: handshake, congestion, frames |
| tokio-quiche | `tokio_quiche` | foundations (bridged to tracing) | QUIC async runtime: connection lifecycle, send errors, GSO failures |
| tun-rs | `tun_rs` | log (bridged) | TUN device creation and I/O |
| route_manager | `route_manager` | none | Route management — no log output currently emitted |

Crate names containing `-` become `_` in tracing targets. Libraries using the `log` crate are
automatically bridged to tracing via `tracing-log`. tokio-quiche uses `foundations::telemetry::log`
macros (slog-based); h3llo bridges these to tracing via `foundations::telemetry::init()` with
`LogOutput::TracingRsCompat`.

**Examples**:

```bash
# Debug DNS resolution issues
RUST_LOG=warn,h3llo=info,hickory_proto=debug

# Debug QUIC connection issues
RUST_LOG=warn,h3llo=info,quiche=debug

# Debug tokio-quiche runtime (connection lifecycle, send errors)
RUST_LOG=warn,h3llo=info,tokio_quiche=info

# Debug both QUIC layers together
RUST_LOG=warn,h3llo=info,quiche=debug,tokio_quiche=debug

# Debug TUN device issues
RUST_LOG=warn,h3llo=info,tun_rs=debug

# Full trace from all dependencies (very verbose)
RUST_LOG=trace
```

### 3. Verify underlay reachability

Confirm the two nodes can reach each other on the QUIC/BareUDP port **outside** the tunnel:

```bash
# From node A, test UDP reachability to node B
echo test | nc -u -w1 <node-B-IP> <port>

# Check if the socket is listening
ss -unlp sport = :<port>
```

### 4. Verify tunnel connectivity

```bash
docker exec h3llo-bench ping -c 3 -W 3 <peer-tunnel-IP>
```

### 5. Inspect counters for packet loss

Once the tunnel is up but throughput is poor, check drop counters at each stage:

```bash
# TUN interface drops
docker exec h3llo-bench ip -s link show <tun-ifname>

# UDP socket drops (look for the 'drops' column at the end)
docker exec h3llo-bench cat /proc/1/net/udp | grep <hex-port>

# System-wide UDP buffer overflows
nstat -az | grep -E 'UdpRcvbufErrors|UdpSndbufErrors|UdpInCsumErrors'

# Socket buffer size and current drops (d=N at the end)
ss -unmap src :<port>

# Softnet statistics (per-CPU softirq queue overflow and time squeeze)
cat /proc/net/softnet_stat

# Qdisc drops on physical interface and TUN
tc -s qdisc show dev <phy-interface>
tc -s qdisc show dev <tun-ifname>

# NIC driver-level drops and errors
ethtool -S <phy-interface>
```

The drop location tells you where the bottleneck is:

| Drop location | Counter | Likely cause |
|---------------|---------|--------------|
| TUN TX dropped | `ip -s link show` | h3llo reads TUN too slowly; increase `packet_queue_depth` |
| UDP socket drops | `/proc/net/udp` `drops` column | h3llo reads socket too slowly; increase `socket_buffer_size` |
| UdpRcvbufErrors | `nstat` | Kernel UDP receive buffer overflow; increase `socket_buffer_size` or `net.core.rmem_max` |
| UdpInCsumErrors | `nstat` | NIC checksum offload incompatibility (see [BareUDP Checksum Errors](#bareudp-checksum-errors-with-nic-tx-offload)) |
| softnet dropped | `/proc/net/softnet_stat` col 2 | CPU softirq overload; tune RPS/RFS, increase `netdev_budget`, or rebalance IRQ affinity |
| softnet time_squeeze | `/proc/net/softnet_stat` col 3 | Softirq ran out of time/budget; increase `net.core.netdev_budget_usecs` |
| qdisc drops | `tc -s qdisc show` | Egress queue overflow; switch to `fq` qdisc, tune pacing, or increase queue length |
| NIC rx_missed/rx_dropped | `ethtool -S` | NIC ring buffer full; increase with `ethtool -G <if> rx <size>` |

## Common Issues

### DNS Resolution Failure Due to Query Burst Rate Limiting

**Symptom**: Some or all peer endpoints fail to resolve on startup. Logs show `dns: response truncated, will retry` warnings and/or `dns: query timed out, retrying` for multiple hostnames. Affected peers never establish QUIC connections. The issue is intermittent — restarting may resolve a different subset of hostnames each time.

**Root cause**: On startup, h3llo issues A and AAAA queries for every peer endpoint hostname simultaneously. With many peers (e.g., 20+ peers = 40+ concurrent queries), the burst of UDP packets sent to a remote public DNS resolver (e.g., `1.1.1.1`, `8.8.8.8`) can trigger server-side rate limiting. The resolver responds with truncated (`TC=1`) or empty responses for the excess queries. h3llo treats truncated responses as packet loss and retries after `dns_query_timeout` (default 2s), but if the server persistently truncates under load, retries will also be truncated.

The severity depends on the number of peers and the DNS server's rate-limiting policy. A mesh with 5 peers may work fine; a mesh with 20+ peers will likely hit the limit on remote resolvers.

**Diagnostic clues**:

With 20+ peers and `dns.server: udp://1.1.1.1:53`, startup logs will show a burst of truncation warnings within the same millisecond:

```
WARN h3llo::dns: dns: response truncated, will retry host=peer1.example.com
WARN h3llo::dns: dns: response truncated, will retry host=peer2.example.com
WARN h3llo::dns: dns: response truncated, will retry host=peer3.example.com
WARN h3llo::dns: dns: response truncated, will retry host=peer4.example.com
WARN h3llo::dns: dns: response truncated, will retry host=peer5.example.com
...  (28 warnings in <3ms)
```

To confirm:

```bash
# Look for truncation warnings in logs
docker logs <container> 2>&1 | grep -i "truncated"

# Check if some peers have no resolved IPs (no "dialing H3 endpoint" log for those peers)
docker logs <container> 2>&1 | grep "dialing H3 endpoint"
```

**Fix**: Use a local caching resolver instead of a remote public resolver:

```yaml
local:
  dns:
    server: udp://127.0.0.53:53    # systemd-resolved (local cache)
    # server: udp://1.1.1.1:53     # avoid: rate-limited under burst
```

The local resolver (e.g., systemd-resolved at `127.0.0.53`) absorbs the query burst locally, deduplicates identical queries, and handles upstream TCP fallback transparently. This eliminates both the rate-limiting and truncation issues.

> **Note**: h3llo's DNS implementation uses plain UDP without EDNS0 and does not fall back to TCP on truncation. Truncated responses are treated as packet loss — the pending query is preserved and retried after `dns_query_timeout` (default 2s) with a new transaction ID. However, if the server persistently truncates (e.g., due to rate limiting under burst), retries will also be truncated until the burst subsides. Using a local caching resolver (as recommended above) remains the most effective mitigation.

### Silent H3/QUIC Connection Failure on Multi-NIC Hosts

**Symptom**: H3 tunnel shows no connection errors in logs, but ping through the tunnel fails with 100% packet loss. Logs only show TUN setup and route warnings — no QUIC handshake attempt or TLS error.

**Root cause**: When `peers[].h3.bindif` is omitted, h3llo auto-detects the outbound interface via route probing. If multiple physical interfaces share the same subnet (e.g., `cx7p0` at `10.200.2.27/24` and `bf3p1` at `10.200.2.127/24`), the probe returns all candidates and h3llo picks the first one. The QUIC socket is then bound to that interface via `SO_BINDTODEVICE`.

If the chosen interface is **not** the one whose IP is used in `local.h3.listen` or the peer's `endpoint`, packets arrive on the correct NIC but the kernel refuses to deliver them to the socket bound to a different device. The QUIC handshake silently fails with no error logged.

**Diagnostic clues**:

- Log line: `WARN h3llo::bind: multiple interfaces found, using first; if policy routing is active, this heuristic may differ from the kernel's route selection — set bindif explicitly chosen=<wrong-iface> alternatives=[...]`
- No `H3 connection established` or `CONNECT-IP accepted` log entries.
- The peer's `endpoint` IP belongs to an interface listed in `alternatives`, not `chosen`.

**Fix**: Explicitly set `peers[].h3.bindif` to the correct interface:

```yaml
peers:
  - id: remote-node
    h3:
      endpoint: "https://10.200.2.127:4433/path"
      bindif: bf3p1        # ← match the interface that owns the endpoint IP
      token: <token>
      insecure: true
    tun:
      allowed_ips:
        - 10.99.0.1/32
```

The same applies to `peers[].bare.bindif` for BareUDP and `local.dns.bindif` for DNS resolution.

**Affected topology**: Hosts with multiple NICs on the same IP subnet (common with SmartNICs like NVIDIA BlueField where `cx7p0`, `bf3p0`, `bf3p1` may all sit on the same `/24`).

### Interface Selection Mismatch with Policy Routing

**Symptom**: h3llo selects the wrong outbound interface when the host has policy routing rules (`ip rule`) that direct traffic to custom routing tables. The log shows `multiple interfaces found, using first; if policy routing is active, this heuristic may differ from the kernel's route selection — set bindif explicitly chosen=<iface>` but the kernel would route via a different interface.

**Root cause**: h3llo probes all routing tables via `route_manager` and applies a heuristic: longest prefix match → main table (254) preferred → lower metric within the same table category (main vs. non-main). This heuristic does not evaluate `ip rule` priorities, source-based routing, or fwmark-based rules. When policy routing is configured, the kernel's actual route selection follows the RPDB rule chain, which may pick a different table (and therefore a different interface) than h3llo's heuristic.

**Example**: A host with three default routes across tables `1444579712`, `176`, and `main (254)`. h3llo prefers the main table route (correct for most cases), but the kernel may follow a higher-priority `ip rule` that directs traffic to table `176` based on source address.

**Fix**: Explicitly set `bindif` for each transport when policy routing is active:

```yaml
local:
  dns:
    bindif: enp0s6
peers:
  - id: remote
    h3:
      bindif: enp0s6
    bare:
      bindif: enp0s6
```

**Diagnostic**: Check which routing tables and rules exist:

```bash
ip rule show
ip route show table main
ip route show table all
```

### TLS Certificate Errors on NFS-Mounted Paths

**Symptom**: h3llo logs a TLS error at startup (e.g., `tls error`, `failed to read private key`, or a rustls/quinn handshake failure) even though the certificate and key files exist and appear correct.

**Root cause**: On NFS mounts with `root_squash` (the default), the NFS server maps UID 0 (root inside the container) to `nobody`/`nfsnobody`. Private key files typically have `0600` permissions owned by the creating user. When the container process (running as root) tries to read the key via NFS, the squashed UID has no read permission. Native filesystem watchers also do not reliably receive remote NFS changes, so hot reload can remain idle even when permissions allow reading.

This manifests differently from a missing file — the file is visible in `ls -la`, but reading by root inside the container fails with a permission error that surfaces as a TLS initialization failure.

**Diagnostic steps**:

```bash
# 1. Check if the cert path is on NFS
df /path/to/certs/

# 2. Test if root in the container can actually read the key
docker exec h3llo cat /certs/key.pem > /dev/null && echo readable || echo NOT-readable

# 3. Check file permissions
docker exec h3llo ls -la /certs/
```

**Fix**: Store TLS certificates on a **local filesystem** (not NFS). On most systems, `/tmp` is on a local disk:

```bash
# Generate certs on local storage
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout /tmp/h3llo-key.pem -out /tmp/h3llo-cert.pem \
  -days 365 -nodes -subj "/CN=<node-IP>" \
  -addext "subjectAltName=IP:<node-IP>"

# Mount from local path
docker run -d \
  -v /tmp/h3llo-cert.pem:/certs/cert.pem:ro \
  -v /tmp/h3llo-key.pem:/certs/key.pem:ro \
  ...
```

Alternatively, if NFS is unavoidable, either disable `root_squash` on the export or `chmod 644` the key file (less secure — only acceptable for test environments).

### TLS Certificate Hot Reload Does Not Trigger

**Symptom**: The certificate files changed, but no `TLS certificate reloaded` log appears and new H3 connections still receive the previous certificate.

**Common causes**:

- **File-only container mount**: A certificate or key was bind-mounted as an individual file. Atomic replacement changes the host directory entry while the container mount can remain attached to the old file. Mount the containing directory read-only instead.
- **Kubernetes `subPath`**: Secret volume updates are not propagated through `subPath` mounts. Mount the complete Secret or projected volume directory.
- **Network filesystem**: NFS and similar filesystems may not emit native notification events. Copy credentials onto a local filesystem before rotation or restart h3llo after renewal.
- **Parent replacement**: The credential parent directory itself was replaced. Keep the watched directory stable and rotate its child files or symlinks.
- **Invalid pair**: h3llo detected the change but logged `TLS certificate reload rejected; retaining previous certificate`. Check that the leaf certificate and private key match and that both files are readable.

**Recommended container mount**:

```bash
docker run -d \
  --mount type=bind,src=/host/h3llo-certs,dst=/etc/h3llo/certs,readonly \
  ... \
  h3llo -c /etc/h3llo/config.yaml
```

Configure `cert: /etc/h3llo/certs/cert.pem` and `key: /etc/h3llo/certs/key.pem`, then stage and rename both files inside `/host/h3llo-certs`. Hot reload affects only new handshakes; existing H3 connections intentionally keep their established TLS sessions.

### Silent QUIC Handshake Timeout Due to TLS Certificate SAN Mismatch

**Symptom**: All outbound QUIC handshakes time out. Logs show `H3 dial failed peer=<name> addr=<ip>:443 error=handshake failed: QUIC connect failed: connection <scid> timed out`. Inbound connections from peers fail with `QUIC handshake failed in IQC::start, error: connection closed during Handshake stage`. tcpdump confirms packets are exchanged in both directions (Initial and Handshake packets flow normally), yet no connection is ever established.

**Root cause**: The TLS certificate's Subject Alternative Name (SAN) does not cover the hostnames used in `peers[].h3.endpoint`. For example, the cert has `DNS:*.api.example.com` but endpoints use `https://node.v4.example.com:443/h3llo`. When `tuning.h3_insecure_skip_verify` is `false` (the default), quiche's BoringSSL backend verifies the server certificate against the SNI and silently rejects the handshake when the SAN doesn't match.

"Silently" is the key word: **no TLS error, alert code, or certificate detail is logged at any level** — not even at `quiche=trace`. BoringSSL rejects the cert internally, the client simply stops progressing the handshake, and the connection eventually times out. The only observable difference between this failure and a network blackhole is that tcpdump shows Handshake packets being exchanged (the server sends its certificate, the client ACKs it, then goes silent).

**Diagnostic steps**:

```bash
# 1. Check the cert's SAN
openssl x509 -in /path/to/cert -noout -ext subjectAltName
# Output: DNS:*.api.example.com
# Compare with the endpoint hostnames (e.g., node.v4.example.com) — they must match.

# 2. Confirm packets flow but handshake stalls
# If tcpdump shows Initial+Handshake exchange in both directions but
# no 1-RTT packets follow, TLS verification failure is the likely cause.
tcpdump -i <iface> -n 'udp port 443 and host <peer-ip>' -c 20

# 3. (Optional) Enable quiche=trace to see the handshake stall point
# You will see rx/tx of Handshake packets, then silence — no "send alert" or
# certificate error. This confirms BoringSSL rejects the cert without logging.
RUST_LOG=h3llo=debug,quiche=trace
```

**Fix**: Either issue a certificate whose SAN covers the endpoint hostnames, or disable verification:

```yaml
tuning:
  h3_insecure_skip_verify: true   # disables TLS peer verification
```

> **Note on observability**: This is a known gap — quiche and BoringSSL do not surface TLS verification failure reasons. Even `quiche=trace` only shows packet-level events (rx/tx pkt) without any TLS error detail. If you see a normal Initial → Handshake packet exchange followed by silence, suspect certificate SAN mismatch first.

### GSO (UDP_SEGMENT) sendto EINVAL on aarch64

**Symptom**: All outbound QUIC handshakes time out. Logs show only `H3 dial failed ... timed out` with **no send errors visible in h3llo's default log output**. tcpdump shows zero outbound QUIC packets — the node appears completely silent on the network.

**Root cause**: On Linux, h3llo calls `apply_max_capabilities()` on QUIC sockets when `tuning.udp_enable_offload` is `true` (disabled by default), which enables `UDP_SEGMENT` (Generic Segmentation Offload). On certain aarch64 kernels (observed on Oracle Cloud Linux 6.5 aarch64), the kernel does not support `UDP_SEGMENT` on the socket path used, causing every subsequent `sendto()` to fail with `EINVAL` (errno 22). No QUIC packets are ever transmitted.

tokio-quiche logs the `EINVAL` via `foundations::telemetry::log` (slog-based), bridged to tracing.
The error appears at `warn` level by default: `WARN tokio_quiche: error sending client Initial packets to peer, error: Invalid argument (os error 22)`.

**Diagnostic steps**:

```bash
# 1. Check if ANY outbound QUIC packets leave the host
tcpdump -i <iface> -n 'udp port 443' -c 5
# If zero outbound packets appear, sendto() is likely failing.

# 2. Confirm EINVAL with strace
strace -e sendto -p $(pgrep h3llo) 2>&1 | head -10
# Look for: sendto(...) = -1 EINVAL (Invalid argument)

# 3. Check architecture — this affects aarch64 primarily
uname -m   # aarch64

# 4. Look for the tokio-quiche send error:
RUST_LOG=warn,h3llo=info,tokio_quiche=info docker restart h3llo
docker logs h3llo 2>&1 | grep "error sending"
```

**Fix**: Disable UDP offload in the configuration:

```yaml
tuning:
  udp_enable_offload: false
```

> **Note on observability**: tokio-quiche's send errors are bridged to tracing and visible at `warn` level by default. Set `RUST_LOG=warn,h3llo=info,tokio_quiche=info` for additional QUIC runtime detail.

### BareUDP Checksum Errors with NIC TX Offload

**Symptom**: High `UdpInCsumErrors` in `/proc/net/snmp` on the receiver and severe TCP retransmits inside the BareUDP tunnel. Throughput drops to ~1/30 of expected. UDP-over-tunnel traffic (e.g., iperf3 `-u`) may appear less affected than TCP-over-tunnel.

**Root cause**: On certain NICs (observed on Mellanox ConnectX / BlueField mlx5, firmware 32.46.x), hardware UDP TX checksum offload produces incorrect checksums for BareUDP traffic. The suspected cause is the NIC hardware parser misidentifying the raw IP payload inside the UDP datagram as an encapsulated tunnel packet, which confuses the TX checksum calculation. HTTP/3 traffic is unaffected because QUIC encryption makes the payload opaque to the parser.

**Diagnostic steps**:

```bash
# Check checksum error counter on the receiver
nstat -az | grep UdpInCsumErrors

# Check if TX UDP segmentation offload is enabled on the sender
ethtool -k <iface> | grep tx-udp-segmentation
```

If `UdpInCsumErrors` grows rapidly during BareUDP transfers but not during H3 transfers, this is almost certainly the cause.

**Fix**: Either disable hardware UDP segmentation offload on the **sending** interface:

```bash
ethtool -K <iface> tx-udp-segmentation off
```

The kernel software GSO path computes checksums correctly and can still achieve multi-Gbps throughput.

Alternatively, disable software GSO in h3llo to avoid triggering the NIC offload path entirely:

```yaml
tuning:
  udp_enable_offload: false
```

### Docker Container Missing Required Flags

**Symptom**: h3llo exits immediately with `failed to build TUN device: No such file or directory (os error 2)`, `EPERM` errors, or the TUN interface is created but unreachable from the host.

**Root cause**: h3llo requires three Docker flags to function. Missing any one causes a distinct failure:

| Flag | Purpose | Error if missing |
|------|---------|------------------|
| `--net=host` | Share host network namespace so TUN and routes are visible to the host | TUN is created in an isolated namespace; traffic never reaches the host |
| `--cap-add NET_ADMIN` | Allow creating TUN devices, setting routes, and configuring interfaces | `EPERM` on TUN creation or `ip link` / `ip route` operations |
| `--device /dev/net/tun` | Expose the kernel TUN/TAP device node inside the container | `No such file or directory (os error 2)` |

**Fix**: Always include all three flags:

```bash
docker run -d --name h3llo-bench \
  --net=host \
  --cap-add NET_ADMIN \
  --device /dev/net/tun \
  -v /path/to/config.yaml:/etc/h3llo/config.yaml:ro \
  h3llo:test
```

For H3 mode, add TLS certificate mounts:

```bash
docker run -d --name h3llo-h3 \
  --net=host --cap-add NET_ADMIN --device /dev/net/tun \
  -v /tmp/config.yaml:/etc/h3llo/config.yaml:ro \
  -v /tmp/cert.pem:/certs/cert.pem:ro \
  -v /tmp/key.pem:/certs/key.pem:ro \
  h3llo:test
```

**Additional notes**:

- **Config updates**: The config file is bind-mounted, so `docker cp` cannot overwrite it (`device or resource busy`). Edit the host-side file and `docker restart` instead.
- **Stale containers**: `docker run` fails if a container with the same `--name` already exists (even if stopped). Remove first with `docker rm -f <name>`.
- **Debug logging**: Pass `-e RUST_LOG=h3llo=debug` for verbose h3llo output. For third-party library logs, add targets like `quiche=debug`; see [Enable debug logging](#2-enable-debug-logging) for the full target list. `RUST_LOG` is an environment variable, not a config file option.
