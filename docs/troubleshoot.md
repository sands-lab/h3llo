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

Set `RUST_LOG=h3llo=debug` to expose QUIC handshake steps, socket binding, and packet counters:

```bash
docker run -d --name h3llo-debug \
  -e RUST_LOG=h3llo=debug \
  ... h3llo:test
```

Key log lines to look for:

| Log line | Meaning |
|----------|---------|
| `H3 listener state created` | QUIC listen socket bound successfully |
| `dialing H3 endpoint` | Outbound QUIC handshake started |
| `H3 connection established` | QUIC handshake completed |
| `CONNECT-IP accepted` | H3 CONNECT-IP session active, tunnel ready |
| `multiple interfaces found` | Interface auto-detection ambiguity (see [Multi-NIC binding](#silent-h3quic-connection-failure-on-multi-nic-hosts)) |

If none of the connection log lines appear, the handshake is failing silently — check `bindif`, TLS certs, and network reachability.

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
```

The drop location tells you where the bottleneck is:

| Drop location | Counter | Likely cause |
|---------------|---------|--------------|
| TUN TX dropped | `ip -s link show` | h3llo reads TUN too slowly; increase `packet_queue_depth` |
| UDP socket drops | `/proc/net/udp` `drops` column | h3llo reads socket too slowly; increase `socket_buffer_size` |
| UdpRcvbufErrors | `nstat` | Kernel UDP receive buffer overflow; increase `socket_buffer_size` or `net.core.rmem_max` |
| UdpInCsumErrors | `nstat` | NIC checksum offload incompatibility (see [BareUDP Checksum Errors](#bareudp-checksum-errors-with-nic-tx-offload)) |

## Common Issues

### Silent H3/QUIC Connection Failure on Multi-NIC Hosts

**Symptom**: H3 tunnel shows no connection errors in logs, but ping through the tunnel fails with 100% packet loss. Logs only show TUN setup and route warnings — no QUIC handshake attempt or TLS error.

**Root cause**: When `peers[].h3.bindif` is omitted, h3llo auto-detects the outbound interface via route probing. If multiple physical interfaces share the same subnet (e.g., `cx7p0` at `10.200.2.27/24` and `bf3p1` at `10.200.2.127/24`), the probe returns all candidates and h3llo picks the first one. The QUIC socket is then bound to that interface via `SO_BINDTODEVICE`.

If the chosen interface is **not** the one whose IP is used in `local.h3.listen` or the peer's `endpoint`, packets arrive on the correct NIC but the kernel refuses to deliver them to the socket bound to a different device. The QUIC handshake silently fails with no error logged.

**Diagnostic clues**:

- Log line: `WARN h3llo::bind: multiple interfaces found, using first chosen=<wrong-iface> alternatives=[...]`
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

**Symptom**: h3llo selects the wrong outbound interface when the host has policy routing rules (`ip rule`) that direct traffic to custom routing tables. The log shows `multiple interfaces found, using first chosen=<iface>` but the kernel would route via a different interface.

**Root cause**: h3llo probes all routing tables via `route_manager` and applies a heuristic: longest prefix match → main table (254) preferred → lower metric within the same table. This heuristic does not evaluate `ip rule` priorities, source-based routing, or fwmark-based rules. When policy routing is configured, the kernel's actual route selection follows the RPDB rule chain, which may pick a different table (and therefore a different interface) than h3llo's heuristic.

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

**Root cause**: On NFS mounts with `root_squash` (the default), the NFS server maps UID 0 (root inside the container) to `nobody`/`nfsnobody`. Private key files typically have `0600` permissions owned by the creating user. When the container process (running as root) tries to read the key via NFS, the squashed UID has no read permission.

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

**Fix**: Disable hardware UDP segmentation offload on the **sending** interface:

```bash
ethtool -K <iface> tx-udp-segmentation off
```

The kernel software GSO path computes checksums correctly and can still achieve multi-Gbps throughput.

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
- **Debug logging**: Pass `-e RUST_LOG=h3llo=debug` for verbose output; this is an environment variable, not a config file option.
