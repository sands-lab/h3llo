#!/usr/bin/env bash
# HTTP/3 (CONNECT-IP) throughput benchmark using network namespaces and iperf3.
# Requires: root, iperf3, ip, openssl, h3llo binary
#
# Usage: sudo ./scripts/bench-h3.sh [iperf3-client-args...]
# Example: sudo ./scripts/bench-h3.sh -t 30
#          sudo ./scripts/bench-h3.sh -u -b 1G
#          sudo ./scripts/bench-h3.sh -J
#
# Environment variables:
#   H3LLO_BIN  - path to h3llo binary (default: /tmp/h3llo-musl)
#   VETH_MTU   - veth (underlay) MTU (default: 9000 for jumbo frames)
#   TUN_MTU    - TUN interface MTU (default: auto-computed from VETH_MTU)
set -euo pipefail

# --- Configuration ---
H3LLO_BIN="${H3LLO_BIN:-/tmp/h3llo-musl}"
# CONNECT-IP IPv4 overhead: 20 (IPv4) + 8 (UDP) + 59 (QUIC/H3) = 87 bytes
H3_OVERHEAD=87
VETH_MTU="${VETH_MTU:-1500}"
TUN_MTU="${TUN_MTU:-$((VETH_MTU - H3_OVERHEAD))}"
H3_CC="${H3_CC:-cubic}"

NS_A="h3llo-bench-h3-a"
NS_B="h3llo-bench-h3-b"
H3_PORT=4433
H3_PATH="/bench"
H3_TOKEN="bench-token-12ch"  # Test-only token, NOT for production

# --- Prerequisites ---
if [[ $EUID -ne 0 ]]; then echo "Error: must run as root" >&2; exit 1; fi
for cmd in iperf3 ip openssl; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "Error: $cmd not found" >&2; exit 1; }
done
if [[ ! -x "$H3LLO_BIN" ]]; then
    echo "Error: h3llo binary not found at $H3LLO_BIN" >&2
    echo "Build with: cargo build --release" >&2
    exit 1
fi

# --- Cleanup ---
TMPDIR=""
cleanup() {
    ip netns pids "$NS_A" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns pids "$NS_B" 2>/dev/null | xargs -r kill 2>/dev/null || true
    sleep 0.5
    ip link del veth-a 2>/dev/null || true
    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
    if [[ -n "$TMPDIR" ]]; then rm -rf "$TMPDIR"; fi
}
trap cleanup EXIT INT TERM

cleanup  # Remove leftover from a previous failed run
TMPDIR=$(mktemp -d)

# --- Generate self-signed TLS certificates ---
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$TMPDIR/node-a-key.pem" -out "$TMPDIR/node-a-cert.pem" \
    -days 1 -nodes -subj "/CN=192.168.100.1" \
    -addext "subjectAltName=IP:192.168.100.1" 2>/dev/null

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$TMPDIR/node-b-key.pem" -out "$TMPDIR/node-b-cert.pem" \
    -days 1 -nodes -subj "/CN=192.168.100.2" \
    -addext "subjectAltName=IP:192.168.100.2" 2>/dev/null

# --- Namespaces and veth pair ---
ip netns add "$NS_A"
ip netns add "$NS_B"

ip link add veth-a type veth peer name veth-b
ip link set veth-a netns "$NS_A"
ip link set veth-b netns "$NS_B"
ip netns exec "$NS_A" ip addr add 192.168.100.1/24 dev veth-a
ip netns exec "$NS_B" ip addr add 192.168.100.2/24 dev veth-b
ip netns exec "$NS_A" ip link set veth-a mtu "$VETH_MTU" up
ip netns exec "$NS_B" ip link set veth-b mtu "$VETH_MTU" up
ip netns exec "$NS_A" ip link set lo up
ip netns exec "$NS_B" ip link set lo up

# --- h3llo configs ---
cat > "$TMPDIR/node-a.yaml" <<EOF
local:
  table: true
  dns:
    server: "udp://127.0.0.1:53"
  tun:
    ifname: tun0
    addrs:
      - 10.0.0.1/32
    mtu: $TUN_MTU
  h3:
    listen: "https://0.0.0.0:${H3_PORT}${H3_PATH}"
    cert: "$TMPDIR/node-a-cert.pem"
    key: "$TMPDIR/node-a-key.pem"
tuning:
  h3_cc_algorithm: $H3_CC
peers:
  - id: node-b
    enabled: true
    h3:
      token: "$H3_TOKEN"
      endpoint: "https://192.168.100.2:${H3_PORT}${H3_PATH}"
      insecure: true
    tun:
      allowed_ips:
        - 10.0.0.2/32
EOF

cat > "$TMPDIR/node-b.yaml" <<EOF
local:
  table: true
  dns:
    server: "udp://127.0.0.1:53"
  tun:
    ifname: tun0
    addrs:
      - 10.0.0.2/32
    mtu: $TUN_MTU
  h3:
    listen: "https://0.0.0.0:${H3_PORT}${H3_PATH}"
    cert: "$TMPDIR/node-b-cert.pem"
    key: "$TMPDIR/node-b-key.pem"
tuning:
  h3_cc_algorithm: $H3_CC
peers:
  - id: node-a
    enabled: true
    h3:
      token: "$H3_TOKEN"
      endpoint: "https://192.168.100.1:${H3_PORT}${H3_PATH}"
      insecure: true
    tun:
      allowed_ips:
        - 10.0.0.1/32
EOF

echo "=== HTTP/3 (CONNECT-IP) Throughput Benchmark ==="
echo "  TUN MTU:      $TUN_MTU"
echo "  Veth MTU:     $VETH_MTU"
echo "  H3 overhead:  $H3_OVERHEAD bytes (IPv4)"
echo "  CC algorithm: $H3_CC"
echo "  Binary:       $H3LLO_BIN"

# --- Start h3llo ---
ip netns exec "$NS_A" "$H3LLO_BIN" -c "$TMPDIR/node-a.yaml" &
ip netns exec "$NS_B" "$H3LLO_BIN" -c "$TMPDIR/node-b.yaml" &

sleep 5  # Wait for TUN creation, TLS handshake, and CONNECT-IP setup

# --- Verify connectivity ---
ip netns exec "$NS_A" ping -c 2 -W 2 10.0.0.2 >/dev/null || {
    echo "Error: tunnel ping failed" >&2; exit 1
}
echo "  Connectivity: OK"

# --- Benchmark ---
ip netns exec "$NS_B" iperf3 -s -1 -D
sleep 0.5  # Wait for iperf3 daemon to bind
ip netns exec "$NS_A" iperf3 -c 10.0.0.2 "$@"
