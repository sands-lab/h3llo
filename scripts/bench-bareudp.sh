#!/usr/bin/env bash
# BareUDP throughput benchmark using network namespaces and iperf3.
# Requires: root, iperf3, ip, h3llo binary
#
# Usage: sudo ./scripts/bench-bareudp.sh [iperf3-client-args...]
# Example: sudo ./scripts/bench-bareudp.sh -t 30
#          sudo ./scripts/bench-bareudp.sh -u -b 1G
#          sudo ./scripts/bench-bareudp.sh -J
#
# Environment variables:
#   H3LLO_BIN  - path to h3llo binary (default: ./target/release/h3llo)
#   TUN_MTU    - TUN interface MTU (default: 1393)
set -euo pipefail

# --- Configuration ---
H3LLO_BIN="${H3LLO_BIN:-/tmp/h3llo-musl}"
TUN_MTU="${TUN_MTU:-1393}"
# BareUDP IPv4 overhead: 20 (IPv4) + 8 (UDP) = 28 bytes
VETH_MTU=$((TUN_MTU + 28))

NS_A="h3llo-bench-a"
NS_B="h3llo-bench-b"

# --- Prerequisites ---
if [[ $EUID -ne 0 ]]; then echo "Error: must run as root" >&2; exit 1; fi
for cmd in iperf3 ip; do
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
  bare:
    listen: "udp://0.0.0.0:5353"
peers:
  - id: node-b
    bare:
      endpoint: "udp://192.168.100.2:5353"
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
  bare:
    listen: "udp://0.0.0.0:5353"
peers:
  - id: node-a
    bare:
      endpoint: "udp://192.168.100.1:5353"
    tun:
      allowed_ips:
        - 10.0.0.1/32
EOF

echo "=== BareUDP Throughput Benchmark ==="
echo "  TUN MTU:   $TUN_MTU"
echo "  Veth MTU:  $VETH_MTU"
echo "  Binary:    $H3LLO_BIN"

# --- Start h3llo ---
ip netns exec "$NS_A" "$H3LLO_BIN" -c "$TMPDIR/node-a.yaml" &
ip netns exec "$NS_B" "$H3LLO_BIN" -c "$TMPDIR/node-b.yaml" &

sleep 3  # Wait for TUN creation and peer connection

# --- Verify connectivity ---
ip netns exec "$NS_A" ping -c 2 -W 2 10.0.0.2 >/dev/null || {
    echo "Error: tunnel ping failed" >&2; exit 1
}
echo "  Connectivity: OK"

# --- Benchmark ---
ip netns exec "$NS_B" iperf3 -s -1 -D
sleep 0.5  # Wait for iperf3 daemon to bind
ip netns exec "$NS_A" iperf3 -c 10.0.0.2 "$@"
