#!/usr/bin/env bash
# WireGuard throughput baseline benchmark using network namespaces and iperf3.
# Requires: root, wireguard kernel module, wg, iperf3, ip
#
# Usage: sudo ./scripts/bench-wireguard.sh [iperf3-client-args...]
# Example: sudo ./scripts/bench-wireguard.sh -t 30
#          sudo ./scripts/bench-wireguard.sh -u -b 1G
#          sudo ./scripts/bench-wireguard.sh -J
set -euo pipefail

# --- Prerequisites ---
if [[ $EUID -ne 0 ]]; then echo "Error: must run as root" >&2; exit 1; fi
for cmd in wg iperf3 ip ping; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "Error: $cmd not found" >&2; exit 1; }
done
if ! ip link add wg-probe type wireguard 2>/dev/null; then
    echo "Error: WireGuard kernel module not loaded (try: modprobe wireguard)" >&2
    exit 1
fi
ip link del wg-probe 2>/dev/null

# --- Fixed Curve25519 keys (test-only, NOT for production) ---
# Generated via: wg genkey | tee priv | wg pubkey > pub
KEY_A_PRIV="yAnw4/bFKWQyuiDKWrXruXyKk/Ah1CJWQfV0FTXcXWU="
KEY_A_PUB="xopHDYsmeG7tk7UdovGv7RUBaiD1sADUrIlujSYHVFY="
KEY_B_PRIV="0AMR6oqMwHg1NDZMRMtRXi/xd3Ot6Camb1euWJY1lWI="
KEY_B_PUB="mqgf3siT/qS86WCoYmZFaXHUx5JRGSFVfjU4avuNanM="

# --- Namespaces and interfaces ---
NS_A="wg-bench-a"
NS_B="wg-bench-b"

cleanup() {
    # Namespace deletion also kills all processes within the namespace.
    # Deleting one veth end auto-destroys its peer; this handles the window
    # between veth creation and moving both ends into namespaces.
    ip link del veth-a 2>/dev/null || true
    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

cleanup  # Remove leftover namespaces from a previous failed run
ip netns add "$NS_A"
ip netns add "$NS_B"

# Veth pair for underlay connectivity between namespaces
ip link add veth-a type veth peer name veth-b
ip link set veth-a netns "$NS_A"
ip link set veth-b netns "$NS_B"
ip netns exec "$NS_A" ip addr add 192.168.100.1/24 dev veth-a
ip netns exec "$NS_B" ip addr add 192.168.100.2/24 dev veth-b
ip netns exec "$NS_A" ip link set veth-a up
ip netns exec "$NS_B" ip link set veth-b up

# WireGuard interfaces
ip netns exec "$NS_A" ip link add wg0 type wireguard
ip netns exec "$NS_B" ip link add wg0 type wireguard
ip netns exec "$NS_A" wg set wg0 listen-port 51820 private-key <(echo "$KEY_A_PRIV") \
    peer "$KEY_B_PUB" allowed-ips 10.0.0.2/32 endpoint 192.168.100.2:51820
ip netns exec "$NS_B" wg set wg0 listen-port 51820 private-key <(echo "$KEY_B_PRIV") \
    peer "$KEY_A_PUB" allowed-ips 10.0.0.1/32 endpoint 192.168.100.1:51820
ip netns exec "$NS_A" ip addr add 10.0.0.1/24 dev wg0
ip netns exec "$NS_B" ip addr add 10.0.0.2/24 dev wg0
# Match h3llo default TUN MTU (1393) for fair comparison.
ip netns exec "$NS_A" ip link set wg0 mtu 1393 up
ip netns exec "$NS_B" ip link set wg0 mtu 1393 up

# --- Verify connectivity ---
ip netns exec "$NS_A" ping -c 1 -W 2 10.0.0.2 >/dev/null || { echo "Error: WireGuard ping failed" >&2; exit 1; }

# --- Benchmark ---
echo "=== WireGuard Throughput Baseline ==="
ip netns exec "$NS_B" iperf3 -s -1 -D
sleep 0.5  # Wait for iperf3 daemon to bind; increase if "connection refused" on slow hosts
ip netns exec "$NS_A" iperf3 -c 10.0.0.2 "$@"
