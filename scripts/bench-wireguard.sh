#!/usr/bin/env bash
# Cross-node WireGuard throughput baseline benchmark using iperf3.
# Sets up a WireGuard tunnel between two physical nodes over SSH and
# runs a TCP throughput test via iperf3.
#
# Prerequisites:
#   - Passwordless sudo on both nodes
#   - Passwordless SSH access to REMOTE
#   - wireguard kernel module, wg, iperf3, ip on both nodes
#
# Usage: ./scripts/bench-wireguard.sh
#
# Environment variables:
#   REMOTE     - remote hostname (default: mcnode26)
#   LOCAL_IP   - local underlay IP (default: 10.200.2.127)
#   REMOTE_IP  - remote underlay IP (default: 10.200.2.126)
#   TUN_MTU    - WireGuard interface MTU (default: 1291)
#   BENCH_DIR  - base benchmark directory (default: /tmp/bench)
#   IPERF_TIME - iperf3 test duration in seconds (default: 10)
set -euo pipefail
source "$(dirname "$0")/bench-common.sh"

# --- Configuration ---
WG_PORT=51820
WG_IF="wg-bench"

# WireGuard keys from bench-common.sh
KEY_A_PRIV="$WG_KEY_A_PRIV"
KEY_A_PUB="$WG_KEY_A_PUB"
KEY_B_PRIV="$WG_KEY_B_PRIV"
KEY_B_PUB="$WG_KEY_B_PUB"

# Initialized after first cleanup; guarded in cleanup() via ${KEY_DIR:-}.
KEY_DIR=""

# --- Prerequisites ---
require_cmds wg iperf3 ip ssh

# --- Cleanup ---
cleanup() {
    echo "[cleanup] Tearing down WireGuard interfaces..."
    sudo ip link del "$WG_IF" 2>/dev/null || true
    ssh "$REMOTE" "sudo ip link del \"$WG_IF\"" 2>/dev/null || true
    kill_remote_iperf
    if [[ -n "${KEY_DIR:-}" && -d "$KEY_DIR" ]]; then
        rm -rf "$KEY_DIR"
        ssh "$REMOTE" "rm -rf \"$KEY_DIR\"" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# Clean up leftovers from previous runs
cleanup

# --- Key files (avoids process substitution issues with sudo over SSH) ---
setup_wg_key_files "$KEY_A_PRIV" "$KEY_B_PRIV"

# --- Setup local WireGuard ---
sudo ip link add "$WG_IF" type wireguard
sudo wg set "$WG_IF" listen-port "$WG_PORT" private-key "$KEY_DIR/local.key" \
    peer "$KEY_B_PUB" allowed-ips "${REMOTE_TUN}/32" endpoint "${REMOTE_IP}:${WG_PORT}"
sudo ip addr add "${LOCAL_TUN}/32" dev "$WG_IF"
sudo ip link set "$WG_IF" mtu "$TUN_MTU" up
sudo ip route add "${REMOTE_TUN}/32" dev "$WG_IF"

# --- Setup remote WireGuard ---
ssh "$REMOTE" "\
    sudo ip link add \"$WG_IF\" type wireguard && \
    sudo wg set \"$WG_IF\" listen-port $WG_PORT private-key \"$KEY_DIR/remote.key\" \
        peer \"$KEY_A_PUB\" allowed-ips ${LOCAL_TUN}/32 endpoint ${LOCAL_IP}:${WG_PORT} && \
    sudo ip addr add ${REMOTE_TUN}/32 dev \"$WG_IF\" && \
    sudo ip link set \"$WG_IF\" mtu $TUN_MTU up && \
    sudo ip route add ${LOCAL_TUN}/32 dev \"$WG_IF\""

# --- Verify connectivity ---
if ! wait_for_connectivity "$REMOTE_TUN"; then
    sudo wg show "$WG_IF"
    ssh "$REMOTE" "sudo wg show \"$WG_IF\""
    exit 1
fi

# --- Benchmark ---
echo ""
print_banner "WireGuard Cross-Node Benchmark" \
    "TUN MTU: $TUN_MTU"

run_iperf_tcp "$REMOTE_TUN"

print_done
