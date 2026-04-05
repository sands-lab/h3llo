#!/usr/bin/env bash
# Cross-node wireguard-go (userspace) throughput benchmark using iperf3.
# Sets up a WireGuard tunnel via wireguard-go between two physical nodes
# over SSH and runs a TCP throughput test via iperf3.
#
# Prerequisites:
#   - Passwordless sudo on both nodes
#   - Passwordless SSH access to REMOTE
#   - wireguard-go, wg, iperf3, ip on both nodes
#
# Usage: ./scripts/bench-wireguard-go.sh
#
# Environment variables:
#   REMOTE     - remote hostname (default: mcnode26)
#   LOCAL_IP   - local underlay IP (default: 10.200.2.127)
#   REMOTE_IP  - remote underlay IP (default: 10.200.2.126)
#   TUN_MTU    - WireGuard interface MTU (default: 1291)
#   BENCH_DIR  - base benchmark directory (default: /tmp/bench)
#   IPERF_TIME - iperf3 test duration in seconds (default: 10)
#   NUMA_NODE  - NUMA node for CPU/mem pinning (default: 3)
#   WG_CPUS    - CPU set for wireguard-go (default: 48-63,112-127)
set -euo pipefail
source "$(dirname "$0")/bench-common.sh"

# --- Configuration ---
WG_CPUS="${WG_CPUS:-48-63,112-127}"  # CPUs for wireguard-go (default: all on NUMA node 3)
NUMA="numactl --membind=$NUMA_NODE"
TASKSET="taskset -c $WG_CPUS"

WG_PORT=51821  # Different from kernel WG default to avoid conflicts
WG_IF="wg-bench-go"

# WireGuard keys from bench-common.sh
KEY_A_PRIV="$WG_KEY_A_PRIV"
KEY_A_PUB="$WG_KEY_A_PUB"
KEY_B_PRIV="$WG_KEY_B_PRIV"
KEY_B_PUB="$WG_KEY_B_PUB"

# Initialized after first cleanup; guarded in cleanup() via ${KEY_DIR:-}.
KEY_DIR=""
WG_GO_LOCAL="${WG_GO:-$HOME/bin/wireguard-go}"
REMOTE_BIN_DIR="/tmp/wg-bench-go-bin"
WG_GO_REMOTE="$REMOTE_BIN_DIR/wireguard-go"

# --- Prerequisites ---
[[ -x "$WG_GO_LOCAL" ]] || { echo "Error: $WG_GO_LOCAL not found" >&2; exit 1; }
require_cmds numactl wg iperf3 ip ssh scp

# --- Cleanup ---
cleanup() {
    echo "[cleanup] Tearing down wireguard-go interfaces..."
    sudo ip link del "$WG_IF" 2>/dev/null || true
    sudo pkill -f "$WG_GO_LOCAL $WG_IF" 2>/dev/null || true
    ssh "$REMOTE" "sudo ip link del \"$WG_IF\"; sudo pkill -f 'wireguard-go $WG_IF'" 2>/dev/null || true
    kill_remote_iperf
    if [[ -n "${KEY_DIR:-}" && -d "$KEY_DIR" ]]; then
        rm -rf "$KEY_DIR"
        ssh "$REMOTE" "rm -rf \"$KEY_DIR\"" 2>/dev/null || true
    fi
    ssh "$REMOTE" "rm -rf \"$REMOTE_BIN_DIR\"" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Clean up leftovers from previous runs
cleanup

# --- Key files (avoids process substitution issues with sudo over SSH) ---
setup_wg_key_files "$KEY_A_PRIV" "$KEY_B_PRIV"

# --- Sync wireguard-go binary to remote ---
ssh "$REMOTE" "mkdir -p \"$REMOTE_BIN_DIR\""
scp -q "$WG_GO_LOCAL" "$REMOTE:$WG_GO_REMOTE"

# --- Setup local wireguard-go (NUMA + CPU pinned) ---
sudo $NUMA $TASKSET "$WG_GO_LOCAL" "$WG_IF"
sudo wg set "$WG_IF" listen-port "$WG_PORT" private-key "$KEY_DIR/local.key" \
    peer "$KEY_B_PUB" allowed-ips "${REMOTE_TUN}/32" endpoint "${REMOTE_IP}:${WG_PORT}"
sudo ip addr add "${LOCAL_TUN}/32" dev "$WG_IF"
sudo ip link set "$WG_IF" mtu "$TUN_MTU" up
sudo ip route add "${REMOTE_TUN}/32" dev "$WG_IF"

# --- Setup remote wireguard-go (NUMA + CPU pinned) ---
ssh "$REMOTE" "\
    sudo $NUMA $TASKSET \"$WG_GO_REMOTE\" \"$WG_IF\" && \
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
print_banner "wireguard-go Cross-Node Benchmark (TCP only)" \
    "TUN MTU: $TUN_MTU | NUMA: $NUMA_NODE | WG CPUs: $WG_CPUS"

run_iperf_tcp "$REMOTE_TUN"

print_done
