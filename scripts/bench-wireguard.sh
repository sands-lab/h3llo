#!/usr/bin/env bash
# Cross-node WireGuard throughput baseline benchmark using iperf3.
# Sets up a WireGuard tunnel between two physical nodes over SSH and
# runs TCP + UDP throughput tests via iperf3.
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
#   TUN_MTU    - WireGuard interface MTU (default: 1393)
#   IPERF_TIME - iperf3 test duration in seconds (default: 10)
set -euo pipefail

# --- Configuration ---
REMOTE="${REMOTE:-mcnode26}"
LOCAL_IP="${LOCAL_IP:-10.200.2.127}"
REMOTE_IP="${REMOTE_IP:-10.200.2.126}"
TUN_MTU="${TUN_MTU:-1393}"
IPERF_TIME="${IPERF_TIME:-10}"

UDP_PAYLOAD=$((TUN_MTU - 28))  # Subtract IP+UDP overhead to avoid fragmentation
WG_PORT=51820
WG_IF="wg-bench"

# Overlay addresses
LOCAL_TUN="10.0.0.1"
REMOTE_TUN="10.0.0.2"

# Fixed Curve25519 keys (test-only, NOT for production)
# Generated via: wg genkey | tee priv | wg pubkey > pub
KEY_A_PRIV="yAnw4/bFKWQyuiDKWrXruXyKk/Ah1CJWQfV0FTXcXWU="
KEY_A_PUB="xopHDYsmeG7tk7UdovGv7RUBaiD1sADUrIlujSYHVFY="
KEY_B_PRIV="0AMR6oqMwHg1NDZMRMtRXi/xd3Ot6Camb1euWJY1lWI="
KEY_B_PUB="mqgf3siT/qS86WCoYmZFaXHUx5JRGSFVfjU4avuNanM="

# Initialized after first cleanup; guarded in cleanup() via ${KEY_DIR:-}.
KEY_DIR=""

# --- Prerequisites ---
for cmd in wg iperf3 ip ssh; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "Error: $cmd not found" >&2; exit 1; }
done

# --- Cleanup ---
cleanup() {
    echo "[cleanup] Tearing down WireGuard interfaces..."
    sudo ip link del "$WG_IF" 2>/dev/null || true
    ssh "$REMOTE" "sudo ip link del $WG_IF" 2>/dev/null || true
    ssh "$REMOTE" "pkill -f 'iperf3 -s'" 2>/dev/null || true
    if [[ -n "${KEY_DIR:-}" && -d "$KEY_DIR" ]]; then
        rm -rf "$KEY_DIR"
        ssh "$REMOTE" "rm -rf $KEY_DIR" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# Clean up leftovers from previous runs
cleanup

# --- Key files (avoids process substitution issues with sudo over SSH) ---
KEY_DIR=$(mktemp -d /tmp/wg-bench-keys.XXXXXX)
echo "$KEY_A_PRIV" > "$KEY_DIR/local.key"
chmod 600 "$KEY_DIR/local.key"
ssh "$REMOTE" "mkdir -p $KEY_DIR && printf '%s\n' '$KEY_B_PRIV' > $KEY_DIR/remote.key && chmod 600 $KEY_DIR/remote.key"

# --- Setup local WireGuard ---
sudo ip link add "$WG_IF" type wireguard
sudo wg set "$WG_IF" listen-port "$WG_PORT" private-key "$KEY_DIR/local.key" \
    peer "$KEY_B_PUB" allowed-ips "${REMOTE_TUN}/32" endpoint "${REMOTE_IP}:${WG_PORT}"
sudo ip addr add "${LOCAL_TUN}/32" dev "$WG_IF"
sudo ip link set "$WG_IF" mtu "$TUN_MTU" up
sudo ip route add "${REMOTE_TUN}/32" dev "$WG_IF"

# --- Setup remote WireGuard ---
ssh "$REMOTE" "\
    sudo ip link add $WG_IF type wireguard && \
    sudo wg set $WG_IF listen-port $WG_PORT private-key $KEY_DIR/remote.key \
        peer $KEY_A_PUB allowed-ips ${LOCAL_TUN}/32 endpoint ${LOCAL_IP}:${WG_PORT} && \
    sudo ip addr add ${REMOTE_TUN}/32 dev $WG_IF && \
    sudo ip link set $WG_IF mtu $TUN_MTU up && \
    sudo ip route add ${LOCAL_TUN}/32 dev $WG_IF"

# --- Verify connectivity ---
echo -n "  Connectivity: "
if ping -c 2 -W 2 "$REMOTE_TUN" >/dev/null 2>&1; then
    echo "OK"
else
    echo "FAILED"
    sudo wg show "$WG_IF"
    ssh "$REMOTE" "sudo wg show $WG_IF"
    exit 1
fi

# --- Benchmark ---
echo ""
echo "================================================================"
echo "  WireGuard Cross-Node Benchmark"
echo "  Local:  $LOCAL_IP ($(hostname))"
echo "  Remote: $REMOTE_IP ($REMOTE)"
echo "  TUN MTU: $TUN_MTU | UDP payload: $UDP_PAYLOAD"
echo "  Date: $(date -Iseconds)"
echo "================================================================"

echo "--- TCP ---"
ssh "$REMOTE" "iperf3 -s -1 -B $REMOTE_TUN -D"
sleep 1
iperf3 -c "$REMOTE_TUN" -t "$IPERF_TIME"

echo ""
echo "--- UDP 5Gbps (payload=${UDP_PAYLOAD}B, no frag) ---"
ssh "$REMOTE" "iperf3 -s -1 -B $REMOTE_TUN -D"
sleep 1
iperf3 -c "$REMOTE_TUN" -u -b 5G -l "$UDP_PAYLOAD" -t "$IPERF_TIME"

echo ""
echo "================================================================"
echo "  Benchmark completed."
echo "================================================================"
