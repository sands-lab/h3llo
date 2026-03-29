#!/usr/bin/env bash
# Cross-node OpenVPN DCO throughput benchmark using iperf3.
# Sets up an OpenVPN tunnel with DCO (Data Channel Offload) between two
# physical nodes over SSH and runs a TCP throughput test via iperf3.
#
# Uses self-signed certificates with peer-fingerprint (no CA needed).
# DCO requires TLS mode + UDP + AEAD ciphers.
#
# Prerequisites:
#   - Passwordless sudo on both nodes
#   - Passwordless SSH access to REMOTE
#   - openvpn (>= 2.6), openvpn-dco-dkms, iperf3 on both nodes
#
# Usage: ./scripts/bench-openvpn-dco.sh
#
# Environment variables:
#   REMOTE     - remote hostname (default: mcnode26)
#   LOCAL_IP   - local underlay IP (default: 10.200.2.127)
#   REMOTE_IP  - remote underlay IP (default: 10.200.2.126)
#   TUN_MTU     - TUN interface MTU (default: 1291)
#   BENCH_DIR   - base benchmark directory (default: /tmp/bench)
#   IPERF_TIME  - iperf3 test duration in seconds (default: 10)
#   CIPHER      - data cipher (default: AES-256-GCM)
#   DISABLE_DCO - set to 1 to disable DCO (default: 0)
set -euo pipefail
source "$(dirname "$0")/bench-common.sh"

# --- Configuration ---
CIPHER="${CIPHER:-AES-256-GCM}"
DISABLE_DCO="${DISABLE_DCO:-0}"

OVPN_PORT=1194
OVPN_IF="ovpn-bench"

# Use /tmp (not NFS home) since sudo+openvpn needs root-readable paths.
# Each node has its own /tmp, so files must be synced via scp.
BENCH_DIR="$BENCH_DIR/openvpn-dco"

# --- Prerequisites ---
require_cmds openvpn iperf3 ip ssh openssl scp

# --- Cleanup ---
cleanup() {
    echo "[cleanup] Tearing down OpenVPN..."
    sudo killall openvpn 2>/dev/null || true
    ssh "$REMOTE" "sudo killall openvpn" 2>/dev/null || true
    ssh "$REMOTE" "pkill -f 'iperf3 -s'" 2>/dev/null || true
    sleep 1
    sudo ip link del "$OVPN_IF" 2>/dev/null || true
    ssh "$REMOTE" "sudo ip link del $OVPN_IF" 2>/dev/null || true
    rm -rf "$BENCH_DIR"
    ssh "$REMOTE" "rm -rf $BENCH_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Clean up leftovers
cleanup

# --- Load DCO module ---
sudo modprobe ovpn-dco-v2 2>/dev/null || true
ssh "$REMOTE" "sudo modprobe ovpn-dco-v2" 2>/dev/null || true

# --- Generate self-signed certificates ---
mkdir -p "$BENCH_DIR"

gen_self_signed_cert "$BENCH_DIR/server-key.pem" "$BENCH_DIR/server-cert.pem" "server"
gen_self_signed_cert "$BENCH_DIR/client-key.pem" "$BENCH_DIR/client-cert.pem" "client"

# Extract fingerprints
SERVER_FP=$(openssl x509 -fingerprint -sha256 -noout -in "$BENCH_DIR/server-cert.pem" | sed 's/.*=//')
CLIENT_FP=$(openssl x509 -fingerprint -sha256 -noout -in "$BENCH_DIR/client-cert.pem" | sed 's/.*=//')

DCO_OPT=""
if [[ "$DISABLE_DCO" == "1" ]]; then
    DCO_OPT="disable-dco"
fi

# --- Generate configs ---
cat > "$BENCH_DIR/server.conf" <<EOF
mode p2p
proto udp
port $OVPN_PORT
dev $OVPN_IF
dev-type tun
tls-server
dh none
cert $BENCH_DIR/server-cert.pem
key $BENCH_DIR/server-key.pem
ifconfig $REMOTE_TUN $LOCAL_TUN
tun-mtu $TUN_MTU
data-ciphers $CIPHER
peer-fingerprint $CLIENT_FP
sndbuf 0
rcvbuf 0
txqueuelen 1000
$DCO_OPT
verb 3
EOF

cat > "$BENCH_DIR/client.conf" <<EOF
mode p2p
proto udp
remote $REMOTE_IP $OVPN_PORT
dev $OVPN_IF
dev-type tun
tls-client
cert $BENCH_DIR/client-cert.pem
key $BENCH_DIR/client-key.pem
ifconfig $LOCAL_TUN $REMOTE_TUN
tun-mtu $TUN_MTU
data-ciphers $CIPHER
peer-fingerprint $SERVER_FP
sndbuf 0
rcvbuf 0
txqueuelen 1000
$DCO_OPT
verb 3
EOF

# --- Sync certs and config to remote ---
ssh "$REMOTE" "mkdir -p $BENCH_DIR"
scp -q "$BENCH_DIR"/* "$REMOTE:$BENCH_DIR/"

# --- Start remote (server) ---
ssh "$REMOTE" "sudo openvpn --config $BENCH_DIR/server.conf --daemon --log $BENCH_DIR/server.log"

# --- Start local (client) ---
sleep 1
sudo openvpn --config "$BENCH_DIR/client.conf" --daemon --log "$BENCH_DIR/client.log"

# --- Wait for tunnel ---
echo -n "  Waiting for tunnel..."
for i in $(seq 1 30); do
    if ping -c 1 -W 1 "$REMOTE_TUN" >/dev/null 2>&1; then
        echo " OK (${i}s)"
        break
    fi
    if [[ $i -eq 30 ]]; then
        echo " FAILED"
        echo "  --- Local log ---"
        cat "$BENCH_DIR/client.log" 2>/dev/null | tail -20
        echo "  --- Remote log ---"
        ssh "$REMOTE" "cat $BENCH_DIR/server.log 2>/dev/null | tail -20"
        exit 1
    fi
    sleep 1
done

# --- Verify DCO ---
echo -n "  DCO: "
if grep -q "DCO device .* opened" "$BENCH_DIR/client.log" 2>/dev/null; then
    echo "ACTIVE"
else
    echo "INACTIVE (falling back to userspace)"
fi

# --- Benchmark ---
echo ""
print_banner "OpenVPN DCO Cross-Node Benchmark (TCP only)" \
    "TUN MTU: $TUN_MTU | Cipher: $CIPHER | DCO: $( [[ $DISABLE_DCO == 1 ]] && echo OFF || echo ON )"

run_iperf_tcp "$REMOTE_TUN"

# --- Dump logs for diagnostics ---
echo ""
echo "  --- Local OpenVPN log ---"
sudo cat "$BENCH_DIR/client.log" 2>/dev/null | grep -i -E "dco|ovpn|offload|disabl|error|warn" | head -20
echo "  --- Remote OpenVPN log ---"
ssh "$REMOTE" "sudo cat $BENCH_DIR/server.log 2>/dev/null | grep -i -E 'dco|ovpn|offload|disabl|error|warn' | head -20"

print_done
