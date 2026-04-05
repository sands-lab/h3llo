#!/usr/bin/env bash
# Cross-node TrustTunnel throughput benchmark using iperf3.
# Downloads prebuilt binaries from GitHub Releases (no install script).
# Tests HTTP/2 and HTTP/3 (QUIC) transport at MTU=1291, NUMA-pinned.
#
# TrustTunnel is a proxy-based VPN (not peer-to-peer):
#   Remote: TrustTunnel endpoint (server) + iperf3 server
#   Local:  TrustTunnel client (TUN)    + iperf3 client
#
# Traffic: iperf3 → TUN → TT client →[HTTP/2|QUIC]→ TT endpoint → iperf3 server
#
# The client's [listener.tun] bound_if option forces the endpoint connection
# through the specified interface (SO_BINDTODEVICE), keeping all traffic on
# the NUMA3 NIC without needing a network namespace.
#
# TLS SNI must be a hostname, not an IP (RFC 6066 / rustls requirement).
# The iperf3 server binds to 198.18.0.1 (RFC 2544 benchmarking range) on the
# remote loopback. Only 198.18.0.0/24 is routed through the tunnel.
#
# Prerequisites:
#   - Passwordless sudo + SSH to REMOTE
#   - numactl, iperf3, openssl, curl on both nodes
#
# Usage: ./scripts/bench-trusttunnel.sh
#
# Environment variables:
#   REMOTE              - remote hostname (default: mcnode26)
#   LOCAL_IP            - local underlay IP (default: 10.200.2.127)
#   REMOTE_IP           - remote underlay IP (default: 10.200.2.126)
#   LOCAL_IF            - local outbound interface (default: bf3p1)
#   TUN_MTU             - TUN interface MTU (default: 1291)
#   BENCH_DIR           - base benchmark directory (default: /tmp/bench)
#   IPERF_TIME          - iperf3 test duration in seconds (default: 10)
#   NUMA_NODE           - NUMA node for CPU/mem pinning (default: 3)
#   TT_CPUS             - CPU set for TrustTunnel processes (default: 48-51)
#   IPERF_CPU           - CPU for iperf3 (default: 52)
#   TT_ENDPOINT_VER     - endpoint release tag (default: v1.0.17)
#   TT_CLIENT_VER       - client release tag (default: v1.0.31)
set -euo pipefail
source "$(dirname "$0")/bench-common.sh"

# --- Configuration ---
TT_CPUS="${TT_CPUS:-48-51}"
NUMA="numactl --membind=$NUMA_NODE"
TT_PIN="taskset -c $TT_CPUS"

TT_PORT=8443
TEST_IP="198.18.0.1"  # RFC 2544 benchmarking range, on remote loopback
TEST_NET="198.18.0.0/24"
TT_HOSTNAME="tt-bench.local"  # TLS SNI must be a hostname, not an IP (RFC 6066)

# Release versions (update as needed)
TT_ENDPOINT_VER="${TT_ENDPOINT_VER:-v1.0.17}"
TT_CLIENT_VER="${TT_CLIENT_VER:-v1.0.31}"

BENCH_DIR="$BENCH_DIR/trusttunnel"
BIN_DIR="$BENCH_DIR/bin"
CONF_DIR="$BENCH_DIR/config"
CERT_DIR="$BENCH_DIR/certs"

# Credentials (benchmark only, NOT for production)
TT_USER="benchuser"
TT_PASS="benchpass-12345678"

# --- Prerequisites ---
require_cmds numactl iperf3 ip ssh scp openssl curl tar

# --- Download & extract binaries ---
download_binaries() {
    mkdir -p "$BIN_DIR"

    # Endpoint
    if [[ ! -x "$BIN_DIR/trusttunnel_endpoint" ]]; then
        local ep_tarball="trusttunnel-${TT_ENDPOINT_VER}-linux-x86_64.tar.gz"
        local ep_url="https://github.com/TrustTunnel/TrustTunnel/releases/download/${TT_ENDPOINT_VER}/${ep_tarball}"
        echo "  Downloading endpoint ${TT_ENDPOINT_VER}..."
        curl -fsSL "$ep_url" -o "$BENCH_DIR/ep.tar.gz"
        tar -xzf "$BENCH_DIR/ep.tar.gz" -C "$BIN_DIR"
        # Binary may be nested in a subdirectory; locate it.
        if [[ ! -x "$BIN_DIR/trusttunnel_endpoint" ]]; then
            find "$BIN_DIR" -name "trusttunnel_endpoint" -type f -exec mv {} "$BIN_DIR/" \;
        fi
        chmod +x "$BIN_DIR/trusttunnel_endpoint"
        rm -f "$BENCH_DIR/ep.tar.gz"
    fi

    # Client
    if [[ ! -x "$BIN_DIR/trusttunnel_client" ]]; then
        local cl_tarball="trusttunnel_client-${TT_CLIENT_VER}-linux-x86_64.tar.gz"
        local cl_url="https://github.com/TrustTunnel/TrustTunnelClient/releases/download/${TT_CLIENT_VER}/${cl_tarball}"
        echo "  Downloading client ${TT_CLIENT_VER}..."
        curl -fsSL "$cl_url" -o "$BENCH_DIR/cl.tar.gz"
        tar -xzf "$BENCH_DIR/cl.tar.gz" -C "$BIN_DIR"
        if [[ ! -x "$BIN_DIR/trusttunnel_client" ]]; then
            find "$BIN_DIR" -name "trusttunnel_client" -type f -exec mv {} "$BIN_DIR/" \;
        fi
        chmod +x "$BIN_DIR/trusttunnel_client"
        rm -f "$BENCH_DIR/cl.tar.gz"
    fi

    [[ -x "$BIN_DIR/trusttunnel_endpoint" ]] || { echo "Error: trusttunnel_endpoint not found after extraction" >&2; exit 1; }
    [[ -x "$BIN_DIR/trusttunnel_client" ]]   || { echo "Error: trusttunnel_client not found after extraction" >&2; exit 1; }

    # Sync endpoint binary to remote
    ssh "$REMOTE" "mkdir -p \"$BIN_DIR\""
    scp -q "$BIN_DIR/trusttunnel_endpoint" "$REMOTE:$BIN_DIR/"

    echo "  Binaries: endpoint=$TT_ENDPOINT_VER  client=$TT_CLIENT_VER"
}

# --- Stop both sides (between tests) ---
stop_tunnel() {
    sudo pkill -f trusttunnel_client 2>/dev/null || true
    ssh "$REMOTE" "sudo pkill -f trusttunnel_endpoint" 2>/dev/null || true
    kill_remote_iperf
    sleep 2
    # TrustTunnel creates "tun0" by default; no config option to customize the name.
    # Guard: only delete if tun0 has our test network route, to avoid tearing down
    # an unrelated interface.
    if ip route show "$TEST_NET" dev tun0 >/dev/null 2>&1; then
        sudo ip link del tun0 2>/dev/null || true
    fi
}

# --- Cleanup ---
cleanup() {
    echo "[cleanup] Stopping TrustTunnel..."
    stop_tunnel
    ssh "$REMOTE" "sudo ip addr del \"$TEST_IP/32\" dev lo" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
cleanup

# --- Setup ---
mkdir -p "$CONF_DIR" "$CERT_DIR"
download_binaries

# Self-signed TLS certificate (must use DNS hostname, not IP, for SNI)
gen_self_signed_cert "$CERT_DIR/key.pem" "$CERT_DIR/cert.pem" "$TT_HOSTNAME" "DNS:$TT_HOSTNAME,IP:$REMOTE_IP"
echo "  TLS certificate generated"

# Benchmark IP on remote loopback
ssh "$REMOTE" "sudo ip addr add \"$TEST_IP/32\" dev lo 2>/dev/null || true"

# --- Endpoint config (shared for both HTTP/2 and HTTP/3) ---
cat > "$CONF_DIR/vpn.toml" <<EOF
listen_address = "0.0.0.0:$TT_PORT"
ipv6_available = false
allow_private_network_connections = true
tls_handshake_timeout_secs = 10
client_listener_timeout_secs = 600
connection_establishment_timeout_secs = 30
tcp_connections_timeout_secs = 604800
udp_connections_timeout_secs = 300
credentials_file = "$CONF_DIR/credentials.toml"
rules_file = "$CONF_DIR/rules.toml"

[listen_protocols.http2]
initial_connection_window_size = 8388608
initial_stream_window_size = 2097152
max_concurrent_streams = 1000
max_frame_size = 16384

[listen_protocols.quic]
recv_udp_payload_size = 1350
send_udp_payload_size = 1350
initial_max_data = 104857600
initial_max_streams_bidi = 4096
enable_early_data = true

[forward_protocol]
direct = {}
EOF

cat > "$CONF_DIR/hosts.toml" <<EOF
[[main_hosts]]
hostname = "$TT_HOSTNAME"
cert_chain_path = "$CERT_DIR/cert.pem"
private_key_path = "$CERT_DIR/key.pem"
EOF

cat > "$CONF_DIR/credentials.toml" <<EOF
[[client]]
username = "$TT_USER"
password = "$TT_PASS"
EOF
chmod 600 "$CONF_DIR/credentials.toml"

: > "$CONF_DIR/rules.toml"  # empty = allow all

# Sync everything to remote
ssh "$REMOTE" "mkdir -p \"$CONF_DIR\" \"$CERT_DIR\""
scp -rq "$CONF_DIR/"* "$REMOTE:$CONF_DIR/"
scp -rq "$CERT_DIR/"* "$REMOTE:$CERT_DIR/"

# --- Client config generator ---
gen_client_config() {
    local proto="$1"  # "http2" or "http3"

    cat > "$BENCH_DIR/client-${proto}.toml" <<EOF
loglevel = "info"
vpn_mode = "general"
killswitch_enabled = false
post_quantum_group_enabled = false
exclusions = []
dns_upstreams = []

[endpoint]
hostname = "$TT_HOSTNAME"
addresses = ["$REMOTE_IP:$TT_PORT"]
has_ipv6 = false
username = "$TT_USER"
password = "$TT_PASS"
upstream_protocol = "$proto"

[listener.tun]
bound_if = "$LOCAL_IF"
included_routes = ["$TEST_NET"]
excluded_routes = []
mtu_size = $TUN_MTU
change_system_dns = false
EOF
}

# --- Run a single benchmark ---
run_test() {
    local label="$1"
    local proto="$2"

    print_test_header "$label" "TUN MTU: $TUN_MTU | Protocol: $proto | NUMA: $NUMA_NODE"

    gen_client_config "$proto"

    # Start endpoint on remote (NUMA + CPU pinned)
    ssh "$REMOTE" "sudo $NUMA $TT_PIN \"$BIN_DIR/trusttunnel_endpoint\" \
        \"$CONF_DIR/vpn.toml\" \"$CONF_DIR/hosts.toml\" \
        </dev/null >/dev/null 2>&1 &"
    sleep 3

    # Start client locally (NUMA + CPU pinned)
    # -s: skip TLS certificate verification (self-signed cert)
    sudo $NUMA $TT_PIN "$BIN_DIR/trusttunnel_client" \
        -s -c "$BENCH_DIR/client-${proto}.toml" \
        >/dev/null 2>&1 &

    # TrustTunnel client needs ~10-15s for TLS handshake + TUN setup
    if ! wait_for_connectivity "$TEST_IP" 20; then
        echo "  --- Local client process ---"
        ps aux | grep trusttunnel_client | grep -v grep || echo "  (not running)"
        echo "  --- Remote endpoint process ---"
        ssh "$REMOTE" "ps aux | grep trusttunnel_endpoint | grep -v grep" 2>/dev/null || echo "  (not running)"
        return
    fi

    run_iperf_tcp "$TEST_IP"

    stop_tunnel
}

# ============================================================
# Main
# ============================================================
print_banner "TrustTunnel Cross-Node Benchmark" \
    "TUN MTU: $TUN_MTU | NUMA: $NUMA_NODE | bound_if=$LOCAL_IF" \
    "TT CPUs: $TT_CPUS | iperf3 CPU: $IPERF_CPU" \
    "Endpoint: $TT_ENDPOINT_VER | Client: $TT_CLIENT_VER"

run_test "TrustTunnel (HTTP/2)" "http2"
run_test "TrustTunnel (HTTP/3)" "http3"

print_done "All benchmarks completed."
