#!/usr/bin/env bash
# Cross-node Docker benchmark for h3llo.
# Runs BareUDP and HTTP/3 throughput tests between two physical nodes using
# Docker containers and iperf3 (TCP + UDP).
#
# Test matrix: BareUDP → H3(none) → H3(cubic) → H3(bbr2) → H3(bbr2+pacing)
#
# Prerequisites:
#   - Docker image (IMAGE) available on both nodes
#   - Passwordless SSH access to REMOTE
#   - openssl (for generating self-signed TLS certificates)
#
# Usage: ./scripts/bench-cross-node.sh
#
# Environment variables:
#   REMOTE              - remote hostname (default: mcnode26)
#   LOCAL_IP            - local underlay IP (default: 10.200.2.127)
#   REMOTE_IP           - remote underlay IP (default: 10.200.2.126)
#   LOCAL_IF            - local outbound interface (default: bf3p1)
#   REMOTE_IF           - remote outbound interface (default: bf3p1)
#   TUN_MTU             - TUN interface MTU (default: 8980)
#   IMAGE               - Docker image name (default: nekonuts/h3llo)
#   CERT_DIR            - certificate directory on both nodes (default: auto-created temp dir)
#   IPERF_TIME          - iperf3 test duration in seconds (default: 10)
#   PACKET_QUEUE_DEPTH  - packet queue depth (default: 256)
set -euo pipefail

# --- Configuration ---
REMOTE="${REMOTE:-mcnode26}"
LOCAL_IP="${LOCAL_IP:-10.200.2.127}"
REMOTE_IP="${REMOTE_IP:-10.200.2.126}"
LOCAL_IF="${LOCAL_IF:-bf3p1}"
REMOTE_IF="${REMOTE_IF:-bf3p1}"
TUN_MTU="${TUN_MTU:-1393}"
IMAGE="${IMAGE:-nekonuts/h3llo}"
CERT_DIR="${CERT_DIR:-$(mktemp -d /tmp/h3llo-bench-certs.XXXXXX)}"
IPERF_TIME="${IPERF_TIME:-10}"
PACKET_QUEUE_DEPTH="${PACKET_QUEUE_DEPTH:-256}"

UDP_PAYLOAD=$((TUN_MTU - 28))  # Subtract IP+UDP overhead to avoid fragmentation
H3_PORT=4433
BAREUDP_PORT=5353
H3_PATH="/bench"
H3_TOKEN="bench-token-12ch"  # Test-only token, NOT for production

BENCH_DIR="/tmp/h3llo-bench"
LOCAL_CTR="h3llo-bench-local"
REMOTE_CTR="h3llo-bench-remote"

# Docker flags: host networking + TUN device access.
# Intentionally unquoted at call sites to allow word splitting into separate args.
DOCKER_FLAGS="--net=host --cap-add NET_ADMIN --device /dev/net/tun"

# --- Counter collection helpers ---
# Collect TUN drops, UDP socket drops, nstat UDP errors in a single docker exec.
# Usage: collect_counters <container> <tun_if> <udp_port> [remote]
# Output: "tun_rx_drop tun_tx_drop udp_sock_drops nstat_rcvbuf nstat_sndbuf"
collect_counters() {
    local ctr="$1" tun="$2" port="$3" remote="${4:-}"
    local hex_port
    hex_port=$(printf '%04X' "$port")
    local script
    script=$(cat <<'SCRIPT'
tun_stats=$(ip -s link show TUN_IF 2>/dev/null || echo "")
tun_rx_drop=0; tun_tx_drop=0
if [ -n "$tun_stats" ]; then
    tun_rx_drop=$(echo "$tun_stats" | awk '/RX:/{getline; print $4; exit}')
    tun_tx_drop=$(echo "$tun_stats" | awk '/TX:/{getline; print $4; exit}')
fi
udp_drops=$(awk -v hp="HEX_PORT" 'NR>1 && toupper(substr($2, index($2,":")+1)) == hp {t+=$NF} END{print t+0}' /proc/1/net/udp 2>/dev/null || echo 0)
nstat_out=$(nstat -az 2>/dev/null || echo "")
rcvbuf=$(echo "$nstat_out" | awk '/UdpRcvbufErrors/{print $2}')
sndbuf=$(echo "$nstat_out" | awk '/UdpSndbufErrors/{print $2}')
echo "${tun_rx_drop:-0} ${tun_tx_drop:-0} ${udp_drops:-0} ${rcvbuf:-0} ${sndbuf:-0}"
SCRIPT
    )
    script="${script//TUN_IF/$tun}"
    script="${script//HEX_PORT/$hex_port}"
    if [[ -n "$remote" ]]; then
        ssh "$REMOTE" "docker exec $ctr sh -c '$script'" 2>/dev/null || echo "0 0 0 0 0"
    else
        docker exec "$ctr" sh -c "$script" 2>/dev/null || echo "0 0 0 0 0"
    fi
}

# Report delta between two counter snapshots.
# Usage: report_counters <label> "<before>" "<after>"
report_counters() {
    local label="$1"
    local -a before after
    read -ra before <<< "$2"
    read -ra after <<< "$3"
    local d_rx=$(( after[0] - before[0] ))
    local d_tx=$(( after[1] - before[1] ))
    local d_udp=$(( after[2] - before[2] ))
    local d_rcvbuf=$(( after[3] - before[3] ))
    local d_sndbuf=$(( after[4] - before[4] ))
    echo "  [$label] TUN rx_drop=+$d_rx tx_drop=+$d_tx | UDP sock_drops=+$d_udp | nstat RcvbufErr=+$d_rcvbuf SndbufErr=+$d_sndbuf"
}

# --- Prerequisites ---
for cmd in docker ssh scp iperf3 openssl; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "Error: $cmd not found" >&2; exit 1; }
done

# --- Pull latest Docker image ---
echo "Pulling latest image: $IMAGE ..."
docker pull "$IMAGE"
ssh "$REMOTE" "docker pull $IMAGE"

# --- Cleanup ---
cleanup() {
    echo "[cleanup] Stopping containers and cleaning up..."
    docker rm -f "$LOCAL_CTR" 2>/dev/null || true
    ssh "$REMOTE" "docker rm -f $REMOTE_CTR" 2>/dev/null || true
    sleep 1
    # Remove leftover TUN devices (--net=host leaves them in the host namespace).
    # Requires NET_ADMIN, so use a privileged Docker container.
    docker run --rm --net=host --cap-add NET_ADMIN --entrypoint ip "$IMAGE" link del tun-bench 2>/dev/null || true
    ssh "$REMOTE" "docker run --rm --net=host --cap-add NET_ADMIN --entrypoint ip $IMAGE link del tun-bench" 2>/dev/null || true
    # Remove generated cert dirs (local + remote)
    if [[ -d "$CERT_DIR" ]]; then rm -rf "$CERT_DIR"; fi
    ssh "$REMOTE" "rm -rf $CERT_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

stop_containers() {
    docker rm -f "$LOCAL_CTR" 2>/dev/null || true
    ssh "$REMOTE" "docker rm -f $REMOTE_CTR" 2>/dev/null || true
    sleep 2
}

# --- Tunnel lifecycle ---
TUN_IF="tun-bench"

start_tunnel() {
    local local_cfg="$1"
    local remote_cfg="$2"

    # Clean up leftover TUN devices from previous runs (requires NET_ADMIN)
    docker run --rm --net=host --cap-add NET_ADMIN "$IMAGE" sh -c "ip link del $TUN_IF" 2>/dev/null || true
    ssh "$REMOTE" "docker run --rm --net=host --cap-add NET_ADMIN $IMAGE sh -c 'ip link del $TUN_IF'" 2>/dev/null || true

    ssh "$REMOTE" "mkdir -p $BENCH_DIR"
    scp -q "$BENCH_DIR/$remote_cfg" "$REMOTE:$BENCH_DIR/$remote_cfg"

    # Start remote container
    ssh "$REMOTE" "docker rm -f $REMOTE_CTR 2>/dev/null; \
        docker run -d --name $REMOTE_CTR \
        $DOCKER_FLAGS \
        -e RUST_LOG=h3llo=debug \
        -v $BENCH_DIR:/etc/h3llo \
        -v $CERT_DIR:/certs \
        $IMAGE -c /etc/h3llo/$remote_cfg"

    # Start local container
    docker rm -f "$LOCAL_CTR" 2>/dev/null || true
    docker run -d --name "$LOCAL_CTR" \
        $DOCKER_FLAGS \
        -e RUST_LOG=h3llo=debug \
        -v "$BENCH_DIR":/etc/h3llo \
        -v "$CERT_DIR":/certs \
        "$IMAGE" -c "/etc/h3llo/$local_cfg"

    sleep 5  # Wait for TUN creation and tunnel setup

    # Verify connectivity
    echo -n "  Connectivity: "
    if docker exec "$LOCAL_CTR" ping -c 2 -W 2 10.0.0.2 >/dev/null 2>&1; then
        echo "OK"
    else
        echo "FAILED"
        echo "  --- Local container logs (tail) ---"
        docker logs "$LOCAL_CTR" 2>&1 | tail -40
        echo "  --- Remote container logs (tail) ---"
        ssh "$REMOTE" "docker logs $REMOTE_CTR 2>&1 | tail -40"
        return 1
    fi
}

# --- iperf3 helpers ---
run_iperf_tcp() {
    echo "--- TCP ---"
    ssh "$REMOTE" "docker exec -d $REMOTE_CTR iperf3 -s -1"
    sleep 1
    docker exec "$LOCAL_CTR" iperf3 -c 10.0.0.2 -t "$IPERF_TIME"
}

run_iperf_udp() {
    echo "--- UDP 5Gbps (payload=${UDP_PAYLOAD}B, no frag) ---"
    ssh "$REMOTE" "docker exec -d $REMOTE_CTR iperf3 -s -1"
    sleep 1
    docker exec "$LOCAL_CTR" iperf3 -c 10.0.0.2 -u -b 5G -l "$UDP_PAYLOAD" -t "$IPERF_TIME"
}

# --- Test runner ---
run_test() {
    local label="$1"
    local local_cfg="$2"
    local remote_cfg="$3"
    # Determine the underlay UDP port for socket drop collection.
    local udp_port="$BAREUDP_PORT"
    if [[ "$local_cfg" == *h3* ]]; then
        udp_port="$H3_PORT"
    fi

    echo ""
    echo "================================================================"
    echo "  $label"
    echo "  TUN MTU: $TUN_MTU | UDP payload: $UDP_PAYLOAD"
    echo "================================================================"

    if ! start_tunnel "$local_cfg" "$remote_cfg"; then
        stop_containers
        return
    fi

    # --- Capture baseline counters ---
    local local_before remote_before
    local_before=$(collect_counters "$LOCAL_CTR" "$TUN_IF" "$udp_port")
    remote_before=$(collect_counters "$REMOTE_CTR" "$TUN_IF" "$udp_port" remote)

    run_iperf_tcp
    echo ""
    run_iperf_udp

    # --- Capture post-test counters and report deltas ---
    local local_after remote_after
    local_after=$(collect_counters "$LOCAL_CTR" "$TUN_IF" "$udp_port")
    remote_after=$(collect_counters "$REMOTE_CTR" "$TUN_IF" "$udp_port" remote)
    echo ""
    report_counters "Local ($LOCAL_CTR)" "$local_before" "$local_after"
    report_counters "Remote ($REMOTE_CTR)" "$remote_before" "$remote_after"

    # --- Print h3llo debug logs (includes congestion metrics) ---
    echo ""
    echo "  --- h3llo logs: Local ($LOCAL_CTR) ---"
    docker logs "$LOCAL_CTR" 2>&1
    echo "  --- h3llo logs: Remote ($REMOTE_CTR) ---"
    ssh "$REMOTE" "docker logs $REMOTE_CTR 2>&1"

    stop_containers
}

# --- Config generators ---
gen_bareudp_configs() {
    cat > "$BENCH_DIR/local-bareudp.yaml" <<EOF
local:
  table: true
  dns:
    server: "udp://127.0.0.1:53"
  tun:
    ifname: tun-bench
    addrs:
      - 10.0.0.1/32
    mtu: $TUN_MTU
  bare:
    listen: "udp://0.0.0.0:5353"
tuning:
  packet_queue_depth: $PACKET_QUEUE_DEPTH
  metrics_log_interval: 1
peers:
  - id: remote
    bare:
      endpoint: "udp://${REMOTE_IP}:5353"
      bindif: $LOCAL_IF
    tun:
      allowed_ips:
        - 10.0.0.2/32
EOF

    cat > "$BENCH_DIR/remote-bareudp.yaml" <<EOF
local:
  table: true
  dns:
    server: "udp://127.0.0.1:53"
  tun:
    ifname: tun-bench
    addrs:
      - 10.0.0.2/32
    mtu: $TUN_MTU
  bare:
    listen: "udp://0.0.0.0:5353"
tuning:
  packet_queue_depth: $PACKET_QUEUE_DEPTH
  metrics_log_interval: 1
peers:
  - id: local
    bare:
      endpoint: "udp://${LOCAL_IP}:5353"
      bindif: $REMOTE_IF
    tun:
      allowed_ips:
        - 10.0.0.1/32
EOF
}

gen_h3_configs() {
    local cc="$1"
    local pacing="${2:-false}"
    local suffix="$cc"
    if [[ "$pacing" == "true" ]]; then
        suffix="${cc}-pacing"
    fi

    local pacing_line=""
    if [[ "$pacing" == "true" ]]; then
        pacing_line=$'\n  h3_enable_pacing: true'
    fi

    cat > "$BENCH_DIR/local-h3-${suffix}.yaml" <<EOF
local:
  table: true
  dns:
    server: "udp://127.0.0.1:53"
  tun:
    ifname: tun-bench
    addrs:
      - 10.0.0.1/32
    mtu: $TUN_MTU
  h3:
    listen: "https://0.0.0.0:${H3_PORT}${H3_PATH}"
    cert: "/certs/local-cert.pem"
    key: "/certs/local-key.pem"
tuning:
  h3_cc_algorithm: $cc
  h3_insecure_skip_verify: true
  packet_queue_depth: ${PACKET_QUEUE_DEPTH}
  metrics_log_interval: 1${pacing_line}
peers:
  - id: remote
    h3:
      token: "$H3_TOKEN"
      endpoint: "https://${REMOTE_IP}:${H3_PORT}${H3_PATH}"
      bindif: $LOCAL_IF
    tun:
      allowed_ips:
        - 10.0.0.2/32
EOF

    cat > "$BENCH_DIR/remote-h3-${suffix}.yaml" <<EOF
local:
  table: true
  dns:
    server: "udp://127.0.0.1:53"
  tun:
    ifname: tun-bench
    addrs:
      - 10.0.0.2/32
    mtu: $TUN_MTU
  h3:
    listen: "https://0.0.0.0:${H3_PORT}${H3_PATH}"
    cert: "/certs/remote-cert.pem"
    key: "/certs/remote-key.pem"
tuning:
  h3_cc_algorithm: $cc
  h3_insecure_skip_verify: true
  packet_queue_depth: ${PACKET_QUEUE_DEPTH}
  metrics_log_interval: 1${pacing_line}
peers:
  - id: local
    h3:
      token: "$H3_TOKEN"
      endpoint: "https://${LOCAL_IP}:${H3_PORT}${H3_PATH}"
      bindif: $REMOTE_IF
    tun:
      allowed_ips:
        - 10.0.0.1/32
EOF
}

# --- Smoke test ---
# When BENCH_DRY_RUN=1, validate helper functions and exit.
if [[ "${BENCH_DRY_RUN:-0}" == "1" ]]; then
    echo "[dry-run] Testing report_counters..."
    report_counters "TEST" "0 0 0 0 0" "10 5 3 2 1"
    echo "[dry-run] Expected: [TEST] TUN rx_drop=+10 tx_drop=+5 | UDP sock_drops=+3 | nstat RcvbufErr=+2 SndbufErr=+1"
    echo "[dry-run] OK"
    exit 0
fi

# ============================================================
# Main
# ============================================================
mkdir -p "$BENCH_DIR"

# --- Generate self-signed TLS certificates ---
mkdir -p "$CERT_DIR"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$CERT_DIR/local-key.pem" -out "$CERT_DIR/local-cert.pem" \
    -days 1 -nodes -subj "/CN=$LOCAL_IP" \
    -addext "subjectAltName=IP:$LOCAL_IP" 2>/dev/null
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$CERT_DIR/remote-key.pem" -out "$CERT_DIR/remote-cert.pem" \
    -days 1 -nodes -subj "/CN=$REMOTE_IP" \
    -addext "subjectAltName=IP:$REMOTE_IP" 2>/dev/null
echo "  Certificates generated in $CERT_DIR"

# Copy certificates to remote node
ssh "$REMOTE" "mkdir -p $CERT_DIR"
scp -q "$CERT_DIR"/*.pem "$REMOTE:$CERT_DIR/"
echo "  Certificates synced to $REMOTE:$CERT_DIR"

echo "================================================================"
echo "  h3llo Cross-Node Benchmark"
echo "  Local:  $LOCAL_IP ($LOCAL_IF) - $(hostname)"
echo "  Remote: $REMOTE_IP ($REMOTE_IF) - $REMOTE"
echo "  TUN MTU: $TUN_MTU | UDP payload: $UDP_PAYLOAD"
echo "  Packet queue depth: $PACKET_QUEUE_DEPTH"
echo "  Date: $(date -Iseconds)"
echo "================================================================"

# --- BareUDP ---
gen_bareudp_configs
run_test "BareUDP" "local-bareudp.yaml" "remote-bareudp.yaml"

# --- H3 (none) ---
gen_h3_configs "none"
run_test "H3 (none)" "local-h3-none.yaml" "remote-h3-none.yaml"

# --- H3 (cubic) ---
gen_h3_configs "cubic"
run_test "H3 (cubic)" "local-h3-cubic.yaml" "remote-h3-cubic.yaml"

# --- H3 (bbr2) ---
gen_h3_configs "bbr2"
run_test "H3 (bbr2)" "local-h3-bbr2.yaml" "remote-h3-bbr2.yaml"

# --- H3 (bbr2 + pacing) ---
gen_h3_configs "bbr2" "true"
run_test "H3 (bbr2 + pacing)" "local-h3-bbr2-pacing.yaml" "remote-h3-bbr2-pacing.yaml"

echo ""
echo "================================================================"
echo "  All benchmarks completed."
echo "================================================================"
