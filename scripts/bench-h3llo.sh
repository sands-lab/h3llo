#!/usr/bin/env bash
# Cross-node Docker benchmark for h3llo.
# Runs BareUDP and HTTP/3 throughput tests between two physical nodes using
# Docker containers and iperf3 (TCP + UDP).
#
# Test matrix: BareUDP → H3(none) → H3(cubic) → H3(bbr2) → H3(bbr2+pacing)
#
# Raw network counters (softnet, tc qdisc, ethtool -S) are dumped to a
# timestamped file in BENCH_DIR for post-hoc packet-loss diagnosis.
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
TUN_TX_QUEUE_LEN="${TUN_TX_QUEUE_LEN:-1000}"

UDP_PAYLOAD=$((TUN_MTU - 28))  # Subtract IP+UDP overhead to avoid fragmentation
H3_PORT=4433
BAREUDP_PORT=5353
H3_PATH="/bench"
H3_TOKEN="bench-token-12ch"  # Test-only token, NOT for production

BENCH_DIR="/tmp/h3llo-bench"
LOCAL_CTR="h3llo-bench-local"
REMOTE_CTR="h3llo-bench-remote"
TUN_IF="tun-bench"

# Docker flags: host networking + TUN device access.
# Intentionally unquoted at call sites to allow word splitting into separate args.
DOCKER_FLAGS="--net=host --cap-add NET_ADMIN --device /dev/net/tun"

# --- Counter collection helpers ---

# Dump raw network counters (softnet, tc qdisc/class, ethtool -S) to the
# counters file. Runs on the host directly (not via docker exec) because
# --net=host shares the network namespace, and softnet_stat is host-global.
# Usage: collect_raw_counters <label> <phy_if> [remote]
# Output is appended to $COUNTERS_FILE.
collect_raw_counters() {
    local label="$1" phy_if="$2" remote="${3:-}"
    local -a run_cmd=()
    local node_label="local"
    if [[ -n "$remote" ]]; then
        run_cmd=(ssh "$REMOTE")
        node_label="remote"
    fi

    {
        echo ""
        echo "======== $label ($node_label) | $(date -Iseconds) ========"
        echo ""
        echo "---- /proc/net/softnet_stat ----"
        "${run_cmd[@]}" cat /proc/net/softnet_stat 2>&1 || echo "(unavailable)"
        echo ""
        echo "---- tc -s qdisc show dev $phy_if ----"
        "${run_cmd[@]}" tc -s qdisc show dev "$phy_if" 2>&1 || echo "(unavailable)"
        echo ""
        echo "---- tc -s qdisc show dev $TUN_IF ----"
        "${run_cmd[@]}" tc -s qdisc show dev "$TUN_IF" 2>&1 || echo "(unavailable)"
        echo ""
        echo "---- tc -s class show dev $phy_if ----"
        "${run_cmd[@]}" tc -s class show dev "$phy_if" 2>&1 || echo "(no classes)"
        echo ""
        echo "---- ethtool -S $phy_if ----"
        "${run_cmd[@]}" ethtool -S "$phy_if" 2>&1 || echo "(unavailable)"
        echo ""
    } >> "$COUNTERS_FILE"
}

# Dump raw container-level counters (TUN link stats, UDP socket drops, nstat)
# to the counters file via docker exec.
# Usage: collect_container_counters <label> <container> <tun_if> <udp_port> [remote]
# Output is appended to $COUNTERS_FILE.
collect_container_counters() {
    local label="$1" ctr="$2" tun="$3" port="$4" remote="${5:-}"
    local hex_port
    hex_port=$(printf '%04X' "$port")
    local script
    script=$(cat <<'SCRIPT'
echo "---- ip -s link show TUN_IF ----"
ip -s link show TUN_IF 2>&1 || echo "(unavailable)"
echo ""
echo "---- /proc/1/net/udp (port HEX_PORT) ----"
cat /proc/1/net/udp 2>&1 || echo "(unavailable)"
echo ""
echo "---- nstat -az ----"
nstat -az 2>&1 || echo "(unavailable)"
SCRIPT
    )
    script="${script//TUN_IF/$tun}"
    script="${script//HEX_PORT/$hex_port}"

    local node_label="local"
    if [[ -n "$remote" ]]; then
        node_label="remote"
    fi

    {
        echo ""
        echo "======== $label ($node_label / $ctr) | $(date -Iseconds) ========"
        echo ""
        if [[ -n "$remote" ]]; then
            ssh "$REMOTE" "docker exec \"$ctr\" sh -c '$script'" 2>&1 || echo "(docker exec failed)"
        else
            docker exec "$ctr" sh -c "$script" 2>&1 || echo "(docker exec failed)"
        fi
        echo ""
    } >> "$COUNTERS_FILE"
}

# --- Smoke test ---
# When BENCH_DRY_RUN=1, validate helper functions and exit early
# (before any remote operations or Docker image pulls).
if [[ "${BENCH_DRY_RUN:-0}" == "1" ]]; then
    mkdir -p "$BENCH_DIR"
    COUNTERS_FILE="$BENCH_DIR/counters-dryrun.txt"
    echo "# dry-run" > "$COUNTERS_FILE"
    echo "[dry-run] Testing collect_raw_counters..."
    collect_raw_counters "DRY-RUN TEST" "lo"
    echo "[dry-run] Counters file contents:"
    cat "$COUNTERS_FILE"
    rm -f "$COUNTERS_FILE"
    # Clean up auto-created temp cert dir (cleanup trap not registered yet)
    [[ "$CERT_DIR" == /tmp/h3llo-bench-certs.* ]] && rm -rf "$CERT_DIR"
    echo "[dry-run] OK"
    exit 0
fi

# --- Prerequisites ---
for cmd in docker ssh scp iperf3 openssl; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "Error: $cmd not found" >&2; exit 1; }
done

# --- Pull latest Docker image and build bench variant ---
echo "Pulling latest image: $IMAGE ..."
docker pull "$IMAGE"
ssh "$REMOTE" "docker pull \"$IMAGE\""

# Build a derived image with benchmark dependencies (iperf3, iproute2, ping).
# The production image is minimal; we layer tools on top to avoid modifying it.
BENCH_IMAGE="${IMAGE}:bench"
echo "Building benchmark image: $BENCH_IMAGE ..."
printf 'FROM %s\nRUN apk add --no-cache iperf3 iputils-ping iproute2\n' "$IMAGE" \
    | docker build --quiet -t "$BENCH_IMAGE" -
printf 'FROM %s\nRUN apk add --no-cache iperf3 iputils-ping iproute2\n' "$IMAGE" \
    | ssh "$REMOTE" "docker build --quiet -t \"$BENCH_IMAGE\" -"

# --- Cleanup ---
cleanup() {
    echo "[cleanup] Stopping containers and cleaning up..."
    [[ -n "${COUNTERS_FILE:-}" ]] && echo "[cleanup] Raw counters (partial): $COUNTERS_FILE"
    docker rm -f "$LOCAL_CTR" 2>/dev/null || true
    ssh "$REMOTE" "docker rm -f \"$REMOTE_CTR\"" 2>/dev/null || true
    sleep 1
    # Remove leftover TUN devices (--net=host leaves them in the host namespace).
    # Requires NET_ADMIN, so use a privileged Docker container.
    docker run --rm --net=host --cap-add NET_ADMIN --entrypoint ip "$BENCH_IMAGE" link del tun-bench 2>/dev/null || true
    ssh "$REMOTE" "docker run --rm --net=host --cap-add NET_ADMIN --entrypoint ip \"$BENCH_IMAGE\" link del tun-bench" 2>/dev/null || true
    # Remove generated cert dirs (local + remote)
    if [[ -d "$CERT_DIR" ]]; then rm -rf "$CERT_DIR"; fi
    ssh "$REMOTE" "rm -rf \"$CERT_DIR\"" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

stop_containers() {
    docker rm -f "$LOCAL_CTR" 2>/dev/null || true
    ssh "$REMOTE" "docker rm -f \"$REMOTE_CTR\"" 2>/dev/null || true
    sleep 2
}

# --- Tunnel lifecycle ---
start_tunnel() {
    local local_cfg="$1"
    local remote_cfg="$2"

    # Clean up leftover TUN devices from previous runs (requires NET_ADMIN)
    docker run --rm --net=host --cap-add NET_ADMIN "$BENCH_IMAGE" sh -c "ip link del $TUN_IF" 2>/dev/null || true
    ssh "$REMOTE" "docker run --rm --net=host --cap-add NET_ADMIN \"$BENCH_IMAGE\" sh -c 'ip link del $TUN_IF'" 2>/dev/null || true

    ssh "$REMOTE" "mkdir -p \"$BENCH_DIR\""
    scp -q "$BENCH_DIR/$remote_cfg" "$REMOTE:$BENCH_DIR/$remote_cfg"

    # Start remote container
    ssh "$REMOTE" "docker rm -f \"$REMOTE_CTR\" 2>/dev/null; \
        docker run -d --name \"$REMOTE_CTR\" \
        $DOCKER_FLAGS \
        -e RUST_LOG=h3llo=debug \
        -v \"$BENCH_DIR\":/etc/h3llo \
        -v \"$CERT_DIR\":/certs \
        \"$BENCH_IMAGE\" -c \"/etc/h3llo/$remote_cfg\""

    # Start local container
    docker rm -f "$LOCAL_CTR" 2>/dev/null || true
    docker run -d --name "$LOCAL_CTR" \
        $DOCKER_FLAGS \
        -e RUST_LOG=h3llo=debug \
        -v "$BENCH_DIR":/etc/h3llo \
        -v "$CERT_DIR":/certs \
        "$BENCH_IMAGE" -c "/etc/h3llo/$local_cfg"

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
        ssh "$REMOTE" "docker logs \"$REMOTE_CTR\" 2>&1 | tail -40"
        return 1
    fi
}

# --- iperf3 helpers ---
run_iperf_tcp() {
    echo "--- TCP ---"
    ssh "$REMOTE" "docker exec -d \"$REMOTE_CTR\" iperf3 -s -1"
    sleep 1
    docker exec "$LOCAL_CTR" iperf3 -c 10.0.0.2 -t "$IPERF_TIME"
}

run_iperf_udp() {
    echo "--- UDP 5Gbps (payload=${UDP_PAYLOAD}B, no frag) ---"
    ssh "$REMOTE" "docker exec -d \"$REMOTE_CTR\" iperf3 -s -1"
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
    collect_container_counters "$label - BEFORE" "$LOCAL_CTR" "$TUN_IF" "$udp_port"
    collect_container_counters "$label - BEFORE" "$REMOTE_CTR" "$TUN_IF" "$udp_port" remote
    collect_raw_counters "$label - BEFORE" "$LOCAL_IF"
    collect_raw_counters "$label - BEFORE" "$REMOTE_IF" remote

    run_iperf_tcp
    echo ""
    run_iperf_udp

    # --- Capture post-test counters ---
    collect_container_counters "$label - AFTER" "$LOCAL_CTR" "$TUN_IF" "$udp_port"
    collect_container_counters "$label - AFTER" "$REMOTE_CTR" "$TUN_IF" "$udp_port" remote
    collect_raw_counters "$label - AFTER" "$LOCAL_IF"
    collect_raw_counters "$label - AFTER" "$REMOTE_IF" remote

    # --- Print h3llo debug logs (includes congestion metrics) ---
    echo ""
    echo "  --- h3llo logs: Local ($LOCAL_CTR) ---"
    docker logs "$LOCAL_CTR" 2>&1
    echo "  --- h3llo logs: Remote ($REMOTE_CTR) ---"
    ssh "$REMOTE" "docker logs \"$REMOTE_CTR\" 2>&1"

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
  tun_tx_queue_len: $TUN_TX_QUEUE_LEN
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
  tun_tx_queue_len: $TUN_TX_QUEUE_LEN
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
  tun_tx_queue_len: ${TUN_TX_QUEUE_LEN}
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
  tun_tx_queue_len: ${TUN_TX_QUEUE_LEN}
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

# ============================================================
# Main
# ============================================================
mkdir -p "$BENCH_DIR"

# --- Initialize raw counters file ---
COUNTERS_FILE="$BENCH_DIR/counters-$(date +%Y%m%dT%H%M%S).txt"
{
    echo "# h3llo benchmark raw counters - $(date -Iseconds)"
    echo "# Local: $LOCAL_IP ($LOCAL_IF) | Remote: $REMOTE_IP ($REMOTE_IF)"
    echo "# TUN: $TUN_IF | MTU: $TUN_MTU"
} > "$COUNTERS_FILE"
echo "  Raw counters file: $COUNTERS_FILE"

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
ssh "$REMOTE" "mkdir -p \"$CERT_DIR\""
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
echo "  Raw counters saved to: $COUNTERS_FILE"
echo "================================================================"
