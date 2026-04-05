#!/usr/bin/env bash
# Common defaults and helpers for cross-node bench scripts.
# Source this file from each bench-*.sh script:
#   source "$(dirname "$0")/bench-common.sh"
#
# Provides:
#   Variables: REMOTE, LOCAL_IP, REMOTE_IP, LOCAL_IF, REMOTE_IF, TUN_MTU,
#              NUMA_NODE, IPERF_TIME, BENCH_DIR, LOCAL_TUN, REMOTE_TUN
#   Functions: require_cmds, gen_self_signed_cert, run_iperf_tcp,
#              wait_for_connectivity, setup_wg_key_files, kill_remote_iperf,
#              print_banner, print_test_header, print_done
#   WireGuard test keys: WG_KEY_A_PRIV, WG_KEY_A_PUB, WG_KEY_B_PRIV, WG_KEY_B_PUB

# --- Common defaults (override via environment before sourcing) ---
REMOTE="${REMOTE:-mcnode26}"
LOCAL_IP="${LOCAL_IP:-10.200.2.127}"
REMOTE_IP="${REMOTE_IP:-10.200.2.126}"
LOCAL_IF="${LOCAL_IF:-bf3p1}"
REMOTE_IF="${REMOTE_IF:-bf3p1}"
TUN_MTU="${TUN_MTU:-1291}"
IPERF_TIME="${IPERF_TIME:-10}"
BENCH_DIR="${BENCH_DIR:-/tmp/bench}"

# NUMA pinning: VPN on VPN_CPUS, iperf3 on IPERF_CPU (all NUMA-local).
NUMA_NODE="${NUMA_NODE:-3}"
VPN_CPUS="${VPN_CPUS:-48-51}"
IPERF_CPU="${IPERF_CPU:-52}"

# Overlay addresses
LOCAL_TUN="${LOCAL_TUN:-10.0.0.1}"
REMOTE_TUN="${REMOTE_TUN:-10.0.0.2}"

# Fixed Curve25519 keys for WireGuard benchmarks (test-only, NOT for production).
# Generated via: wg genkey | tee priv | wg pubkey > pub
WG_KEY_A_PRIV="yAnw4/bFKWQyuiDKWrXruXyKk/Ah1CJWQfV0FTXcXWU="
WG_KEY_A_PUB="xopHDYsmeG7tk7UdovGv7RUBaiD1sADUrIlujSYHVFY="
WG_KEY_B_PRIV="0AMR6oqMwHg1NDZMRMtRXi/xd3Ot6Camb1euWJY1lWI="
WG_KEY_B_PUB="mqgf3siT/qS86WCoYmZFaXHUx5JRGSFVfjU4avuNanM="

# --- Helpers ---

# Verify that all listed commands are available.
# Usage: require_cmds docker ssh iperf3
require_cmds() {
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || { echo "Error: $cmd not found" >&2; exit 1; }
    done
}

# Generate a self-signed EC certificate (1-day validity).
# Usage: gen_self_signed_cert <key> <cert> <cn> [san] [curve]
#   san   - e.g. "IP:1.2.3.4" or "DNS:host,IP:1.2.3.4" (optional)
#   curve - EC curve name (default: prime256v1)
gen_self_signed_cert() {
    local key="$1" cert="$2" cn="$3"
    local san="${4:-}" curve="${5:-prime256v1}"
    local -a extra=()
    if [[ -n "$san" ]]; then
        extra=(-addext "subjectAltName=$san")
    fi
    openssl req -x509 -newkey ec -pkeyopt "ec_paramgen_curve:$curve" \
        -keyout "$key" -out "$cert" \
        -days 1 -nodes -subj "/CN=$cn" \
        "${extra[@]}" \
        || { echo "Error: certificate generation failed for CN=$cn" >&2; return 1; }
}

# Run an iperf3 TCP throughput test over the tunnel.
# Starts a one-shot iperf3 server on REMOTE, then runs the client locally.
# NUMA memory and CPU pinning are applied automatically via NUMA_NODE / IPERF_CPU.
# Usage: run_iperf_tcp <target_ip>
run_iperf_tcp() {
    local target="$1"
    echo "--- TCP ---"
    ssh "$REMOTE" "numactl --membind=$NUMA_NODE taskset -c $IPERF_CPU iperf3 -s -1 -B \"$target\" -D"
    sleep 1
    numactl --membind="$NUMA_NODE" taskset -c "$IPERF_CPU" iperf3 -c "$target" -t "$IPERF_TIME"
}

# Wait for tunnel connectivity via ping.
# Returns 0 on success, 1 on failure. Prints "OK" or "FAILED".
# Usage: wait_for_connectivity <target_ip> [max_retries]
#   max_retries - number of 1-second ping attempts (default: 1 = single check)
wait_for_connectivity() {
    local target="$1" max_retries="${2:-1}"
    echo -n "  Connectivity: "
    for i in $(seq 1 "$max_retries"); do
        if ping -c 1 -W 1 "$target" >/dev/null 2>&1; then
            if [[ "$max_retries" -gt 1 ]]; then
                echo "OK (${i}s)"
            else
                echo "OK"
            fi
            return 0
        fi
        [[ "$i" -lt "$max_retries" ]] && sleep 1
    done
    echo "FAILED"
    return 1
}

# Create WireGuard key files on local and remote nodes.
# Sets KEY_DIR to a temp directory containing local.key.
# Usage: setup_wg_key_files <local_priv_key> <remote_priv_key>
setup_wg_key_files() {
    local local_priv="$1" remote_priv="$2"
    KEY_DIR=$(mktemp -d /tmp/wg-bench-keys.XXXXXX)
    echo "$local_priv" > "$KEY_DIR/local.key"
    chmod 600 "$KEY_DIR/local.key"
    ssh "$REMOTE" "mkdir -p \"$KEY_DIR\" && printf '%s\n' '$remote_priv' > \"$KEY_DIR/remote.key\" && chmod 600 \"$KEY_DIR/remote.key\""
}

# Kill leftover iperf3 servers on REMOTE.
# Usage: kill_remote_iperf
kill_remote_iperf() {
    ssh "$REMOTE" "pkill -f 'iperf3 -s'" 2>/dev/null || true
}

# Print the main benchmark banner.
# Usage: print_banner "Title" ["extra line" ...]
print_banner() {
    local title="$1"; shift
    echo "================================================================"
    echo "  $title"
    echo "  Local:  $LOCAL_IP ($(hostname))"
    echo "  Remote: $REMOTE_IP ($REMOTE)"
    for line in "$@"; do
        echo "  $line"
    done
    echo "  Date: $(date -Iseconds)"
    echo "================================================================"
}

# Print a sub-test header.
# Usage: print_test_header "Label" ["extra line" ...]
print_test_header() {
    local label="$1"; shift
    echo ""
    echo "================================================================"
    echo "  $label"
    for line in "$@"; do
        echo "  $line"
    done
    echo "================================================================"
}

# Print the completion banner.
# Usage: print_done ["Custom message"]
print_done() {
    local msg="${1:-Benchmark completed.}"
    echo ""
    echo "================================================================"
    echo "  $msg"
    echo "================================================================"
}
