#!/usr/bin/env bash
set -euo pipefail

# Profile h3llo memory with heaptrack for a fixed duration.
# Example:
#   sudo ./scripts/profile-h3llo.sh -d 60 -c /root/v5/h3llo.yaml

DURATION=60
CONFIG="/root/v5/h3llo.yaml"
BINARY="/home/ubuntu/ANETv5/tmp/h3llo/target/debug/h3llo"
OUTPUT_PREFIX=""
RUST_LOG_LEVEL="${RUST_LOG_LEVEL:-h3llo=info}"
TOP_N=20
SUB_TOP_N=8

usage() {
  cat <<'EOF'
Usage: profile-h3llo.sh [options]

Options:
  -d, --duration <seconds>     Profile duration in seconds (default: 60)
  -c, --config <path>          h3llo config path (default: /root/v5/h3llo.yaml)
  -b, --binary <path>          h3llo binary path
                               (default: /home/ubuntu/ANETv5/tmp/h3llo/target/debug/h3llo)
  -o, --output-prefix <path>   Output prefix (default: /tmp/h3llo-<duration>s-<timestamp>)
  -n, --top-n <count>          Top entries for heaptrack_print (default: 20)
  -h, --help                   Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--duration)
      DURATION="${2:?missing duration}"
      shift 2
      ;;
    -c|--config)
      CONFIG="${2:?missing config}"
      shift 2
      ;;
    -b|--binary)
      BINARY="${2:?missing binary}"
      shift 2
      ;;
    -o|--output-prefix)
      OUTPUT_PREFIX="${2:?missing output prefix}"
      shift 2
      ;;
    -n|--top-n)
      TOP_N="${2:?missing top-n}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "${OUTPUT_PREFIX}" ]]; then
  OUTPUT_PREFIX="/tmp/h3llo-${DURATION}s-$(date +%Y%m%d-%H%M%S)"
fi

for cmd in heaptrack heaptrack_print pgrep awk sed; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "Error: required command not found: $cmd" >&2
    exit 1
  }
done

if [[ ! -x "$BINARY" ]]; then
  echo "Error: binary not executable: $BINARY" >&2
  exit 1
fi

if [[ ! -f "$CONFIG" ]]; then
  echo "Error: config not found: $CONFIG" >&2
  exit 1
fi

HEAP_ZST="${OUTPUT_PREFIX}.zst"
RUN_LOG="${OUTPUT_PREFIX}.run.log"
PRINT_TXT="${OUTPUT_PREFIX}.print.txt"
MASSIF_TXT="${OUTPUT_PREFIX}.massif"
SUMMARY_TXT="${OUTPUT_PREFIX}.summary.txt"

rm -f "$HEAP_ZST" "$RUN_LOG" "$PRINT_TXT" "$MASSIF_TXT" "$SUMMARY_TXT"

echo "[profile] duration=${DURATION}s"
echo "[profile] binary=$BINARY"
echo "[profile] config=$CONFIG"
echo "[profile] output_prefix=$OUTPUT_PREFIX"

env RUST_LOG="$RUST_LOG_LEVEL" heaptrack -o "$OUTPUT_PREFIX" "$BINARY" -c "$CONFIG" > "$RUN_LOG" 2>&1 &
HPID=$!
echo "[profile] heaptrack_pid=$HPID"

sleep "$DURATION"

H3PID="$(pgrep -P "$HPID" -f "$BINARY" | head -n1 || true)"
if [[ -n "$H3PID" ]]; then
  kill -INT "$H3PID" 2>/dev/null || true
  echo "[profile] sent INT to h3llo pid=$H3PID"
fi

sleep 3
kill -INT "$HPID" 2>/dev/null || true
wait "$HPID" || true

if [[ ! -s "$HEAP_ZST" ]]; then
  echo "Error: heaptrack output missing or empty: $HEAP_ZST" >&2
  echo "See run log: $RUN_LOG" >&2
  exit 2
fi

heaptrack_print -f "$HEAP_ZST" -n "$TOP_N" -s "$SUB_TOP_N" -p 1 -a 1 -T 1 -l 1 > "$PRINT_TXT"
heaptrack_print -f "$HEAP_ZST" --massif-threshold 0 --massif-detailed-freq 1 -M "$MASSIF_TXT" > /dev/null

{
  echo "output_prefix=$OUTPUT_PREFIX"
  awk -F= '
    /^snapshot=/{s=$2}
    /^time=/{t=$2}
    /^mem_heap_B=/{if ($2 > max) {max=$2; tmax=t; smax=s}}
    END {printf("max_mem_heap_B=%d (%.2f MiB) at_time=%ss snapshot=%s\n", max, max/1024/1024, tmax, smax)}
  ' "$MASSIF_TXT"
  echo "top_peak_consumers:"
  awk '
    /peak memory consumed over/ {print; getline; print}
  ' "$PRINT_TXT" | sed -n '1,40p'
} | tee "$SUMMARY_TXT"

echo "[profile] done"
echo "[profile] heaptrack=$HEAP_ZST"
echo "[profile] log=$RUN_LOG"
echo "[profile] report=$PRINT_TXT"
echo "[profile] summary=$SUMMARY_TXT"
