#!/usr/bin/env bash
set -euo pipefail

# Profile resident memory growth (RSS) and smaps_rollup for h3llo.
# Example:
#   sudo ./scripts/profile-rss.sh -d 600 -c /root/v5/h3llo.yaml

DURATION=60
INTERVAL=1
CONFIG="/root/v5/h3llo.yaml"
BINARY="/home/ubuntu/ANETv5/tmp/h3llo/target/debug/h3llo"
OUTPUT_PREFIX=""
RUST_LOG_LEVEL="${RUST_LOG_LEVEL:-h3llo=info}"
PMAP_EVERY=30

usage() {
  cat <<'EOF'
Usage: profile-rss.sh [options]

Options:
  -d, --duration <seconds>      Sample duration in seconds (default: 60)
  -i, --interval <seconds>      Sample interval in seconds (default: 1)
  -c, --config <path>           h3llo config path (default: /root/v5/h3llo.yaml)
  -b, --binary <path>           h3llo binary path
                                (default: /home/ubuntu/ANETv5/tmp/h3llo/target/debug/h3llo)
  -o, --output-prefix <path>    Output prefix (default: /tmp/h3llo-rss-<duration>s-<timestamp>)
      --pmap-every <seconds>    Dump pmap every N seconds; 0 to disable (default: 30)
  -h, --help                    Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--duration)
      DURATION="${2:?missing duration}"
      shift 2
      ;;
    -i|--interval)
      INTERVAL="${2:?missing interval}"
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
    --pmap-every)
      PMAP_EVERY="${2:?missing pmap interval}"
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

if [[ -z "$OUTPUT_PREFIX" ]]; then
  OUTPUT_PREFIX="/tmp/h3llo-rss-${DURATION}s-$(date +%Y%m%d-%H%M%S)"
fi

for cmd in awk date kill sed; do
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

RSS_CSV="${OUTPUT_PREFIX}.rss.csv"
SMAPS_CSV="${OUTPUT_PREFIX}.smaps.csv"
SUMMARY_TXT="${OUTPUT_PREFIX}.summary.txt"
RUN_LOG="${OUTPUT_PREFIX}.run.log"

rm -f "$RSS_CSV" "$SMAPS_CSV" "$SUMMARY_TXT" "$RUN_LOG"

echo "ts,sec,rss_kb,vms_kb,threads" > "$RSS_CSV"
echo "ts,sec,rss_kb,pss_kb,anon_kb,file_kb,shared_dirty_kb" > "$SMAPS_CSV"

echo "[profile-rss] duration=${DURATION}s interval=${INTERVAL}s"
echo "[profile-rss] binary=$BINARY"
echo "[profile-rss] config=$CONFIG"
echo "[profile-rss] output_prefix=$OUTPUT_PREFIX"

env RUST_LOG="$RUST_LOG_LEVEL" "$BINARY" -c "$CONFIG" > "$RUN_LOG" 2>&1 &
PID=$!
echo "[profile-rss] h3llo_pid=$PID"

for ((sec=1; sec<=DURATION; sec+=INTERVAL)); do
  if [[ ! -r "/proc/$PID/status" ]]; then
    echo "[profile-rss] process exited at ${sec}s"
    break
  fi

  ts="$(date +%s)"
  rss_kb="$(awk '/VmRSS:/ {print $2}' "/proc/$PID/status")"
  vms_kb="$(awk '/VmSize:/ {print $2}' "/proc/$PID/status")"
  threads="$(awk '/Threads:/ {print $2}' "/proc/$PID/status")"
  echo "${ts},${sec},${rss_kb:-0},${vms_kb:-0},${threads:-0}" >> "$RSS_CSV"

  awk -v ts="$ts" -v sec="$sec" '
    $1=="Rss:" {rss=$2}
    $1=="Pss:" {pss=$2}
    $1=="Anonymous:" {anon=$2}
    $1=="Private_Clean:" {pc=$2}
    $1=="Shared_Clean:" {sc=$2}
    $1=="Shared_Dirty:" {sd=$2}
    END {
      file = (pc + sc)
      printf "%s,%s,%d,%d,%d,%d,%d\n", ts, sec, rss + 0, pss + 0, anon + 0, file + 0, sd + 0
    }
  ' "/proc/$PID/smaps_rollup" >> "$SMAPS_CSV"

  if [[ "$PMAP_EVERY" -gt 0 ]] && (( sec % PMAP_EVERY == 0 )); then
    if command -v pmap >/dev/null 2>&1; then
      pmap -x "$PID" > "${OUTPUT_PREFIX}.pmap.${sec}s.txt" 2>/dev/null || true
    fi
  fi

  sleep "$INTERVAL"
done

kill -INT "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true

{
  echo "output_prefix=$OUTPUT_PREFIX"
  awk -F, '
    NR==2 {rss_start=$3; sec_start=$2}
    NR>1 {
      rss=$3+0
      if (rss > rss_max) {rss_max=rss; sec_max=$2}
      rss_end=rss; sec_end=$2
      if (min_set == 0 || rss < rss_min) {rss_min=rss; sec_min=$2; min_set=1}
    }
    END {
      growth=rss_end-rss_start
      printf("rss_start_kb=%d at %ss (%.2f MiB)\n", rss_start, sec_start, rss_start/1024)
      printf("rss_peak_kb=%d at %ss (%.2f MiB)\n", rss_max, sec_max, rss_max/1024)
      printf("rss_min_kb=%d at %ss (%.2f MiB)\n", rss_min, sec_min, rss_min/1024)
      printf("rss_end_kb=%d at %ss (%.2f MiB)\n", rss_end, sec_end, rss_end/1024)
      printf("rss_growth_kb=%d (%.2f MiB)\n", growth, growth/1024)
    }
  ' "$RSS_CSV"
  awk -F, '
    NR>1 {
      anon=$5+0
      file=$6+0
      if (anon > anon_max) {anon_max=anon; sec_anon=$2}
      if (file > file_max) {file_max=file; sec_file=$2}
      anon_end=anon
      file_end=file
    }
    END {
      printf("anon_peak_kb=%d at %ss (%.2f MiB)\n", anon_max, sec_anon, anon_max/1024)
      printf("file_peak_kb=%d at %ss (%.2f MiB)\n", file_max, sec_file, file_max/1024)
      printf("anon_end_kb=%d (%.2f MiB)\n", anon_end, anon_end/1024)
      printf("file_end_kb=%d (%.2f MiB)\n", file_end, file_end/1024)
    }
  ' "$SMAPS_CSV"
} | tee "$SUMMARY_TXT"

echo "[profile-rss] done"
echo "[profile-rss] rss_csv=$RSS_CSV"
echo "[profile-rss] smaps_csv=$SMAPS_CSV"
echo "[profile-rss] summary=$SUMMARY_TXT"
echo "[profile-rss] run_log=$RUN_LOG"
