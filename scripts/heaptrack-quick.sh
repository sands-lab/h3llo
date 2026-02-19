#!/usr/bin/env bash
set -euo pipefail

# Quick heaptrack runner:
# 1) start heaptrack on h3llo
# 2) wait N seconds
# 3) send INT to h3llo (child of heaptrack) so it exits gracefully
# 4) heaptrack flushes output and exits
# 5) fallback: kill heaptrack after timeout if it hangs

DURATION="${1:-10}"
BINARY="${2:-/tmp/h3llo-from-image}"
CONFIG="${3:-/root/v5/h3llo.yaml}"
OUT_PREFIX="${4:-/tmp/h3llo-heap-${DURATION}s-$(date +%Y%m%d-%H%M%S)}"
FLUSH_TIMEOUT=15

command -v heaptrack >/dev/null 2>&1 || { echo "heaptrack not found" >&2; exit 1; }
[[ -x "$BINARY" ]] || { echo "binary not executable: $BINARY" >&2; exit 1; }
[[ -f "$CONFIG" ]] || { echo "config not found: $CONFIG" >&2; exit 1; }

echo "[ht] duration=${DURATION}s  binary=$BINARY"
echo "[ht] config=$CONFIG"
echo "[ht] out=$OUT_PREFIX"

env RUST_LOG="${RUST_LOG:-h3llo=info}" \
  heaptrack -o "$OUT_PREFIX" "$BINARY" -c "$CONFIG" \
  > "${OUT_PREFIX}.run.log" 2>&1 &
HPID=$!
echo "[ht] heaptrack pid=$HPID"

# Find h3llo: it's a direct child of heaptrack.
H3PID=""
for _ in $(seq 1 50); do
  H3PID="$(pgrep -P "$HPID" 2>/dev/null | head -1)" && [[ -n "$H3PID" ]] && break
  H3PID=""
  sleep 0.1
done

if [[ -z "$H3PID" ]]; then
  echo "[ht] WARN: could not find h3llo child pid, will kill heaptrack directly" >&2
fi

echo "[ht] h3llo pid=${H3PID:-NA}, sleeping ${DURATION}s..."
sleep "$DURATION"

# Stop h3llo gracefully → heaptrack flushes and exits.
if [[ -n "$H3PID" ]]; then
  kill -INT "$H3PID" 2>/dev/null || true
  echo "[ht] sent INT to h3llo pid=$H3PID"
else
  kill -INT "$HPID" 2>/dev/null || true
  echo "[ht] sent INT to heaptrack pid=$HPID"
fi

# Wait with timeout.
WAITED=0
while kill -0 "$HPID" 2>/dev/null; do
  sleep 1
  WAITED=$((WAITED + 1))
  if [[ "$WAITED" -ge "$FLUSH_TIMEOUT" ]]; then
    echo "[ht] heaptrack still alive after ${FLUSH_TIMEOUT}s, force killing"
    kill -9 "$HPID" 2>/dev/null || true
    break
  fi
done
wait "$HPID" 2>/dev/null || true

echo "[ht] done"
ls -lah "${OUT_PREFIX}"*.zst "${OUT_PREFIX}.run.log" 2>/dev/null
echo "[ht] To inspect:"
echo "  heaptrack_print -f ${OUT_PREFIX}.zst -n 20 -s 8 | head -200"
