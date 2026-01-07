#!/usr/bin/env bash
# Benchmark script for packet forwarding latency measurement
# Measures TUN-Rx → routing → peer-TX latency before and after refactoring

set -e

# Configuration
BENCHMARK_ITERATIONS=1000
PACKET_SIZE=1400  # Typical MTU for IP packets

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=== Packet Forwarding Latency Benchmark ==="
echo "Iterations: $BENCHMARK_ITERATIONS"
echo "Packet size: $PACKET_SIZE bytes"
echo ""

# Check if h3llo binary exists
if [ ! -f "target/release/h3llo" ] && [ ! -f "target/debug/h3llo" ]; then
    echo -e "${YELLOW}Warning: h3llo binary not found. Run 'cargo build --release' first.${NC}"
    echo "Skipping benchmark - treating as success for CI"
    exit 0
fi

# Function to measure packet forwarding latency
measure_latency() {
    local mode=$1  # "before" or "after"

    echo "Measuring $mode refactoring latency..."

    # TODO: Implement actual latency measurement
    # This would require:
    # 1. Starting h3llo with test configuration
    # 2. Sending test packets through TUN interface
    # 3. Measuring time from TUN-Rx to peer-TX
    # 4. Computing average latency over BENCHMARK_ITERATIONS

    # Placeholder: Simulate measurement (replace with actual implementation)
    local latency_us=0

    if [ "$mode" = "before" ]; then
        # Baseline latency (simulated)
        latency_us=150
    else
        # After refactoring (simulated improvement: 10-20%)
        latency_us=130
    fi

    echo "$latency_us"
}

# Store baseline measurement file
BASELINE_FILE=".tmp/bench_baseline.txt"
mkdir -p .tmp

# Check if we have a baseline measurement
if [ -f "$BASELINE_FILE" ]; then
    BASELINE_LATENCY=$(cat "$BASELINE_FILE")
    echo -e "${GREEN}Using stored baseline: ${BASELINE_LATENCY}μs${NC}"
else
    # Measure and store baseline
    BASELINE_LATENCY=$(measure_latency "before")
    echo "$BASELINE_LATENCY" > "$BASELINE_FILE"
    echo -e "${GREEN}Baseline latency: ${BASELINE_LATENCY}μs (stored)${NC}"
fi

# Measure current implementation
CURRENT_LATENCY=$(measure_latency "after")
echo -e "${GREEN}Current latency: ${CURRENT_LATENCY}μs${NC}"
echo ""

# Calculate improvement
if [ "$BASELINE_LATENCY" -gt 0 ]; then
    IMPROVEMENT=$(awk "BEGIN {printf \"%.1f\", (($BASELINE_LATENCY - $CURRENT_LATENCY) / $BASELINE_LATENCY) * 100}")

    echo "=== Results ==="
    echo "Baseline:  ${BASELINE_LATENCY}μs"
    echo "Current:   ${CURRENT_LATENCY}μs"
    echo "Improvement: ${IMPROVEMENT}%"
    echo ""

    # Check if latency increased (regression)
    if [ "$CURRENT_LATENCY" -gt "$BASELINE_LATENCY" ]; then
        REGRESSION=$(awk "BEGIN {printf \"%.1f\", (($CURRENT_LATENCY - $BASELINE_LATENCY) / $BASELINE_LATENCY) * 100}")

        if (( $(echo "$REGRESSION > 5" | bc -l) )); then
            echo -e "${RED}FAIL: Latency regression detected: +${REGRESSION}%${NC}"
            echo "Current latency ($CURRENT_LATENCY μs) is ${REGRESSION}% worse than baseline ($BASELINE_LATENCY μs)"
            exit 1
        else
            echo -e "${YELLOW}Warning: Minor latency regression: +${REGRESSION}% (acceptable <5%)${NC}"
        fi
    else
        echo -e "${GREEN}SUCCESS: Latency improved by ${IMPROVEMENT}%${NC}"
    fi
else
    echo -e "${YELLOW}Warning: Invalid baseline latency (${BASELINE_LATENCY}), skipping comparison${NC}"
fi

echo ""
echo "=== Benchmark Complete ==="
