#!/usr/bin/env bash

# Hook to log token usage to ~/claude-usage.log
# Triggered on Stop event (after Claude finishes responding)

# Debug log file
DEBUG_LOG=~/claude-hook-debug.log

# Read hook input JSON from stdin
INPUT=$(cat)

# Debug: log the input
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Stop hook triggered" >> "$DEBUG_LOG"
echo "Input: $INPUT" >> "$DEBUG_LOG"

# Extract transcript path from JSON
TRANSCRIPT_PATH=$(echo "$INPUT" | jq -r '.transcript_path // empty')

echo "Transcript path: $TRANSCRIPT_PATH" >> "$DEBUG_LOG"

if [ -z "$TRANSCRIPT_PATH" ]; then
    echo "ERROR: transcript_path is empty" >> "$DEBUG_LOG"
    exit 0
fi

if [ ! -f "$TRANSCRIPT_PATH" ]; then
    echo "ERROR: transcript file does not exist: $TRANSCRIPT_PATH" >> "$DEBUG_LOG"
    exit 0
fi

echo "Transcript file exists, processing..." >> "$DEBUG_LOG"

# Extract token usage from the last message with usage information
LAST_USAGE=$(tail -50 "$TRANSCRIPT_PATH" | jq -rs '
  map(select(.message.usage != null))
  | last
  | .message.usage
  | {
      input: (.input_tokens // 0),
      cache_creation: (.cache_creation_input_tokens // 0),
      cache_read: (.cache_read_input_tokens // 0),
      output: (.output_tokens // 0)
    }
  | "input=\(.input) cache_creation=\(.cache_creation) cache_read=\(.cache_read) output=\(.output)"
' 2>>"$DEBUG_LOG")

echo "Extracted token info: $LAST_USAGE" >> "$DEBUG_LOG"

# If we found token usage info, log it
if [ -n "$LAST_USAGE" ] && [ "$LAST_USAGE" != "null" ]; then
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    SESSION_ID=$(echo "$INPUT" | jq -r '.session_id // "unknown"')
    CWD=$(echo "$INPUT" | jq -r '.cwd // "unknown"')

    # Append to log file
    echo "$TIMESTAMP | session=$SESSION_ID | cwd=$CWD | $LAST_USAGE" >> ~/claude-usage.log
    echo "Successfully logged to ~/claude-usage.log" >> "$DEBUG_LOG"
else
    echo "ERROR: No token info found in transcript" >> "$DEBUG_LOG"
fi
