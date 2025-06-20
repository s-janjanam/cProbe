#!/bin/bash
set -e

# The PID file path is the first argument
PID_FILE="$1"
# The log file is the second argument
LOG_FILE="$2"
# All other arguments are passed directly to nprobe
shift 2

# Check if a process is already running using the PID file
if [ -f "$PID_FILE" ]; then
    if ps -p $(cat "$PID_FILE") > /dev/null; then
        echo "ERROR: nProbe process already running with PID $(cat "$PID_FILE")."
        exit 1
    else
        # The process is not running, so remove the stale PID file
        echo "WARNING: Removing stale PID file."
        rm -f "$PID_FILE"
    fi
fi

# Launch nprobe in the background
# All remaining arguments "$@" are passed to nprobe
echo "==> Launching nProbe..."
echo "==> Command: nprobe $@"
echo "==> Logging to: ${LOG_FILE}"

# The 'nohup' command ensures the process isn't terminated if the shell exits,
# and '&' runs it in the background. Output is redirected to the log file.
nohup /usr/bin/nprobe "$@" > "$LOG_FILE" 2>&1 &

# Capture the Process ID (PID) of the last background command
NPROBE_PID=$!

# Write the PID to the PID file. This is our proof that the process was launched.
echo "$NPROBE_PID" > "$PID_FILE"

echo "==> nProbe started with PID: $NPROBE_PID."
echo "==> PID file created at: $PID_FILE."

