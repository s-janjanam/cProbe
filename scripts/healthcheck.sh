#!/bin/bash
# File: scripts/healthcheck.sh
# Health check script for nProbe container

PID_FILE="/var/run/nprobe.pid"
CONFIG_FILE="/etc/nprobe/config.json"

# Check if nProbe process is running
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        echo "nProbe process is running (PID: $PID)"
    else
        echo "nProbe PID file exists but process is not running"
        exit 1
    fi
else
    echo "nProbe PID file not found"
    exit 1
fi

# Check if web interface is responding
WEB_PORT=$(python3 -c "import json; print(json.load(open('$CONFIG_FILE'))['nprobe']['web_interface']['port'])")
if curl -f -s "http://localhost:$WEB_PORT" >/dev/null 2>&1; then
    echo "Web interface is responding"
else
    echo "Web interface is not responding"
    exit 1
fi

# Check if flows are being processed (basic check)
if [ -f "/var/log/nprobe/nprobe.log" ]; then
    # Check for recent activity in logs (within last 5 minutes)
    if find /var/log/nprobe/nprobe.log -mmin -5 | grep -q .; then
        echo "Recent log activity detected"
    else
        echo "No recent log activity"
        exit 1
    fi
fi

echo "Health check passed"
exit 0
