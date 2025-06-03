#!/bin/bash
# File: scripts/monitor-flows.sh
# Flow monitoring script

CONFIG_FILE="/etc/nprobe/config.json"
LOG_FILE="/var/log/nprobe/nprobe.log"

# Get collector information
COLLECTOR_HOST=$(python3 -c "import json; print(json.load(open('$CONFIG_FILE'))['nprobe']['collectors'][0]['host'])")
COLLECTOR_PORT=$(python3 -c "import json; print(json.load(open('$CONFIG_FILE'))['nprobe']['collectors'][0]['port'])")

echo "=== nProbe Flow Monitoring ==="
echo "Collector: $COLLECTOR_HOST:$COLLECTOR_PORT"
echo "Log file: $LOG_FILE"
echo ""

# Monitor log file for flow statistics
if [ -f "$LOG_FILE" ]; then
    echo "Recent nProbe activity:"
    tail -20 "$LOG_FILE" | grep -E "(flows|packets|bytes)" || echo "No flow statistics found in recent logs"
else
    echo "Log file not found: $LOG_FILE"
fi

echo ""
echo "=== System Resources ==="
echo "Memory usage:"
free -h

echo ""
echo "Network interfaces:"
ip link show

echo ""
echo "Active connections to collector:"
netstat -an | grep ":$COLLECTOR_PORT" || echo "No active connections to collector"
