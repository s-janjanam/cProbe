#!/bin/bash
set -e

# Configuration file path
CONFIG_FILE="/opt/nprobe/config/nprobe-config.json"
LOG_FILE="/opt/nprobe/logs/nprobe.log"

# Create log directory if it doesn't exist
mkdir -p /opt/nprobe/logs

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Function to extract configuration values
get_config() {
    jq -r "$1" "$CONFIG_FILE"
}

log "Starting nProbe container initialization..."

# Check if configuration file exists
if [ ! -f "$CONFIG_FILE" ]; then
    log "ERROR: Configuration file not found at $CONFIG_FILE"
    exit 1
fi

# Validate JSON configuration
if ! jq empty "$CONFIG_FILE" 2>/dev/null; then
    log "ERROR: Invalid JSON in configuration file"
    exit 1
fi

# Load configuration values
INTERFACE=$(get_config '.nprobe.capture.interface')
COLLECTOR_IP=$(get_config '.nprobe.flow_export.collector_ip')
COLLECTOR_PORT=$(get_config '.nprobe.flow_export.collector_port')
NETFLOW_VERSION=$(get_config '.nprobe.flow_export.netflow_version')
VERBOSE_LEVEL=$(get_config '.nprobe.general.verbose_level')

log "Configuration loaded:"
log "  Interface: $INTERFACE"
log "  Collector: $COLLECTOR_IP:$COLLECTOR_PORT"
log "  NetFlow Version: $NETFLOW_VERSION"
log "  Verbose Level: $VERBOSE_LEVEL"

# Check if running in privileged mode (required for packet capture)
if [ ! -w /proc/sys ]; then
    log "WARNING: Container may not be running in privileged mode"
    log "         Packet capture may not work properly"
fi

# Load PF_RING kernel module if not already loaded
if ! lsmod | grep -q pf_ring; then
    log "Loading PF_RING kernel module..."
    if ! modprobe pf_ring; then
        log "WARNING: Failed to load PF_RING module"
        log "         Make sure the container is running with --privileged flag"
    fi
fi

# Configure hugepages if Mellanox OFED is enabled
if [ "$(get_config '.environment.mellanox_ofed.enabled')" = "true" ]; then
    HUGEPAGES_COUNT=$(get_config '.environment.mellanox_ofed.hugepages_count')
    if [ "$HUGEPAGES_COUNT" != "null" ] && [ "$HUGEPAGES_COUNT" -gt 0 ]; then
        log "Configuring hugepages: $HUGEPAGES_COUNT pages"
        echo "$HUGEPAGES_COUNT" > /proc/sys/vm/nr_hugepages 2>/dev/null || log "WARNING: Failed to configure hugepages"
    fi
fi

# Set CPU governor if specified
CPU_GOVERNOR=$(get_config '.environment.system.set_cpu_governor')
if [ "$CPU_GOVERNOR" != "null" ] && [ "$CPU_GOVERNOR" != "" ]; then
    log "Setting CPU governor to: $CPU_GOVERNOR"
    for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        [ -f "$cpu" ] && echo "$CPU_GOVERNOR" > "$cpu" 2>/dev/null || true
    done
fi

# Check if interface exists
if [ ! -d "/sys/class/net/$INTERFACE" ]; then
    log "WARNING: Network interface $INTERFACE not found"
    log "Available interfaces:"
    ls /sys/class/net/ | grep -v lo | while read iface; do
        log "  - $iface"
    done
fi

# Check if collector is reachable (optional test)
if command -v nc >/dev/null 2>&1; then
    if ! nc -z -w5 "$COLLECTOR_IP" "$COLLECTOR_PORT" 2>/dev/null; then
        log "WARNING: Cannot reach collector at $COLLECTOR_IP:$COLLECTOR_PORT"
        log "         Flow export may fail"
    else
        log "Collector connectivity test passed"
    fi
fi

# Start nProbe with configuration
log "Starting nProbe..."
exec /opt/nprobe/start-nprobe.sh
