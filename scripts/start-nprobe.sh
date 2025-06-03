#!/bin/bash
# File: scripts/start-nprobe.sh
# Main startup script for nProbe with PF_RING ZC

set -e

# Configuration file path
CONFIG_FILE="/etc/nprobe/config.json"
LOG_FILE="/var/log/nprobe/nprobe.log"
PID_FILE="/var/run/nprobe.pid"

# Function to parse JSON config
parse_config() {
    python3 - <<EOF
import json
import sys

with open('$CONFIG_FILE', 'r') as f:
    config = json.load(f)

# Extract nProbe configuration
nprobe = config['nprobe']
pfring = config['pfring']
system = config['system']

# Print environment variables
print(f"export NPROBE_LICENSE='{nprobe['license_key']}'")
print(f"export INTERFACE='{nprobe['interfaces'][0]['name']}'")
print(f"export PFRING_ZC_DEVICE='{nprobe['capture']['pfring_zc_device']}'")
print(f"export COLLECTOR_HOST='{nprobe['collectors'][0]['host']}'")
print(f"export COLLECTOR_PORT='{nprobe['collectors'][0]['port']}'")
print(f"export ACTIVE_TIMEOUT='{nprobe['flow_collection']['active_timeout']}'")
print(f"export INACTIVE_TIMEOUT='{nprobe['flow_collection']['inactive_timeout']}'")
print(f"export TEMPLATE_ID='{nprobe['netflow']['template_id']}'")
print(f"export NUM_THREADS='{nprobe['performance']['num_threads']}'")
print(f"export CLUSTER_ID='{pfring['cluster_settings']['cluster_id']}'")
print(f"export WEB_PORT='{nprobe['web_interface']['port']}'")
print(f"export LOG_LEVEL='{nprobe['logging']['level']}'")

# Build BPF filter if specified
if nprobe['filtering']['bpf_filter']:
    print(f"export BPF_FILTER='{nprobe['filtering']['bpf_filter']}'")

# Build template fields
template_name = nprobe['collectors'][0]['template']
fields = ','.join(nprobe['templates'][template_name]['fields'])
print(f"export TEMPLATE_FIELDS='{fields}'")
EOF
}

# Function to setup system parameters
setup_system() {
    echo "Setting up system parameters..."
    
    # Load PF_RING kernel module if available
    modprobe pf_ring 2>/dev/null || echo "PF_RING module not available, using userland only"
    
    # Setup hugepages if configured
    HUGEPAGES=$(python3 -c "import json; print(json.load(open('$CONFIG_FILE'))['system']['hugepages_count'])")
    if [ "$HUGEPAGES" != "0" ]; then
        echo $HUGEPAGES > /proc/sys/vm/nr_hugepages 2>/dev/null || echo "Could not set hugepages"
    fi
    
    # Set memory limits
    ulimit -l unlimited 2>/dev/null || echo "Could not set memory limits"
    
    # CPU and IRQ affinity (if running with privileges)
    if [ -w /proc/irq ]; then
        echo "Setting up IRQ affinity..."
        # This would be interface-specific in a real deployment
    fi
}

# Function to wait for network interface
wait_for_interface() {
    local interface="$1"
    local timeout=30
    local count=0
    
    echo "Waiting for interface $interface..."
    while [ $count -lt $timeout ]; do
        if ip link show "$interface" >/dev/null 2>&1; then
            echo "Interface $interface is available"
            return 0
        fi
        sleep 1
        count=$((count + 1))
    done
    
    echo "Interface $interface not found after ${timeout}s"
    return 1
}

# Function to build nProbe command line
build_nprobe_cmd() {
    local cmd="nprobe"
    
    # License
    cmd="$cmd -P /etc/nprobe/nprobe.license"
    
    # Interface and capture settings
    cmd="$cmd -i $PFRING_ZC_DEVICE"
    cmd="$cmd -n $COLLECTOR_HOST:$COLLECTOR_PORT"
    
    # Flow settings
    cmd="$cmd -t $ACTIVE_TIMEOUT"
    cmd="$cmd -d $INACTIVE_TIMEOUT"
    cmd="$cmd -T $TEMPLATE_FIELDS"
    
    # Performance settings
    cmd="$cmd -w $NUM_THREADS"
    cmd="$cmd -c $CLUSTER_ID"
    
    # Logging
    cmd="$cmd -v $LOG_LEVEL"
    cmd="$cmd -L $LOG_FILE"
    
    # Web interface
    cmd="$cmd -W $WEB_PORT"
    
    # Additional options
    cmd="$cmd -M" # Enable GeoIP if available
    cmd="$cmd -F" # Enable flow collection
    cmd="$cmd -O" # Enable extended statistics
    
    # BPF filter if specified
    if [ -n "$BPF_FILTER" ]; then
        cmd="$cmd -f '$BPF_FILTER'"
    fi
    
    # Daemon mode
    cmd="$cmd -D $PID_FILE"
    
    echo "$cmd"
}

# Main execution
main() {
    echo "Starting nProbe with PF_RING ZC..."
    
    # Create log directory
    mkdir -p "$(dirname "$LOG_FILE")"
    mkdir -p "$(dirname "$PID_FILE")"
    
    # Parse configuration
    echo "Loading configuration from $CONFIG_FILE..."
    eval "$(parse_config)"
    
    # Setup system
    setup_system
    
    # Wait for interface
    wait_for_interface "$INTERFACE"
    
    # Create license file from config
    echo "$NPROBE_LICENSE" > /etc/nprobe/nprobe.license
    
    # Build and execute nProbe command
    NPROBE_CMD=$(build_nprobe_cmd)
    echo "Executing: $NPROBE_CMD"
    
    # Start nProbe
    exec $NPROBE_CMD
}

# Trap signals for graceful shutdown
trap 'echo "Shutting down nProbe..."; kill -TERM $(cat $PID_FILE 2>/dev/null) 2>/dev/null; exit 0' TERM INT

# Check if running as init process
if [ $$ -eq 1 ]; then
    main
else
    main &
    wait
fi
