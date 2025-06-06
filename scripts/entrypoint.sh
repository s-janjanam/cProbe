#!/bin/bash
set -e

# Source environment variables 
source /etc/nprobe/nprobe.env 2>/dev/null || true

# Check if PF_RING module is loaded
if ! lsmod | grep -q "^pf_ring"; then
    echo "Loading PF_RING kernel module..."
    modprobe pf_ring
fi

# Initialize directories
mkdir -p /opt/nprobe/{config,logs}
chown -R nprobe:nprobe /opt/nprobe

# Check for config file
if [ ! -f "/opt/nprobe/config/nprobe-config.json" ]; then
    echo "Creating default configuration..."
    cp /opt/nprobe/config/config.json /opt/nprobe/config/nprobe-config.json
fi

# Check for license
if [ -f "/opt/nprobe/licenses/nprobe.license" ]; then
    cp /opt/nprobe/licenses/nprobe.license /etc/nprobe.license
fi

# Set proper permissions
chown nprobe:nprobe /etc/nprobe.license 2>/dev/null || true
exec /opt/nprobe/start-nprobe.sh
