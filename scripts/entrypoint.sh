#!/bin/bash
set -e

# Load environment variables if exists
if [ -f "/opt/nprobe/config/nprobe.env" ]; then
    source /opt/nprobe/config/nprobe.env
fi

# Load required kernel modules
if [ -f "/etc/modules-load.d/pf_ring.conf" ]; then
    modprobe pf_ring
    modprobe pf_ring_zc
fi

# Create necessary directories
mkdir -p /opt/nprobe/config 
mkdir -p /opt/nprobe/logs
mkdir -p /var/lib/nprobe

# Set permissions
chown -R nprobe:nprobe /opt/nprobe /var/lib/nprobe

# Initialize configuration from JSON if provided
python3 -c "
from cprobe_control import cProbeControl
from json import load
from pathlib import Path

try:
    config_file = Path('/opt/nprobe/config/nprobe-config.json')
    if config_file.exists():
        controller = cProbeControl(None, None)  # DB and logger will be None in container
        controller.write_configuration()
        print('Configuration initialized')
except Exception as e:
    print(f'Error initializing configuration: {e}')
"

# Execute the main nprobe start script
exec /opt/nprobe/scripts/start-nprobe.sh
