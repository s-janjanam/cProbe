#!/bin/bash
set -e

# Load environment variables if exists
if [ -f "/opt/nprobe/config/nprobe.env" ]; then
    source /opt/nprobe/config/nprobe.env
fi

# Load required kernel modules if PF_RING is enabled
if [[ "${NPROBE_USE_PFRING:-false}" == "true" ]] && [ -f "/etc/modules-load.d/pf_ring.conf" ]; then
    modprobe pf_ring || echo "Warning: Could not load pf_ring"
    modprobe pf_ring_zc || echo "Warning: Could not load pf_ring_zc"
fi

# Create necessary directories and set permissions
mkdir -p /opt/nprobe/config /opt/nprobe/logs /var/lib/nprobe
chown -R nprobe:nprobe /opt/nprobe /var/lib/nprobe

# Initialize configuration from JSON if provided
python3 -c "
from cprobe_control import NProbeController
from pathlib import Path

try:
    config_file = Path('/opt/nprobe/config/nprobe-config.json')
    if config_file.exists():
        # Only one argument: instance_num
        controller = NProbeController(0)
        controller.write_configuration()
        print('Configuration initialized')
except Exception as e:
    print(f'Error initializing configuration: {e}')
"

# Execute the main nprobe start script
exec /opt/nprobe/scripts/start-nprobe.sh
