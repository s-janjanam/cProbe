#!/bin/bash
set -e

echo "--- cProbe Container Entrypoint v2.0 ---"

# 1. Ensure directories exist and have correct permissions
# /var/run is needed for PID files
mkdir -p /opt/nprobe/config /opt/nprobe/logs /var/run /var/lib/nprobe
chown -R nprobe:nprobe /opt/nprobe /var/run /var/lib/nprobe

# 2. Perform one-time system tuning via the controller
# This must be done as root before dropping privileges, but here we run as nprobe
# So the container must be started with --privileged for these to work
echo "Applying system tuning from config.json..."
python3 -c "from cprobe_control import NProbeController; NProbeController().apply_system_tuning()"

# 3. Start the Flask API in the background. It will manage nprobe.
echo "Starting the cProbe control API on port 5000..."
# Using exec as the last command is good, but we need to background the API
# and then perform the initial start.
python3 /opt/nprobe/app.py &
API_PID=$!
# Give the API a moment to start up
sleep 5 

# 4. Trigger the initial startup of the nprobe pool
# The controller will read the default num_threads from config.json
echo "Triggering initial startup of the nprobe instance pool..."
python3 -c "
from cprobe_control import NProbeController
try:
    controller = NProbeController()
    default_queues = controller.config.get('nprobe', {}).get('capture', {}).get('num_threads', 1)
    controller.reconfigure_queues(default_queues)
except Exception as e:
    print(f'FATAL: Error during initial nprobe startup: {e}')
"

echo "--- Startup sequence complete. API is running. ---"
# Wait for the API process to exit, which keeps the container alive
wait $API_PID
