#!/bin/bash
set -e

# Load environment variables if they exist
if [ -f "/opt/nprobe/config/nprobe.env" ]; then
    source /opt/nprobe/config/nprobe.env
fi

# Create necessary directories and set permissions for user 'nprobe'
mkdir -p /opt/nprobe/config /opt/nprobe/logs /var/lib/nprobe
chown -R nprobe:nprobe /opt/nprobe /var/lib/nprobe

# Launch the Gunicorn server to run the Flask API.
# This is the main process of the container.
echo "==> Starting nProbe Control API on port 5001..."
exec gunicorn --workers 2 --bind 0.0.0.0:5001 api:app --log-level=info
