#!/bin/bash
set -e

CONFIG_FILE="/opt/nprobe/config/nprobe-config.json"

# Function to configure RSS on the interface
configure_rss() {
    echo "==> Attempting to configure RSS..."

    if [ ! -f "$CONFIG_FILE" ]; then
        echo "INFO: Configuration file not found at $CONFIG_FILE. Skipping RSS setup."
        return
    fi

    # Extract interface name. Assumes the first interface in the list is the target.
    IFACE=$(jq -r '.capture.interfaces[0].name' "$CONFIG_FILE")
    if [ -z "$IFACE" ] || [ "$IFACE" == "null" ]; then
        echo "WARNING: No capture interface found in config. Skipping RSS setup."
        return
    fi

    # Check if interface exists
    if ! ip link show "$IFACE" > /dev/null 2>&1; then
        echo "WARNING: Interface '$IFACE' not found. Skipping RSS setup."
        return
    fi

    # Extract RSS queue count
    RSS_QUEUES=$(jq -r '.capture.interfaces[0].rss_queues' "$CONFIG_FILE")

    # If rss_queues is "auto", determine core count
    if [ "$RSS_QUEUES" == "auto" ]; then
        # nproc is a reliable way to get available CPU cores
        RSS_QUEUES=$(nproc)
        echo "INFO: 'rss_queues' is set to 'auto'. Using $RSS_QUEUES queues (based on nproc)."
    fi

    echo "INFO: Configuring interface '$IFACE' with $RSS_QUEUES RSS queues."

    # Get current max combined queues for the interface
    MAX_QUEUES=$(ethtool -l "$IFACE" | grep 'Combined:' | awk 'NR==1{print $2}')
    if [ -z "$MAX_QUEUES" ]; then
        echo "WARNING: Could not determine max queues for '$IFACE'. Cannot configure RSS."
        return
    fi
    echo "INFO: Max supported combined queues for '$IFACE' is $MAX_QUEUES."

    if [ "$RSS_QUEUES" -gt "$MAX_QUEUES" ]; then
        echo "WARNING: Requested RSS queues ($RSS_QUEUES) exceeds max supported ($MAX_QUEUES). Using max value."
        RSS_QUEUES=$MAX_QUEUES
    fi

    # Set the number of queues
    echo "INFO: Bringing interface $IFACE down for configuration..."
    ifconfig "$IFACE" down
    echo "INFO: Setting combined queues to $RSS_QUEUES..."
    ethtool -L "$IFACE" combined "$RSS_QUEUES"
    echo "INFO: Bringing interface $IFACE up..."
    ifconfig "$IFACE" up

    # It is good practice to disable offloading features that can interfere with packet capture
    echo "INFO: Disabling generic-receive-offload and large-receive-offload..."
    ethtool -K "$IFACE" gro off
    ethtool -K "$IFACE" lro off

    echo "==> RSS configuration for '$IFACE' complete."
}

# --- Main Script Execution ---

# Run the RSS configuration function
configure_rss

# Launch the Gunicorn server to run the Flask API.
# This MUST be the last command, using 'exec' to make it the main process.
echo "==> Starting nProbe Control API on port 5001..."
exec gunicorn --workers 2 --bind 0.0.0.0:5001 api:app --log-level=info
