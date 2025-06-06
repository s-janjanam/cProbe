#!/bin/bash
set -e

# Source environment variables
source /opt/nprobe/config/nprobe.env 2>/dev/null || true

# Function to wait for interfaces to be ready
wait_for_interface() {
    local interface=$1
    local max_attempts=30
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        if ip link show "$interface" &>/dev/null; then
            echo "Interface $interface is ready"
            return 0
        fi
        echo "Waiting for interface $interface (attempt $attempt/$max_attempts)..."
        sleep 2
        attempt=$((attempt + 1))
    done

    echo "Error: Interface $interface not available after $max_attempts attempts"
    return 1
}

# Check and apply any ZC licenses
apply_zc_licenses() {
    local zc_dir="/opt/nprobe/config/zc_licenses"
    if [ -d "$zc_dir" ]; then
        for license in "$zc_dir"/*; do
            if [ -f "$license" ]; then
                cp "$license" "/etc/pf_ring/zc/"
            fi
        done
    fi
}

# Verify nProbe license
check_nprobe_license() {
    if [ -f "/opt/nprobe/config/nprobe.license" ]; then
        cp /opt/nprobe/config/nprobe.license /etc/nprobe.license
    fi
}

# Initialize PF_RING
init_pf_ring() {
    local interfaces=(${NPROBE_INTERFACES//,/ })
    for interface in "${interfaces[@]}"; do
        wait_for_interface "$interface"
    done
    
    if [ -x "$(command -v pf_ringcfg)" ]; then
        echo "Configuring PF_RING..."
        if [ ! -z "$NPROBE_RSS_QUEUES" ]; then
            pf_ringcfg --configure-driver "$NPROBE_DRIVER" --rss-queues "$NPROBE_RSS_QUEUES"
        fi
    fi
}

# Main startup sequence
main() {
    # Initialize PF_RING if needed
    if [ "$NPROBE_USE_PFRING" = "true" ]; then
        init_pf_ring
    fi

    # Apply licenses
    check_nprobe_license
    apply_zc_licenses

    # Check if we're using Python controller or direct nProbe
    if [ -f "/opt/nprobe/config/nprobe-0.conf" ]; then
        echo "Starting nProbe with configuration files..."
        NUM_INSTANCES=${NPROBE_INSTANCES:-1}
        for i in $(seq 0 $((NUM_INSTANCES-1))); do
            nprobe --config-file "/opt/nprobe/config/nprobe-$i.conf" &
        done
        wait
    else
        echo "Starting nProbe with default configuration..."
        nprobe -i "${NPROBE_INTERFACE:-any}" \
            -n "${NPROBE_COLLECTOR:-127.0.0.1:2055}" \
            -T "${NPROBE_TEMPLATE:-%IPV4_SRC_ADDR %IPV4_DST_ADDR}" \
            -v "${NPROBE_VERBOSE_LEVEL:-1}" \
            ${NPROBE_EXTRA_OPTS}
    fi
}

# Execute main
main
