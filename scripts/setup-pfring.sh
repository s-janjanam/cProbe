#!/bin/bash
# File: scripts/setup-pfring.sh
# Setup script for PF_RING ZC environment

set -e

CONFIG_FILE="/etc/nprobe/config.json"

echo "Setting up PF_RING ZC environment..."

# Load configuration
ZC_DEVICE=$(python3 -c "import json; print(json.load(open('$CONFIG_FILE'))['nprobe']['capture']['pfring_zc_device'])")
CLUSTER_ID=$(python3 -c "import json; print(json.load(open('$CONFIG_FILE'))['pfring']['cluster_settings']['cluster_id'])")
HUGEPAGES=$(python3 -c "import json; print(json.load(open('$CONFIG_FILE'))['system']['hugepages_count'])")

# Setup hugepages
if [ "$HUGEPAGES" -gt 0 ]; then
    echo "Setting up $HUGEPAGES hugepages..."
    echo $HUGEPAGES > /proc/sys/vm/nr_hugepages
    
    # Mount hugepages filesystem if not already mounted
    if ! mountpoint -q /mnt/huge; then
        mkdir -p /mnt/huge
        mount -t hugetlbfs nodev /mnt/huge
    fi
fi

# Load PF_RING module with ZC support
echo "Loading PF_RING kernel module..."
modprobe pf_ring enable_tx_capture=1 min_num_slots=32768

# Setup interface for ZC mode
INTERFACE=$(echo $ZC_DEVICE | sed 's/zc://')
if [ -n "$INTERFACE" ] && [ "$INTERFACE" != "$ZC_DEVICE" ]; then
    echo "Configuring interface $INTERFACE for ZC mode..."
    
    # Disable hardware features that might interfere
    ethtool -K $INTERFACE gro off gso off tso off lro off rx off tx off
    
    # Set interface up
    ip link set $INTERFACE up
    
    # Set ring buffer sizes
    ethtool -G $INTERFACE rx 4096 tx 4096 2>/dev/null || echo "Could not set ring buffer sizes"
fi

echo "PF_RING ZC setup completed"
