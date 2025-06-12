#!/bin/bash
set -e

# (Your helper functions like wait_for_interface, apply_zc_licenses, etc. should be kept here)
wait_for_interface() {
    local interface=$1; local max_attempts=30; local attempt=1
    while [ $attempt -le $max_attempts ]; do
        if ip link show "$interface" &>/dev/null; then echo "Interface $interface is ready"; return 0; fi
        echo "Waiting for interface $interface (attempt $attempt/$max_attempts)..."; sleep 2; attempt=$((attempt + 1))
    done
    echo "Error: Interface $interface not available after $max_attempts attempts"; return 1
}
apply_zc_licenses() {
    local zc_dir="/opt/nprobe/config/zc_licenses"
    if [ -d "$zc_dir" ]; then for license in "$zc_dir"/*; do if [ -f "$license" ]; then cp "$license" "/etc/pf_ring/zc/"; fi; done; fi
}
check_nprobe_license() {
    if [ -f "/opt/nprobe/config/nprobe.license" ]; then cp /opt/nprobe/config/nprobe.license /etc/nprobe.license; fi
}
init_pf_ring() {
    local interfaces=(${NPROBE_INTERFACES//,/ }); for interface in "${interfaces[@]}"; do wait_for_interface "$interface"; done
    if [ -x "$(command -v pf_ringcfg)" ]; then
        echo "Configuring PF_RING..."; if [ ! -z "$NPROBE_RSS_QUEUES" ]; then pf_ringcfg --configure-driver "$NPROBE_DRIVER" --rss-queues "$NPROBE_RSS_QUEUES"; fi
    fi
}

main() {
    # Perform initial setup
    if [ "$NPROBE_USE_PFRING" = "true" ]; then init_pf_ring; fi
    check_nprobe_license
    apply_zc_licenses

    # Decide how to run nprobe based on arguments
    if [[ "$1" == "--config-file" ]]; then
        # API Call: Start nprobe as a daemon with a specific config
        shift # remove --config-file from args
        CONFIG_ARG="$1"
        shift # remove the config file path from args
        echo "==> API Call: Starting nProbe in daemon mode with ${CONFIG_ARG}"
        exec nprobe --daemon --config-file "${CONFIG_ARG}" "$@"
    elif [ $# -gt 0 ]; then
        # Passthrough Mode: Run nprobe in the foreground with provided args (for debugging)
        echo "==> Passthrough: Starting nProbe in foreground."
        exec nprobe "$@"
    else
        echo "==> Fallback: No arguments provided. This script should be called by the entrypoint."
        exit 1
    fi
}

# Execute main function with all script arguments
main "$@"

# Execute main
main
