#!/bin/bash
set -e

# Configuration file path
CONFIG_FILE="/opt/nprobe/config/nprobe-config.json"

# Function to extract configuration values
get_config() {
    jq -r "$1" "$CONFIG_FILE"
}

# Function to build nProbe command line arguments
build_nprobe_args() {
    local args=""
    
    # Interface
    local interface=$(get_config '.nprobe.capture.interface')
    args="$args -i $interface"
    
    # NetFlow version
    local nf_version=$(get_config '.nprobe.flow_export.netflow_version')
    args="$args -V $nf_version"
    
    # Collector configuration
    local collector_ip=$(get_config '.nprobe.flow_export.collector_ip')
    local collector_port=$(get_config '.nprobe.flow_export.collector_port')
    args="$args -n $collector_ip:$collector_port"
    
    # Source IP and port (if specified)
    local source_ip=$(get_config '.nprobe.flow_export.source_ip')
    local source_port=$(get_config '.nprobe.flow_export.source_port')
    if [ "$source_ip" != "0.0.0.0" ] && [ "$source_ip" != "null" ]; then
        if [ "$source_port" != "0" ] && [ "$source_port" != "null" ]; then
            args="$args -S $source_ip:$source_port"
        else
            args="$args -S $source_ip"
        fi
    fi
    
    # Verbose level
    local verbose=$(get_config '.nprobe.general.verbose_level')
    args="$args --verbose $verbose"
    
    # Template configuration
    local use_custom_template=$(get_config '.nprobe.templates.use_custom_template')
    if [ "$use_custom_template" = "true" ]; then
        local template=$(get_config '.nprobe.templates.custom_template')
        if [ "$template" != "null" ] && [ "$template" != "" ]; then
            args="$args -T \"$template\""
        fi
    fi
    
    # Flow timeouts
    local active_timeout=$(get_config '.nprobe.flow_export.active_timeout')
    local inactive_timeout=$(get_config '.nprobe.flow_export.inactive_timeout')
    if [ "$active_timeout" != "null" ]; then
        args="$args -t $active_timeout"
    fi
    if [ "$inactive_timeout" != "null" ]; then
        args="$args -d $inactive_timeout"
    fi
    
    # Template refresh rate
    local template_refresh=$(get_config '.nprobe.flow_export.template_refresh_rate')
    if [ "$template_refresh" != "null" ]; then
        args="$args --template-refresh-rate $template_refresh"
    fi
    
    # Hash size
    local hash_size=$(get_config '.nprobe.flow_processing.hash_size')
    if [ "$hash_size" != "null" ]; then
        args="$args --hash-size $hash_size"
    fi
    
    # Max flows
    local max_flows=$(get_config '.nprobe.flow_processing.max_num_flows')
    if [ "$max_flows" != "null" ]; then
        args="$args --max-num-flows $max_flows"
    fi
    
    # Packet sampling
    local sampling_rate=$(get_config '.nprobe.flow_processing.packet_sampling_rate')
    if [ "$sampling_rate" != "null" ] && [ "$sampling_rate" != "1" ]; then
        args="$args --sampling-rate $sampling_rate"
    fi
    
    # PF_RING ZC configuration
    local pfring_zc=$(get_config '.nprobe.capture.pfring_zc')
    if [ "$pfring_zc" = "true" ]; then
        local cluster_id=$(get_config '.nprobe.capture.cluster_id')
        if [ "$cluster_id" != "null" ]; then
            args="$args --cluster-id $cluster_id"
        fi
        
        local num_threads=$(get_config '.nprobe.capture.num_threads')
        if [ "$num_threads" != "null" ]; then
            args="$args --num-threads $num_threads"
        fi
    fi
    
    # CPU affinity
    local cpu_affinity=$(get_config '.nprobe.performance.cpu_affinity')
    if [ "$cpu_affinity" != "null" ] && [ "$cpu_affinity" != "" ]; then
        args="$args --cpu-affinity $cpu_affinity"
    fi
    
    # Ring buffer size
    local ring_buffer=$(get_config '.nprobe.performance.ring_buffer_size')
    if [ "$ring_buffer" != "null" ]; then
        args="$args --ring-buffer-size $ring_buffer"
    fi
    
    # Logging
    local log_file=$(get_config '.nprobe.logging.log_file')
    if [ "$log_file" != "null" ] && [ "$log_file" != "" ]; then
        args="$args --log-file $log_file"
    fi
    
    # License file
    local license_file=$(get_config '.nprobe.licenses.license_file')
    if [ "$license_file" != "null" ] && [ -f "$license_file" ]; then
        args="$args --license-file $license_file"
    fi
    
    # PID file
    local pid_file=$(get_config '.nprobe.general.pid_file')
    if [ "$pid_file" != "null" ]; then
        args="$args -P $pid_file"
    fi
    
    # Security: drop privileges
    local drop_privileges=$(get_config '.nprobe.security.drop_privileges')
    local user=$(get_config '.nprobe.general.user')
    if [ "$drop_privileges" = "true" ] && [ "$user" != "null" ]; then
        args="$args -u $user"
    fi
    
    # Additional advanced options
    local ignore_vlan=$(get_config '.nprobe.advanced.ignore_vlan')
    if [ "$ignore_vlan" = "true" ]; then
        args="$args --ignore-vlan"
    fi
    
    local ignore_mpls=$(get_config '.nprobe.advanced.ignore_mpls')
    if [ "$ignore_mpls" = "true" ]; then
        args="$args --ignore-mpls"
    fi
    
    echo "$args"
}

# Get daemon mode setting
DAEMON_MODE=$(get_config '.nprobe.general.daemon_mode')

# Build the command arguments
NPROBE_ARGS=$(build_nprobe_args)

# Log the command that will be executed
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Executing nProbe with arguments:"
echo "nprobe $NPROBE_ARGS"

# Execute nProbe
if [ "$DAEMON_MODE" = "true" ]; then
    # Run as daemon
    exec nprobe $NPROBE_ARGS -D
else
    # Run in foreground
    exec nprobe $NPROBE_ARGS
fi
