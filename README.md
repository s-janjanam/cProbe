# nProbe Flow Exporter Docker Container
This Docker container provides a complete nProbe setup with PF_RING ZC for high-performance packet capture and NetFlow export to external collectors.

## Prerequisites

Docker and Docker Compose installed
Mellanox NIC with OFED drivers installed on the host
Privileged container access for packet capture
Network interface configured for packet capture

## Directory Structure
nprobe-docker/
├── Dockerfile
├── docker-compose.yml
├── config/
│   ├── nprobe-config.json
│   └── license.key (optional)
├── scripts/
│   ├── entrypoint.sh
│   └── start-nprobe.sh
├── logs/
└── licenses/

## Configuration
### 1. Update nProbe Configuration
Edit config/nprobe-config.json:
json{
  "nprobe": {
    "capture": {
      "interface": "enp104s0f0np0",  // Your Mellanox interface
      "cluster_id": 10,
      "num_threads": 4
    },
    "flow_export": {
      "collector_ip": "192.168.1.100",  // Your collector IP
      "collector_port": 2055,
      "netflow_version": 9
    }
  }
}
### 2. License Configuration (Optional)
If you have nProbe licenses:

Place license files in licenses/ directory
Update the license path in nprobe-config.json

### 3. Interface Configuration
Ensure your Mellanox interface is available:

bash# Check available interfaces
ip link show

#Verify Mellanox OFED
ibstat

## Building and Running

### 1. Build the Container
bash# Clone or create the directory structure
mkdir -p nprobe-docker/{config,scripts,logs,licenses}

#Copy all files to their respective directories
#Copy Dockerfile to nprobe-docker/
#Copy nprobe-config.json to nprobe-docker/config/
#Copy entrypoint.sh and start-nprobe.sh to nprobe-docker/scripts/
#Copy docker-compose.yml to nprobe-docker/

#Make scripts executable
chmod +x scripts/*.sh

#Build the container
docker-compose build

### 2. Run the Container
bash# Start the container
docker-compose up -d

#View logs
docker-compose logs -f nprobe

#Check container status
docker-compose ps

### 3. Monitoring
bash# View real-time logs
docker-compose logs -f

#Check nProbe process
docker-compose exec nprobe ps aux | grep nprobe

#Monitor network interface
docker-compose exec nprobe ip -s link show enp104s0f0np0

## Configuration Options
### Key Configuration Parameters

interface: Network interface for packet capture (e.g., enp104s0f0np0)
collector_ip: IP address of the NetFlow collector
collector_port: Port number of the NetFlow collector
netflow_version: NetFlow version (5, 9, or 10/IPFIX)
cluster_id: PF_RING ZC cluster ID for multi-process capture
num_threads: Number of capture threads
active_timeout: Active flow timeout in seconds
inactive_timeout: Inactive flow timeout in seconds

### Performance Tuning

hugepages: Configure hugepages for better performance
cpu_affinity: Pin processes to specific CPU cores
ring_buffer_size: Adjust ring buffer size for high-speed capture
hash_size: Flow hash table size

### Security Options

drop_privileges: Run nProbe as non-root user after initialization
bind_to_device: Bind to specific network device

## Troubleshooting

### Common Issues

Permission Denied: Ensure container runs with --privileged flag
Interface Not Found: Verify interface name in configuration
PF_RING Module: Check if PF_RING kernel module is loaded
Collector Unreachable: Verify network connectivity to collector

### Debugging Commands
bash# Check container logs
docker-compose logs nprobe

#Access container shell
docker-compose exec nprobe bash

#Check network interfaces
docker-compose exec nprobe ip link show

#Test collector connectivity
docker-compose exec nprobe nc -zv <collector_ip> <collector_port>

#Check PF_RING module
docker-compose exec nprobe lsmod | grep pf_ring

### Log Files

Container logs: docker-compose logs
nProbe logs: logs/nprobe.log
System logs: Check host system logs for kernel module issues

## Customization
### Adding Custom Templates
Modify the custom_template field in nprobe-config.json:
json{
  "nprobe": {
    "templates": {
      "custom_template": "%IPV4_SRC_ADDR %IPV4_DST_ADDR %L4_SRC_PORT %L4_DST_PORT %PROTOCOL %IN_BYTES %OUT_BYTES %FIRST_SWITCHED %LAST_SWITCHED",
      "use_custom_template": true
    }
  }
}
### Multiple Collectors
For multiple collectors, modify the flow_export section or run multiple container instances with different configurations.

### Performance Considerations

Use host network mode for best performance
Configure CPU affinity to avoid core conflicts
Tune ring buffer sizes based on traffic volume
Consider using SR-IOV with Mellanox NICs for better isolation
Monitor container resource usage and adjust limits accordingly

### Production Deployment

Security: Run with minimal privileges where possible
Monitoring: Implement health checks and alerting
Backup: Backup configuration files and licenses
Updates: Regularly update nProbe and PF_RING packages
Scaling: Consider multiple instances for high-volume environments
