# nProbe Docker Container with PF_RING ZC
This Docker container packages nProbe with PF_RING Zero Copy (ZC) support for high-performance network flow collection and export.
Directory Structure
nprobe-docker/
├── Dockerfile
├── docker-compose.yml
├── config/
│   └── config.json
├── scripts/
│   ├── start-nprobe.sh
│   ├── healthcheck.sh
│   ├── setup-pfring.sh
│   └── monitor-flows.sh
└── logs/
    └── (log files will be created here)
Prerequisites

Docker and Docker Compose installed
nProbe License from ntop.org
PF_RING ZC License (if using ZC features)
Privileged access for kernel module loading
Network interface available for packet capture

Configuration
1. Update config.json
Edit config/config.json to match your environment:
bash# Essential settings to update:
{
  "nprobe": {
    "license_key": "YOUR_ACTUAL_LICENSE_KEY",
    "interfaces": [
      {
        "name": "eth0",  # Your capture interface
        "pfring_zc_device": "zc:eth0"  # ZC device specification
      }
    ],
    "collectors": [
      {
        "host": "your-collector.example.com",  # Your NetFlow collector
        "port": 2055
      }
    ]
  }
}
2. Set Environment Variables
Create a .env file:
bash# License keys
NPROBE_LICENSE=your_nprobe_license_key_here
PFRING_ZC_LICENSE=your_pfring_zc_license_key_here

# Optional: Custom configuration
COLLECTOR_HOST=collector.example.com
COLLECTOR_PORT=2055
CAPTURE_INTERFACE=eth0
Building and Running
Method 1: Docker Compose (Recommended)
bash# Build and start the container
docker-compose up -d --build

# View logs
docker-compose logs -f nprobe

# Stop the container
docker-compose down
Method 2: Docker Build
bash# Build the image
docker build -t nprobe-pfring .

# Run the container
docker run -d \
  --name nprobe-collector \
  --privileged \
  --network host \
  -v $(pwd)/config:/etc/nprobe:ro \
  -v $(pwd)/logs:/var/log/nprobe \
  -v /dev:/dev \
  -v /proc:/proc \
  -v /sys:/sys \
  -v /lib/modules:/lib/modules:ro \
  -e NPROBE_LICENSE="your_license_here" \
  nprobe-pfring
Monitoring and Troubleshooting
Check Container Status
bash# Container health
docker-compose ps
docker-compose logs nprobe

# Health check
docker exec nprobe-collector /usr/local/bin/healthcheck.sh
Monitor Flow Statistics
bash# Run monitoring script
docker exec nprobe-collector /usr/local/bin/monitor-flows.sh

# Check nProbe web interface
curl http://localhost:8080
Debug Network Issues
bash# Check interfaces
docker exec nprobe-collector ip link show

# Test collector connectivity
docker exec nprobe-collector nc -u -v collector.example.com 2055

# Monitor packets
docker exec nprobe-collector tcpdump -i eth0 -c 10
Performance Tuning
System-Level Optimizations
bash# Set hugepages (on host system)
echo 1024 > /proc/sys/vm/nr_hugepages

# CPU isolation (add to kernel boot parameters)
isolcpus=2,3 nohz_full=2,3 rcu_nocbs=2,3

# IRQ affinity (adjust for your NIC)
echo 2 > /proc/irq/24/smp_affinity
Container Configuration
Update config.json performance settings:
json{
  "nprobe": {
    "performance": {
      "num_threads": 4,
      "cpu_affinity": true,
      "packet_buffer_size": 4096,
      "flow_buffer_size": 2048
    }
  },
  "system": {
    "hugepages_count": 1024,
    "
