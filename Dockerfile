# Dockerfile (Updated)
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /opt/nprobe

# Install base dependencies
RUN apt-get update && \
    apt-get install -y \
    software-properties-common wget curl build-essential \
    linux-headers-generic kmod net-tools iproute2 ethtool pciutils \
    python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

# === ADDED: Install Mellanox OFED Drivers ===
# Note: Check the official NVIDIA/Mellanox documentation for the latest repository URLs
RUN wget https://www.mellanox.com/downloads/ofed/RPM-GPG-KEY-Mellanox -O - | apt-key add -
RUN echo "deb https://www.mellanox.com/linux-ofed/ubuntu-22.04/amd64/ /" > /etc/apt/sources.list.d/mellanox.list
# Install the core OFED package which includes kernel modules and tools like ethtool
RUN apt-get update && apt-get install -y mlnx-ofed-all

# Install nProbe + PF_RING (after OFED)
RUN wget https://packages.ntop.org/apt-stable/22.04/all/apt-ntop-stable.deb && \
    apt install -y ./apt-ntop-stable.deb && \
    rm apt-ntop-stable.deb && \
    apt-get update && \
    apt-get install -y pfring-dkms nprobe pfring-drivers-zc-dkms \
    && rm -rf /var/lib/apt/lists/*

# Create directories and user
RUN mkdir -p /opt/nprobe/config /opt/nprobe/logs /opt/nprobe/scripts /var/run /var/lib/nprobe /etc/pf_ring/zc
RUN useradd -r -d /opt/nprobe -s /bin/false nprobe

# Copy application files
COPY app.py cprobe_control.py /opt/nprobe/

# Copy configurations and scripts
COPY config/ /opt/nprobe/config/
COPY scripts/ /opt/nprobe/scripts/

# Set permissions
RUN chmod +x /opt/nprobe/scripts/*.sh
RUN chown -R nprobe:nprobe /opt/nprobe /var/run /var/lib/nprobe

# Install Python requirements
RUN pip3 install flask

# Set environment variables
ENV PATH="/opt/nprobe/scripts:${PATH}"
ENV PYTHONPATH="/opt/nprobe:${PYTHONPATH}"

# Expose API and NetFlow ports
EXPOSE 5000
EXPOSE 2055/udp 9995/udp

USER nprobe

ENTRYPOINT ["/opt/nprobe/scripts/entrypoint.sh"]
