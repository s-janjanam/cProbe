FROM ubuntu:22.04

# Avoid interactive prompts during package installation 
ENV DEBIAN_FRONTEND=noninteractive

# Set working directory
WORKDIR /opt/nprobe

# Install basic dependencies
RUN apt-get update && \
    apt-get install -y \
    software-properties-common \
    wget \
    curl \
    build-essential \
    linux-headers-generic \
    kmod \
    net-tools \
    iproute2 \
    ethtool \
    pciutils \
    jq \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Add ntop repository and install nProbe + PF_RING
RUN wget https://packages.ntop.org/apt-stable/22.04/all/apt-ntop-stable.deb && \
    apt install -y ./apt-ntop-stable.deb && \
    rm apt-ntop-stable.deb && \
    apt-get update && \
    apt-get install -y \
    pfring-dkms \
    nprobe \
    pfring-drivers-zc-dkms \
    && rm -rf /var/lib/apt/lists/*

# Create required directories
RUN mkdir -p /opt/nprobe/config \
             /opt/nprobe/logs \
             /opt/nprobe/scripts \
             /var/lib/nprobe \
             /etc/pf_ring/zc

# Create nprobe user for security
RUN useradd -r -s /bin/false nprobe && \
    chown -R nprobe:nprobe /opt/nprobe /var/lib/nprobe /etc/pf_ring/zc

# Copy Python files
COPY cprobe_control.py /opt/nprobe/
COPY helper_functions.py /opt/nprobe/
COPY consts.py /opt/nprobe/
COPY MyLogging.py /opt/nprobe/

# Copy configuration files
COPY config/nprobe-config.json /opt/nprobe/config/
COPY config/nprobe.env /opt/nprobe/config/

# Copy scripts
COPY scripts/entrypoint.sh /opt/nprobe/scripts/
COPY scripts/start-nprobe.sh /opt/nprobe/scripts/

# Make scripts executable
RUN chmod +x /opt/nprobe/scripts/entrypoint.sh /opt/nprobe/scripts/start-nprobe.sh

# Install Python requirements
RUN pip3 install \
    typing-extensions \
    setuptools \
    wheel

# Set environment variables
ENV PATH="/opt/nprobe/scripts:${PATH}"
ENV PYTHONPATH="/opt/nprobe:${PYTHONPATH}"

# Default ports for NetFlow
EXPOSE 2055/udp 9995/udp

# Set entrypoint
ENTRYPOINT ["/opt/nprobe/scripts/entrypoint.sh"]
