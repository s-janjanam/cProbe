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
    && rm -rf /var/lib/apt/lists/*

# Add universe repository
RUN add-apt-repository universe

# Download and install ntop repository
RUN wget https://packages.ntop.org/apt-stable/22.04/all/apt-ntop-stable.deb && \
    apt install -y ./apt-ntop-stable.deb && \
    rm apt-ntop-stable.deb

# Clean and update package lists
RUN apt-get clean all && \
    apt-get update

# Install PF_RING and nProbe packages
RUN apt-get install -y \
    pfring-dkms \
    nprobe \
    pfring-drivers-zc-dkms \
    && rm -rf /var/lib/apt/lists/*

# Create directories for configuration and logs
RUN mkdir -p /opt/nprobe/config \
             /opt/nprobe/logs \
             /var/lib/nprobe

# Create nprobe user for security
RUN useradd -r -s /bin/false nprobe && \
    chown -R nprobe:nprobe /opt/nprobe /var/lib/nprobe

# Copy configuration files
COPY config/nprobe-config.json /opt/nprobe/config/
COPY scripts/entrypoint.sh /opt/nprobe/
COPY scripts/start-nprobe.sh /opt/nprobe/

# Make scripts executable
RUN chmod +x /opt/nprobe/entrypoint.sh /opt/nprobe/start-nprobe.sh

# Expose common NetFlow ports (configurable via config)
EXPOSE 2055/udp 9995/udp

# Set entrypoint
ENTRYPOINT ["/opt/nprobe/entrypoint.sh"]
