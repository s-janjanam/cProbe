FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PFRING_VERSION=8.2.0
ENV NPROBE_VERSION=10.2

# Install system dependencies
RUN apt-get update && apt-get install -y \
    wget \
    curl \
    build-essential \
    libtool \
    autotools-dev \
    automake \
    pkg-config \
    libnuma-dev \
    libpcap-dev \
    ethtool \
    net-tools \
    tcpdump \
    flex \
    bison \
    libssl-dev \
    python3 \
    python3-pip \
    git \
    vim \
    dkms \
    linux-headers-generic \
    kmod \
    && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /opt/ntopng /opt/pfring /etc/nprobe /var/log/nprobe

# Download and install PF_RING
WORKDIR /opt/pfring
RUN wget https://github.com/ntop/PF_RING/archive/refs/tags/${PFRING_VERSION}.tar.gz \
    && tar -xzf ${PFRING_VERSION}.tar.gz \
    && cd PF_RING-${PFRING_VERSION}

# Build PF_RING userland libraries
WORKDIR /opt/pfring/PF_RING-${PFRING_VERSION}/userland/lib
RUN ./configure && make && make install

# Build PF_RING kernel module (for systems where it's needed)
WORKDIR /opt/pfring/PF_RING-${PFRING_VERSION}/kernel
RUN make && make install

# Build libpcap with PF_RING support
WORKDIR /opt/pfring/PF_RING-${PFRING_VERSION}/userland/libpcap
RUN ./configure && make && make install

# Build tcpdump with PF_RING support
WORKDIR /opt/pfring/PF_RING-${PFRING_VERSION}/userland/tcpdump
RUN ./configure && make && make install

# Update library paths
RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/ntop.conf
RUN ldconfig

# Download and install nProbe (this would need actual ntop packages or source)
# Note: You'll need to replace this with actual nProbe installation
# This is a placeholder as nProbe requires licensing from ntop
WORKDIR /opt/ntopng
RUN wget https://packages.ntop.org/apt-stable/22.04/all/apt-ntop-stable.deb \
    && dpkg -i apt-ntop-stable.deb || true \
    && apt-get update \
    && apt-get install -y nprobe || echo "nProbe package not available - install manually"

# Alternative: If you have nProbe tarball/binary, copy it here
# COPY nprobe-linux.tar.gz /opt/ntopng/
# RUN tar -xzf nprobe-linux.tar.gz

# Copy configuration and scripts
COPY config/ /etc/nprobe/
COPY scripts/ /usr/local/bin/
RUN chmod +x /usr/local/bin/*.sh

# Create non-root user for security
RUN useradd -r -s /bin/false nprobe \
    && chown -R nprobe:nprobe /var/log/nprobe

# Expose ports (adjust based on your configuration)
EXPOSE 2055/udp 9995/tcp 8080/tcp

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /usr/local/bin/healthcheck.sh

# Set working directory
WORKDIR /etc/nprobe

# Default command
CMD ["/usr/local/bin/start-nprobe.sh"]
