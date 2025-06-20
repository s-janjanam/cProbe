FROM ubuntu:22.04
# Avoid interactive prompts 
ENV DEBIAN_FRONTEND=noninteractive

# Set working directory 
WORKDIR /opt/nprobe

# Install dependencies 
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
    nprobe \
    && rm -rf /var/lib/apt/lists/*

# Create directories and user 
RUN mkdir -p /opt/nprobe/config /opt/nprobe/logs /opt/nprobe/scripts /opt/nprobe/static /var/lib/nprobe /etc/pf_ring/zc
RUN groupadd --force --system nprobe && \
    chown -R nprobe:nprobe /opt/nprobe /var/lib/nprobe /etc/pf_ring/zc

# Copy Python application files 
COPY api.py cprobe_control.py /opt/nprobe/

# Copy static files (UI)
COPY ui.html /opt/nprobe/static/

# Copy configuration and scripts 
COPY scripts/entrypoint.sh /opt/nprobe/scripts/
COPY scripts/start-nprobe.sh /opt/nprobe/scripts/
RUN chmod +x /opt/nprobe/scripts/entrypoint.sh /opt/nprobe/scripts/start-nprobe.sh

# Install Python requirements 
RUN pip3 install --no-cache-dir flask gunicorn

# Set environment variables 
ENV PATH="/opt/nprobe/scripts:${PATH}"
ENV PYTHONPATH="/opt/nprobe:${PYTHONPATH}"

# Expose ports for the API and potential flow collection 
EXPOSE 5001/tcp 
EXPOSE 2055/udp 9995/udp

# Set entrypoint 
ENTRYPOINT ["/opt/nprobe/scripts/entrypoint.sh"]
