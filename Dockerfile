# CyberSentinel Deployment Dockerfile
# Multi-stage build for optimal image size

FROM ubuntu:22.04 as builder

ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    wget \
    git \
    ca-certificates \
    gnupg \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

# Install Python 3.12
RUN apt-get update && apt-get install -y software-properties-common && \
    add-apt-repository ppa:deadsnakes/ppa && \
    apt-get update && apt-get install -y \
    python3.12 \
    python3.12-dev \
    python3.12-venv \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js 20 LTS
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# Install Go 1.22+
RUN wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz && \
    rm go1.22.0.linux-amd64.tar.gz

# Install system security tools
RUN apt-get update && apt-get install -y \
    nmap \
    masscan \
    sqlite3 \
    dnsutils \
    whois \
    jq \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python security tools via pip
RUN python3.12 -m pip install --no-cache-dir --upgrade pip && \
    python3.12 -m pip install --no-cache-dir \
    semgrep \
    bandit \
    pip-audit \
    mitmproxy \
    ollama

# Install govulncheck
ENV PATH=$PATH:/usr/local/go/bin
RUN /usr/local/go/bin/go install golang.org/x/vuln/cmd/govulncheck@latest

# Install TruffleHog from releases
RUN wget https://github.com/trufflesecurity/trufflehog/releases/download/v3.63.0/trufflehog_3.63.0_linux_x86_64.tar.gz && \
    tar -xzf trufflehog_3.63.0_linux_x86_64.tar.gz && \
    mv trufflehog /usr/local/bin/ && \
    chmod +x /usr/local/bin/trufflehog && \
    rm trufflehog_3.63.0_linux_x86_64.tar.gz

# Install OWASP ZAP
RUN apt-get update && apt-get install -y \
    default-jdk \
    && rm -rf /var/lib/apt/lists/ && \
    wget https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz && \
    tar -xzf ZAP_2.14.0_Linux.tar.gz -C /opt && \
    rm ZAP_2.14.0_Linux.tar.gz && \
    ln -s /opt/ZAP_2.14.0/zap.sh /usr/local/bin/zaproxy

# Install Nuclei from releases
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v2.9.11/nuclei_2.9.11_linux_amd64.zip && \
    apt-get update && apt-get install -y unzip && \
    unzip nuclei_2.9.11_linux_amd64.zip && \
    mv nuclei /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm nuclei_2.9.11_linux_amd64.zip && \
    rm -rf /var/lib/apt/lists/*

# Install Subfinder from releases
RUN wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip && \
    unzip subfinder_2.6.6_linux_amd64.zip && \
    mv subfinder /usr/local/bin/ && \
    chmod +x /usr/local/bin/subfinder && \
    rm subfinder_2.6.6_linux_amd64.zip

# Install Amass from OWASP releases
RUN wget https://github.com/OWASP/Amass/releases/download/v4.2.1/amass_linux_amd64.zip && \
    unzip amass_linux_amd64.zip && \
    mv amass_linux_amd64/amass /usr/local/bin/ && \
    chmod +x /usr/local/bin/amass && \
    rm -rf amass_linux_amd64*

# Install Wappalyzer globally via npm
RUN npm install -g wappalyzer

# Final runtime stage
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONPATH=/app:$PYTHONPATH
ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    python3.12 \
    python3-pip \
    nodejs \
    default-jdk \
    nmap \
    masscan \
    sqlite3 \
    dnsutils \
    whois \
    jq \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy artifacts from builder
COPY --from=builder /usr/local/bin/trufflehog /usr/local/bin/
COPY --from=builder /usr/local/bin/zaproxy /usr/local/bin/
COPY --from=builder /usr/local/bin/nuclei /usr/local/bin/
COPY --from=builder /usr/local/bin/subfinder /usr/local/bin/
COPY --from=builder /usr/local/bin/amass /usr/local/bin/
COPY --from=builder /usr/local/go /usr/local/go
COPY --from=builder /root/go /root/go
COPY --from=builder /opt/ZAP* /opt/
COPY --from=builder /usr/local/bin/zap.sh /usr/local/bin/zaproxy

# Reinstall Python packages in runtime image
RUN python3.12 -m pip install --no-cache-dir --upgrade pip && \
    python3.12 -m pip install --no-cache-dir \
    semgrep \
    bandit \
    pip-audit \
    mitmproxy \
    ollama

# Reinstall npm packages
RUN npm install -g wappalyzer

# Copy CyberSentinel package
COPY . /app/

# Create required directories
RUN mkdir -p /app/config /app/reports /app/data

# Set entrypoint
ENTRYPOINT ["python3.12", "-m", "cybersentinel"]
