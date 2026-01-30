FROM kalilinux/kali-rolling:latest

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PATH="/app:/root/go/bin:/usr/local/go/bin:$PATH"
ENV GOPATH="/root/go"

# Update and install security tools available via apt
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Base utilities
    python3 python3-pip python3-venv python3-dev socat curl wget git vim jq file xxd \
    # Build tools (needed for pip packages like psutil)
    build-essential gcc g++ make \
    # Go runtime for installing Go-based tools
    golang-go \
    # Network Scanning
    nmap masscan arp-scan netcat-traditional \
    # Web Scanning & Enumeration
    gobuster nikto dirb dirsearch feroxbuster ffuf wfuzz \
    # Web Crawling (apt-available)
    httpx-toolkit hakrawler arjun paramspider \
    # Vulnerability Scanning
    nuclei sqlmap xsser dotdotpwn wafw00f \
    # Subdomain & DNS
    amass subfinder fierce dnsenum enum4linux enum4linux-ng nbtscan \
    # Password Cracking
    hydra john hashcat \
    # Web App Testing
    wpscan zaproxy \
    # Exploitation
    metasploit-framework responder \
    # Network/SMB
    netexec smbmap samba-common-bin crackmapexec \
    # Binary Analysis
    gdb radare2 binwalk binutils checksec ropper \
    # Steganography
    steghide libimage-exiftool-perl foremost \
    # Cloud Security
    trivy docker.io \
    # Wordlists
    wordlists seclists \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Install Go-based tools not available in apt repos
RUN go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/hahwul/dalfox/v2@latest || true

# Install docker-bench-security
RUN git clone --depth 1 https://github.com/docker/docker-bench-security.git /opt/docker-bench-security && \
    chmod +x /opt/docker-bench-security/docker-bench-security.sh && \
    ln -sf /opt/docker-bench-security/docker-bench-security.sh /usr/local/bin/docker-bench-security || true

# Install Ghidra (download latest release)
RUN mkdir -p /opt/ghidra && \
    cd /tmp && \
    GHIDRA_URL=$(curl -s https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest | grep -o "https.*public_release.*\.zip" | head -1) && \
    if [ -n "$GHIDRA_URL" ]; then \
        wget -q "$GHIDRA_URL" -O ghidra.zip && \
        unzip -q ghidra.zip -d /opt/ghidra && \
        rm ghidra.zip && \
        ln -sf /opt/ghidra/*/ghidraRun /usr/local/bin/ghidra; \
    fi || true

# Install Clair (latest release as binary)
RUN cd /tmp && \
    CLAIR_URL=$(curl -s https://api.github.com/repos/quay/clair/releases/latest | grep -o "https.*linux-amd64.*" | grep -v ".asc" | head -1) && \
    if [ -n "$CLAIR_URL" ]; then \
        wget -q "$CLAIR_URL" -O clair && \
        chmod +x clair && \
        mv clair /usr/local/bin/; \
    fi || true

# Install Falco (runtime security monitoring) - skip due to large binary
# Falco can be installed separately if needed

# Install kubectl (for Kubernetes tools)
RUN curl -s https://raw.githubusercontent.com/kubernetes/kubernetes/master/hack/get-kube-binaries.sh 2>/dev/null | bash 2>/dev/null || \
    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && \
    chmod +x kubectl && \
    mv kubectl /usr/local/bin/ || true

# Python-based tools via pip
RUN python3 -m pip install --no-cache-dir --break-system-packages \
    ropgadget \
    one-gadget \
    volatility3 \
    angr \
    pwntools || true

# Create app directory
WORKDIR /app

# Copy Python requirements and install dependencies
COPY requirements-docker.txt .
RUN python3 -m pip install --no-cache-dir --break-system-packages --ignore-installed -r requirements-docker.txt

# Copy application files
COPY pepperspray_server.py .
COPY pepperspray_mcp.py .
COPY tcp_stdio_bridge.py .

# Make scripts executable
RUN chmod +x tcp_stdio_bridge.py pepperspray_mcp.py pepperspray_server.py

# Create directories for persistent data
RUN mkdir -p /app/results /app/cache /app/logs

# Expose ports
EXPOSE 8888 5000

# Health check
# Use lightweight /ping endpoint instead of /health (which scans all tools)
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 \
  CMD curl -f http://localhost:8888/ping || exit 1

# Default command
CMD ["python3", "pepperspray_server.py"]
