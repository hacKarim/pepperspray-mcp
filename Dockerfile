FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PATH="/root/go/bin:/usr/local/go/bin:$PATH"
ENV GOPATH="/root/go"

# Security toolchain available via apt
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv python3-dev curl wget git vim jq file xxd \
    build-essential gcc g++ make golang-go \
    nmap masscan arp-scan netcat-traditional \
    gobuster nikto dirb dirsearch feroxbuster ffuf wfuzz \
    httpx-toolkit hakrawler arjun paramspider \
    nuclei sqlmap xsser dotdotpwn wafw00f \
    amass subfinder fierce dnsenum enum4linux enum4linux-ng nbtscan \
    hydra john hashcat \
    wpscan zaproxy \
    metasploit-framework responder \
    netexec smbmap samba-common-bin \
    gdb radare2 binwalk binutils checksec ropper \
    steghide libimage-exiftool-perl foremost \
    trivy docker.io \
    wordlists seclists \
    && rm -rf /var/lib/apt/lists/* && apt-get clean

# Go-based tools not in apt
RUN go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/tomnomnom/anew@latest && \
    go install github.com/tomnomnom/qsreplace@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/hahwul/dalfox/v2@latest || echo "warning: optional go tool failed, continuing"

# docker-bench-security
RUN git clone --depth 1 https://github.com/docker/docker-bench-security.git /opt/docker-bench-security && \
    chmod +x /opt/docker-bench-security/docker-bench-security.sh && \
    ln -sf /opt/docker-bench-security/docker-bench-security.sh /usr/local/bin/docker-bench-security \
    || echo "warning: optional tool failed, continuing"

# Python-based security tools (binary/forensics/cloud)
RUN python3 -m pip install --no-cache-dir --break-system-packages \
    ropgadget one-gadget volatility3 angr pwntools uro \
    checkov prowler scoutsuite kube-hunter \
    || echo "warning: optional python tool failed, continuing"

WORKDIR /app

# Install the PepperSpray package and its runtime dependencies
COPY pyproject.toml README.md requirements.txt ./
COPY pepperspray ./pepperspray
RUN python3 -m pip install --no-cache-dir --break-system-packages --ignore-installed .

RUN mkdir -p /app/results

# LLM configuration is provided at runtime (ANTHROPIC_API_KEY, etc.)
ENV PEPPERSPRAY_RESULTS_DIR=/app/results

# Lightweight health check: the registry loads and the CLI runs
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
  CMD pepperspray list-tools >/dev/null 2>&1 || exit 1

# Default: the MCP server over stdio (attach with `docker run -i`).
# For the CLI instead: `docker run --rm pepperspray pepperspray run --target ... --authorized`
CMD ["python3", "-m", "pepperspray.interfaces.mcp_server"]
