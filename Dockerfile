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
    netexec smbmap samba-common-bin smbclient \
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
    go install github.com/jaeles-project/jaeles@latest && \
    go install github.com/hahwul/dalfox/v2@latest || echo "warning: optional go tool failed, continuing"

# Rust-based tools (rustscan, x8, pwninit) — best effort
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal && \
    . "$HOME/.cargo/env" && \
    cargo install rustscan x8 pwninit && \
    ln -sf "$HOME/.cargo/bin/"* /usr/local/bin/ \
    || echo "warning: optional rust tool failed, continuing"

# docker-bench-security + libc-database (git-based tools)
RUN git clone --depth 1 https://github.com/docker/docker-bench-security.git /opt/docker-bench-security && \
    chmod +x /opt/docker-bench-security/docker-bench-security.sh && \
    ln -sf /opt/docker-bench-security/docker-bench-security.sh /usr/local/bin/docker-bench-security \
    || echo "warning: optional tool failed, continuing"
RUN git clone --depth 1 https://github.com/niklasb/libc-database.git /opt/libc-database \
    || echo "warning: optional tool failed, continuing"

# Release-binary tools (kube-bench, terrascan) — best effort
RUN KB=$(curl -s https://api.github.com/repos/aquasecurity/kube-bench/releases/latest | grep -o "https.*linux_amd64.tar.gz" | head -1) && \
    [ -n "$KB" ] && curl -sL "$KB" | tar -xz -C /usr/local/bin kube-bench 2>/dev/null; \
    TS=$(curl -s https://api.github.com/repos/tenable/terrascan/releases/latest | grep -o "https.*Linux_x86_64.tar.gz" | head -1) && \
    [ -n "$TS" ] && curl -sL "$TS" | tar -xz -C /usr/local/bin terrascan 2>/dev/null; \
    echo "release-binary tools best-effort done"

# Ghidra (optional, large) — provides analyzeHeadless for ghidra_analysis
RUN mkdir -p /opt/ghidra && cd /tmp && \
    GHIDRA_URL=$(curl -s https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest | grep -o "https.*public_release.*\.zip" | head -1) && \
    if [ -n "$GHIDRA_URL" ]; then \
        wget -q "$GHIDRA_URL" -O ghidra.zip && unzip -q ghidra.zip -d /opt/ghidra && rm ghidra.zip && \
        ln -sf /opt/ghidra/*/support/analyzeHeadless /usr/local/bin/analyzeHeadless; \
    fi || echo "warning: optional ghidra install failed, continuing"

# Python-based security tools (binary/forensics/cloud)
RUN python3 -m pip install --no-cache-dir --break-system-packages \
    ropgadget one-gadget volatility3 angr pwntools uro \
    checkov prowler scoutsuite kube-hunter autorecon pacu cloudmapper \
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
