# PepperSpray-MCP

[![CI](https://github.com/hacKarim/pepperspray-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/hacKarim/pepperspray-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white)
![MCP](https://img.shields.io/badge/MCP-Model_Context_Protocol-111)

A Model Context Protocol (MCP) server that puts a penetration-testing toolkit
behind an AI assistant. It exposes reconnaissance, scanning, and vulnerability
analysis tooling as MCP tools, so a client like Claude can drive a security
assessment conversationally while the heavy lifting runs inside a sandboxed
Docker container.

> ### ⚠️ Authorized use only
>
> This project is for **authorized security testing, research, and education**.
> Only run it against systems you own or have **explicit written permission** to
> test. Unauthorized scanning or exploitation is illegal in most jurisdictions.
> You are solely responsible for how you use it. Provided **as-is, with no
> warranty**.

## Architecture

```
MCP client (Claude)
      │  stdio
      ▼
mcp-pepperspray-wrapper.sh ──► tcp_stdio_bridge.py ──► TCP
                                                        │
                                                        ▼
                                      pepperspray_server.py  (Docker)
                                      ├─ tool registry & execution
                                      ├─ recon / scanning modules
                                      └─ vulnerability analysis
```

- `pepperspray_server.py`: the core server that registers and executes the tooling
- `pepperspray_mcp.py`: MCP protocol handlers and tool definitions
- `tcp_stdio_bridge.py`: bridges the MCP client's stdio to the container's TCP socket
- `mcp-pepperspray-wrapper.sh`: thin launcher the MCP client invokes

## Requirements

- Docker + Docker Compose
- `socat` for the stdio to TCP bridge (`brew install socat`)

## Quick start

```bash
git clone <repository> pepperspray-mcp && cd pepperspray-mcp
cp .env.example .env
docker compose up -d --build
```

Register it with Claude Code:

```bash
claude mcp add pepperspray -- bash -c "/absolute/path/to/mcp-pepperspray-wrapper.sh"
claude mcp list        # verify it connected
```

Or add it to any MCP client config manually:

```json
{
  "mcpServers": {
    "pepperspray": {
      "command": "bash",
      "args": ["-c", "/absolute/path/to/mcp-pepperspray-wrapper.sh"],
      "timeout": 300
    }
  }
}
```

## Configuration

Copy `.env.example` to `.env`. Core settings (ports, host, timeouts) work out of
the box. Optional third-party API keys (Shodan, Censys, VirusTotal) unlock
additional enrichment when provided.

## License

[MIT](./LICENSE)
