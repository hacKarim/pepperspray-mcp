#!/bin/bash
# PepperSpray MCP Wrapper for Claude Code
# Connects to dockerized MCP server via TCP

# Configuration
DOCKER_HOST="localhost"
MCP_PORT="5001"
TIMEOUT=5

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed${NC}" >&2
    echo "Install Docker from: https://www.docker.com/products/docker-desktop" >&2
    exit 1
fi

# Check if pepperspray-mcp container is running
if ! docker ps 2>/dev/null | grep -q pepperspray-mcp; then
    echo -e "${RED}Error: PepperSpray MCP container is not running${NC}" >&2
    echo -e "${YELLOW}Start containers with:${NC}" >&2
    echo "  cd /path/to/pepperspray-mcp" >&2
    echo "  docker-compose up -d" >&2
    exit 1
fi

# Check if socat is available
if ! command -v socat &> /dev/null; then
    echo -e "${RED}Error: socat is required but not installed${NC}" >&2
    echo -e "${YELLOW}Install socat with:${NC} brew install socat" >&2
    exit 1
fi

# Connect to MCP bridge via socat
# socat - TCP:localhost:5001
# This creates a bidirectional bridge between stdin/stdout and the TCP socket
exec socat - TCP:${DOCKER_HOST}:${MCP_PORT}
