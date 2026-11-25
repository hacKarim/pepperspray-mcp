# Legacy PepperSpray (v1)

These are the original v1 files, kept for reference during the transition to the
v2 LangGraph multi-agent framework (see the repository root). They are **no
longer used** by the new system and will be removed in a future release.

- `pepperspray_server.py` — the old Flask HTTP API that shelled out to the tools
- `pepperspray_mcp.py` — the old thin FastMCP HTTP client
- `tcp_stdio_bridge.py`, `mcp-pepperspray-wrapper.sh` — the old stdio↔TCP bridge
- `requirements-docker.txt` — the old dependency pin set

The v2 system supersedes all of this: a declarative tool registry, a LangGraph
supervisor/specialist agent graph, a Typer CLI, and a FastMCP server.
