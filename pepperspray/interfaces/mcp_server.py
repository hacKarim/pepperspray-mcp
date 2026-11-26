"""MCP server exposing the assessment graph and every individual tool.

High-level tools (run_assessment, run_chain, list_tools) let an MCP client drive
the whole multi-agent graph; the per-tool wrappers keep the granular toolbelt
available. Transport is stdio. Authorized testing only.
"""

from __future__ import annotations

from typing import Any, Callable, Iterator

from pepperspray.core.registry import REGISTRY, ToolContext, spread_target
from pepperspray.tools import load_all

# High-level entrypoint names (for counting / introspection).
HIGH_LEVEL = ["run_assessment", "run_chain", "list_tools"]


def _default_ctx() -> ToolContext:
    from pepperspray.config import get_settings
    from pepperspray.core.cache import ResultCache
    from pepperspray.core.executor import SafeCommandExecutor

    s = get_settings()
    return ToolContext(
        executor=SafeCommandExecutor(s.command_timeout),
        cache=ResultCache(s.cache_size, s.cache_ttl),
        settings=s,
    )


def _make_tool_wrapper(name: str, ctx: ToolContext) -> Callable:
    def wrapper(
        target: str = "",
        extra: str = "",
        authorized: bool = False,
        allow_exploitation: bool = False,
    ) -> dict:
        """Invoke a PepperSpray tool. Set authorized=True only for targets you may test;
        exploitation-class tools also need allow_exploitation=True."""
        params: dict[str, Any] = spread_target(target, extra)
        from pepperspray.core.errors import AuthorizationError

        try:
            return REGISTRY.execute(
                name, params, ctx, authorized=authorized, allow_exploitation=allow_exploitation
            ).to_dict()
        except AuthorizationError as exc:
            return {"status": "failed", "error": f"authorization required: {exc}"}

    wrapper.__name__ = name
    return wrapper


def iter_mcp_tools(ctx: ToolContext) -> Iterator[tuple[str, str, Callable]]:
    """Yield (name, description, callable) for every MCP tool."""

    def run_assessment_tool(
        target: str, objective: str = "comprehensive", authorized: bool = False
    ) -> dict:
        """Run the full multi-agent assessment graph against a target."""
        from pepperspray.graph.build import run_assessment
        from pepperspray.llm.provider import get_llm

        final = run_assessment(
            target=target, objective=objective, authorized=authorized, ctx=ctx, llm=get_llm()
        )
        return {
            "report": final.get("report"),
            "findings": final.get("findings", []),
            "completed_steps": final.get("completed_steps", []),
        }

    def run_chain_tool(
        name: str, target: str, authorized: bool = False, allow_exploitation: bool = False
    ) -> dict:
        """Run a named fixed workflow (chain) against a target."""
        from pepperspray.graph.chains import run_chain
        from pepperspray.llm.provider import get_llm

        final = run_chain(
            name,
            target=target,
            authorized=authorized,
            ctx=ctx,
            llm=get_llm(),
            allow_exploitation=allow_exploitation,
        )
        return {"report": final.get("report"), "findings": final.get("findings", [])}

    def list_tools_tool(family: str = "") -> dict:
        """List available tools, optionally filtered by family."""
        specs = REGISTRY.by_family(family) if family else REGISTRY.all()
        return {
            "tools": [
                {
                    "name": s.name,
                    "family": s.family,
                    "active": s.active,
                    "description": s.description,
                }
                for s in specs
            ]
        }

    yield "run_assessment", run_assessment_tool.__doc__, run_assessment_tool
    yield "run_chain", run_chain_tool.__doc__, run_chain_tool
    yield "list_tools", list_tools_tool.__doc__, list_tools_tool

    for spec in REGISTRY.all():
        yield spec.name, (spec.description or spec.name), _make_tool_wrapper(spec.name, ctx)


def build_mcp(ctx: ToolContext | None = None):
    """Construct the FastMCP server with all tools registered."""
    from fastmcp import FastMCP
    from fastmcp.tools import Tool

    load_all()
    ctx = ctx or _default_ctx()
    server = FastMCP("pepperspray")
    for name, description, fn in iter_mcp_tools(ctx):
        server.add_tool(Tool.from_function(fn, name=name, description=(description or name)[:900]))
    return server


def main() -> None:
    build_mcp().run()


if __name__ == "__main__":
    main()
