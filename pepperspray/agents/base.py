"""Specialist agent factory.

A specialist is a LangGraph node backed by a ReAct agent bound to the tools of
one or more registry families. Registry tools are exposed to the LLM as
LangChain tools; the node runs the agent, harvests tool results into the shared
state, and hands control back to the supervisor.

Authorization is read from the live state at call time, so an unauthorized run
cannot execute active tools.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from langchain_core.messages import HumanMessage
from langchain_core.tools import StructuredTool

from pepperspray.core.errors import AuthorizationError
from pepperspray.core.registry import REGISTRY, ToolContext, ToolRegistry

# Keys a builder might read for the primary target; we set them all to the same
# value so a specialist tool needs only "target" + free-form "extra".
_TARGET_ALIASES = ("target", "url", "domain", "base_url", "host", "ip")


def _make_lc_tool(
    spec, ctx: ToolContext, registry: ToolRegistry, authorized: bool
) -> StructuredTool:
    def _call(target: str = "", extra: str = "") -> str:
        params: dict[str, Any] = {k: target for k in _TARGET_ALIASES}
        if extra:
            params["additional_args"] = extra
        try:
            result = registry.execute(spec.name, params, ctx, authorized=authorized)
        except AuthorizationError as exc:
            return f"authorization required: {exc}"
        return json.dumps(result.to_dict())[:4000]

    return StructuredTool.from_function(
        func=_call,
        name=spec.name,
        description=(spec.description or spec.name)[:900],
    )


def make_specialist(
    name: str,
    families: list[str],
    system_prompt: str,
    ctx: ToolContext,
    registry: ToolRegistry = REGISTRY,
    llm: Any = None,
    agent_factory: Callable | None = None,
) -> Callable[[dict], dict]:
    """Return a LangGraph node function for a specialist agent."""

    def node(state: dict) -> dict:
        authorized = bool(state.get("authorized", False))
        specs = [s for fam in families for s in registry.by_family(fam)]
        lc_tools = [_make_lc_tool(s, ctx, registry, authorized) for s in specs]

        factory = agent_factory or _default_factory
        agent = factory(llm, lc_tools)

        task = (
            f"{system_prompt}\n\nTarget: {state.get('target', '')}\n"
            f"Objective: {state.get('objective', '')}\n"
            f"Authorized: {authorized}. Use your tools, then summarize findings."
        )
        prior = list(state.get("messages", []))
        result = agent.invoke({"messages": prior + [HumanMessage(task)]})
        messages = result.get("messages", [])

        tool_results = _harvest_tool_results(messages)
        return {
            "messages": messages,
            "tool_results": tool_results,
            "completed_steps": [name],
            "next": "supervisor",
        }

    return node


def _default_factory(llm: Any, tools: list):
    from langgraph.prebuilt import create_react_agent

    return create_react_agent(llm, tools)


def _harvest_tool_results(messages: list) -> list[dict]:
    results: list[dict] = []
    for m in messages:
        if getattr(m, "type", "") == "tool":
            content = getattr(m, "content", "")
            try:
                parsed = json.loads(content) if isinstance(content, str) else content
            except (ValueError, TypeError):
                parsed = {"raw": content}
            results.append({"tool": getattr(m, "name", ""), "result": parsed})
    return results
