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
from pepperspray.core.registry import REGISTRY, ToolContext, ToolRegistry, spread_target


def _make_lc_tool(
    spec, ctx: ToolContext, registry: ToolRegistry, authorized: bool
) -> StructuredTool:
    def _call(target: str = "", extra: str = "") -> str:
        # ``target`` is the primary input: a host, URL, file path, image, etc.
        # It is spread across every primary-input key so the tool's builder
        # receives it regardless of which key it reads.
        params: dict[str, Any] = spread_target(target, extra)
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
        findings = _findings_from_results(tool_results, agent=name, target=state.get("target", ""))
        return {
            "messages": messages,
            "tool_results": tool_results,
            "findings": findings,
            "completed_steps": [name],
            "next": "supervisor",
        }

    return node


def _default_factory(llm: Any, tools: list):
    from langgraph.prebuilt import create_react_agent

    return create_react_agent(llm, tools)


_SEVERITY_HINTS = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "sql injection": "high",
    "xss": "medium",
    "rce": "critical",
    "vulnerable": "high",
    "exposed": "medium",
}


def _infer_severity(text: str) -> str:
    low = (text or "").lower()
    for hint, sev in _SEVERITY_HINTS.items():
        if hint in low:
            return sev
    return "info"


def _findings_from_results(tool_results: list[dict], agent: str, target: str) -> list[dict]:
    """Summarize each tool run as a finding the critic and report can work on."""
    findings: list[dict] = []
    for tr in tool_results:
        tool = tr.get("tool", "tool")
        result = tr.get("result", {})
        status = result.get("status", "?") if isinstance(result, dict) else "?"
        blob = ""
        if isinstance(result, dict):
            blob = str(result.get("stdout") or result.get("error") or "")
        findings.append(
            {
                "title": f"{tool} on {target}" if target else tool,
                "severity": _infer_severity(blob),
                "source": agent,
                "detail": f"status={status}; {blob[:160]}".strip(),
            }
        )
    return findings


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
