"""Specialists as nested subgraphs.

Each specialist is its own compiled ``StateGraph`` — a plan → act → verify loop —
rather than a single ReAct node. It shares the parent ``AssessmentState``, so it
plugs into the main graph as one node while running its own internal workflow:

    plan   — pick an approach / recommended tools for the target
    act    — run the ReAct agent against the family's tools (shared core)
    verify — locally score the findings this specialist produced, then promote
             them into the shared findings list

This gives a two-tier reflection: a local verify inside each specialist, and the
global critic across all findings afterwards.
"""

from __future__ import annotations

from typing import Any, Callable

from langchain_core.messages import AIMessage
from langgraph.graph import END, START, StateGraph

from pepperspray.agents.base import run_specialist_act
from pepperspray.agents.specialists import SPECIALISTS
from pepperspray.core.registry import REGISTRY, ToolContext, ToolRegistry
from pepperspray.core.state import AssessmentState
from pepperspray.data import tools_for_target


def _plan_node(name: str, families: list[str]) -> Callable[[dict], dict]:
    def plan(state: dict) -> dict:
        target = str(state.get("target", ""))
        target_type = (
            "web_application" if ("web" in families or "http" in target) else "network_host"
        )
        recommended = tools_for_target(target_type)[:5]
        return {
            "plan": [
                f"{name}: {target_type} → prioritize {', '.join(recommended) or 'available tools'}"
            ],
            "messages": [AIMessage(content=f"[{name}] planning assessment of {target}")],
        }

    return plan


def _verify_node(name: str) -> Callable[[dict], dict]:
    def verify(state: dict) -> dict:
        pending = state.get("pending_findings", [])
        scored: list[dict] = []
        for f in pending:
            finding = dict(f)
            status = finding.pop("_status", "?")
            # Local confidence: a successful tool run is more trustworthy than a
            # failed/unavailable one. The global critic refines this later.
            finding["confidence"] = 0.7 if status == "success" else 0.3
            scored.append(finding)
        return {"findings": scored, "pending_findings": []}

    return verify


def make_specialist_subgraph(
    name: str,
    families: list[str],
    system_prompt: str,
    ctx: ToolContext,
    registry: ToolRegistry = REGISTRY,
    llm: Any = None,
    agent_factory: Callable | None = None,
):
    """Compile one specialist as a plan→act→verify subgraph."""

    def act(state: dict) -> dict:
        updates, findings = run_specialist_act(
            name, families, system_prompt, state, ctx, registry, llm, agent_factory
        )
        updates["pending_findings"] = findings
        return updates

    sub = StateGraph(AssessmentState)
    sub.add_node("plan", _plan_node(name, families))
    sub.add_node("act", act)
    sub.add_node("verify", _verify_node(name))
    sub.add_edge(START, "plan")
    sub.add_edge("plan", "act")
    sub.add_edge("act", "verify")
    sub.add_edge("verify", END)
    # No checkpointer here: nested subgraphs inherit the parent's persistence.
    return sub.compile()


def build_specialist_subgraphs(
    ctx: ToolContext,
    llm: Any = None,
    registry: ToolRegistry = REGISTRY,
    agent_factory: Callable | None = None,
) -> dict[str, Any]:
    """Return {name: compiled subgraph} for every tool-backed specialist."""
    return {
        name: make_specialist_subgraph(
            name,
            families,
            prompt,
            ctx=ctx,
            registry=registry,
            llm=llm,
            agent_factory=agent_factory,
        )
        for name, (families, prompt) in SPECIALISTS.items()
    }
