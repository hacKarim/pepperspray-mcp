"""Named chain subgraphs: deterministic, fixed-order workflows that do not need
LLM routing. Each runs one or more specialists in sequence then reports."""

from __future__ import annotations

from typing import Any, Callable

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from pepperspray.agents.specialists import build_specialists
from pepperspray.core.registry import REGISTRY, ToolContext, ToolRegistry
from pepperspray.core.state import AssessmentState, new_state
from pepperspray.reporting.report import render_report

# name -> ordered specialist sequence
CHAINS: dict[str, list[str]] = {
    "recon_chain": ["recon"],
    "bugbounty_recon": ["recon", "web"],
    "comprehensive_assessment": ["recon", "web", "cve"],
    # Named bug-bounty workflows (callable directly; the agents do the work).
    "bugbounty_osint": ["recon"],
    "bugbounty_file_upload": ["web"],
    "bugbounty_business_logic": ["web"],
    "bugbounty_auth_bypass": ["web", "exploitation"],
}


def build_chain(
    name: str,
    ctx: ToolContext,
    llm: Any = None,
    registry: ToolRegistry = REGISTRY,
    agent_factory: Callable | None = None,
    checkpointer: Any = None,
):
    if name not in CHAINS:
        raise KeyError(f"unknown chain: {name}. Available: {sorted(CHAINS)}")
    sequence = CHAINS[name]
    specialists = build_specialists(ctx, llm=llm, registry=registry, agent_factory=agent_factory)

    graph = StateGraph(AssessmentState)
    for step in sequence:
        graph.add_node(step, specialists[step])
    graph.add_node("reporting", lambda state: {"report": render_report(state)})

    graph.add_edge(START, sequence[0])
    for a, b in zip(sequence, sequence[1:]):
        graph.add_edge(a, b)
    graph.add_edge(sequence[-1], "reporting")
    graph.add_edge("reporting", END)
    return graph.compile(checkpointer=checkpointer or MemorySaver())


def run_chain(
    name: str,
    target: str,
    objective: str = "comprehensive",
    authorized: bool = False,
    ctx: ToolContext | None = None,
    llm: Any = None,
    registry: ToolRegistry = REGISTRY,
    agent_factory: Callable | None = None,
    thread_id: str = "chain",
    allow_exploitation: bool = False,
) -> dict:
    """Run a fixed workflow. Chains have no HITL gate, so exploitation-class
    tools stay refused unless ``allow_exploitation`` is passed explicitly."""
    if ctx is None:
        from pepperspray.core.cache import ResultCache
        from pepperspray.core.executor import SafeCommandExecutor

        ctx = ToolContext(executor=SafeCommandExecutor(300), cache=ResultCache())
    graph = build_chain(name, ctx, llm=llm, registry=registry, agent_factory=agent_factory)
    state = new_state(
        target=target,
        objective=objective,
        authorized=authorized,
        exploitation_approved=allow_exploitation,
    )
    return graph.invoke(state, config={"configurable": {"thread_id": thread_id}})
