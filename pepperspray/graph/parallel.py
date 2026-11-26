"""Parallel fan-out scanning with the LangGraph ``Send`` API.

A discovery step produces a list of sub-targets (subdomains / URLs / hosts);
``fan_out`` emits one ``Send`` per sub-target, so the probe workers run
concurrently. Their outputs merge automatically through the append-reducers on
``findings`` / ``tool_results``. Finally a report is rendered.

    discover → [Send: probe_worker × N] → collect → reporting → END

For authorized security testing only.
"""

from __future__ import annotations

from typing import Any, Callable

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Send

from pepperspray.core.registry import REGISTRY, ToolContext, ToolRegistry, spread_target
from pepperspray.core.state import AssessmentState, new_state
from pepperspray.reporting.report import render_report

DEFAULT_PROBE_TOOL = "httpx_probe"


def default_worker(payload: dict, ctx: ToolContext) -> dict:
    """Probe one sub-target with the default tool and return findings/results."""
    target = payload.get("target", "")
    authorized = bool(payload.get("authorized", False))
    tool = payload.get("probe_tool", DEFAULT_PROBE_TOOL)
    result = REGISTRY.execute(tool, spread_target(target), ctx, authorized=authorized)
    finding = {
        "title": f"probe {target}: {result.status}",
        "severity": "info",
        "source": "parallel-probe",
        "detail": (result.stdout or result.error or "")[:200],
    }
    # Same shape the specialists emit, so the report can read result.status.
    return {"tool_results": [{"tool": tool, "result": result.to_dict()}], "findings": [finding]}


def discover(state: dict) -> dict:
    """Seed sub-targets. Falls back to the single main target when none supplied."""
    subs = state.get("subtargets") or []
    if not subs:
        subs = [state.get("target", "")]
    return {"subtargets": subs}


def fan_out(state: dict) -> list[Send]:
    """Emit one ``Send`` to a probe worker per sub-target (the map step)."""
    subs = state.get("subtargets") or [state.get("target", "")]
    authorized = state.get("authorized", False)
    probe_tool = state.get("probe_tool", DEFAULT_PROBE_TOOL)
    return [
        Send("probe_worker", {"target": sub, "authorized": authorized, "probe_tool": probe_tool})
        for sub in subs
        if sub
    ]


def build_parallel_scan(
    ctx: ToolContext,
    registry: ToolRegistry = REGISTRY,
    worker: Callable[[dict, ToolContext], dict] | None = None,
    checkpointer: Any = None,
):
    """Compile the parallel fan-out scan graph."""
    worker_fn = worker or default_worker

    graph = StateGraph(AssessmentState)
    graph.add_node("discover", discover)
    graph.add_node("probe_worker", lambda payload: worker_fn(payload, ctx))
    graph.add_node("collect", lambda state: {})  # join point; reducers already merged
    graph.add_node("reporting", lambda state: {"report": render_report(state)})

    graph.add_edge(START, "discover")
    graph.add_conditional_edges("discover", fan_out, ["probe_worker"])
    graph.add_edge("probe_worker", "collect")
    graph.add_edge("collect", "reporting")
    graph.add_edge("reporting", END)
    return graph.compile(checkpointer=checkpointer or MemorySaver())


def run_parallel_scan(
    target: str,
    subtargets: list[str] | None = None,
    objective: str = "parallel recon",
    authorized: bool = False,
    ctx: ToolContext | None = None,
    registry: ToolRegistry = REGISTRY,
    worker: Callable[[dict, ToolContext], dict] | None = None,
    thread_id: str = "parallel",
) -> dict:
    if ctx is None:
        from pepperspray.core.cache import ResultCache
        from pepperspray.core.executor import SafeCommandExecutor

        ctx = ToolContext(executor=SafeCommandExecutor(300), cache=ResultCache())
    graph = build_parallel_scan(ctx, registry=registry, worker=worker)
    state = new_state(
        target=target, objective=objective, authorized=authorized, subtargets=subtargets or []
    )
    return graph.invoke(state, config={"configurable": {"thread_id": thread_id}})
