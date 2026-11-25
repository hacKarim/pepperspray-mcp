"""Assemble the supervisor/specialist assessment graph.

START → supervisor → (conditional) → specialist → supervisor → … → reporting → END

The supervisor routes; each specialist returns control to the supervisor; when
the supervisor decides FINISH (or the step budget runs out) the graph renders a
report and ends. Exploitation can be gated behind a human-in-the-loop interrupt.
"""

from __future__ import annotations

from typing import Any, Callable

from langgraph.graph import END, START, StateGraph

from pepperspray.agents.critic import critic_node, route_reflection, verify_node
from pepperspray.agents.specialists import build_specialists
from pepperspray.agents.supervisor import supervisor_node
from pepperspray.core.messages import AGENTS
from pepperspray.core.registry import REGISTRY, ToolContext, ToolRegistry
from pepperspray.core.state import AssessmentState, new_state
from pepperspray.graph.persistence import get_checkpointer
from pepperspray.graph.routing import (
    exploitation_gate,
    route_exploitation_gate,
    route_from_supervisor,
)
from pepperspray.reporting.report import render_report

_EXPLOIT_GATE = "exploitation_gate"

_SPECIALISTS = [a for a in AGENTS if a != "reporting"]


def build_graph(
    ctx: ToolContext,
    llm: Any = None,
    registry: ToolRegistry = REGISTRY,
    agent_factory: Callable | None = None,
    router: Callable | None = None,
    checkpointer: Any = None,
    interrupt_exploitation: bool = True,
    reflect: bool = True,
    scorer: Callable | None = None,
    verifier: Callable | None = None,
    use_subgraphs: bool = True,
):
    """Build and compile the assessment StateGraph.

    Each specialist is a nested plan→act→verify subgraph by default
    (``use_subgraphs``); set it False for the flat single-node specialists.

    When ``reflect`` is set, the supervisor's FINISH routes into a critic →
    (verify → critic)* reflection loop before reporting, so findings are deduped,
    scored and optionally re-verified. Otherwise it goes straight to reporting.
    """
    graph = StateGraph(AssessmentState)

    graph.add_node("supervisor", lambda state: supervisor_node(state, llm=llm, router=router))

    if use_subgraphs:
        from pepperspray.agents.subgraph import build_specialist_subgraphs

        specialists = build_specialist_subgraphs(
            ctx, llm=llm, registry=registry, agent_factory=agent_factory
        )
    else:
        specialists = build_specialists(
            ctx, llm=llm, registry=registry, agent_factory=agent_factory
        )
    for name, node in specialists.items():
        graph.add_node(name, node)

    graph.add_node("reporting", lambda state: {"report": render_report(state)})

    graph.add_edge(START, "supervisor")
    path_map = {name: name for name in _SPECIALISTS}
    # route_from_supervisor returns "reporting" on FINISH; send that into the
    # reflection loop first when enabled.
    path_map["reporting"] = "critic" if reflect else "reporting"
    # Exploitation is gated behind a dynamic human-in-the-loop interrupt: route
    # the supervisor's exploitation pick through the gate node instead.
    if interrupt_exploitation:
        path_map["exploitation"] = _EXPLOIT_GATE
        graph.add_node(_EXPLOIT_GATE, exploitation_gate)
        graph.add_conditional_edges(
            _EXPLOIT_GATE,
            route_exploitation_gate,
            {"exploitation": "exploitation", "supervisor": "supervisor"},
        )
    graph.add_conditional_edges("supervisor", route_from_supervisor, path_map)
    for name in _SPECIALISTS:
        graph.add_edge(name, "supervisor")

    if reflect:
        if verifier is None:
            from pepperspray.agents.critic import make_rerun_verifier

            verifier = make_rerun_verifier(registry)
        graph.add_node("critic", lambda s: critic_node(s, scorer=scorer, llm=llm))
        graph.add_node("verify", lambda s: verify_node(s, verifier=verifier, ctx=ctx))
        graph.add_conditional_edges(
            "critic", route_reflection, {"verify": "verify", "reporting": "reporting"}
        )
        graph.add_edge("verify", "critic")

    graph.add_edge("reporting", END)

    if checkpointer is None:
        from pepperspray.config import get_settings

        checkpointer = get_checkpointer(get_settings().checkpoint_db)
    return graph.compile(checkpointer=checkpointer)


def run_assessment(
    target: str,
    objective: str = "comprehensive",
    authorized: bool = False,
    ctx: ToolContext | None = None,
    llm: Any = None,
    registry: ToolRegistry = REGISTRY,
    agent_factory: Callable | None = None,
    router: Callable | None = None,
    checkpointer: Any = None,
    interrupt_exploitation: bool = True,
    reflect: bool = True,
    scorer: Callable | None = None,
    verifier: Callable | None = None,
    verify_budget: int = 1,
    thread_id: str = "assessment",
    recursion_limit: int = 50,
) -> dict:
    """Run a full assessment and return the final state (incl. the report)."""
    if ctx is None:
        from pepperspray.core.cache import ResultCache
        from pepperspray.core.executor import SafeCommandExecutor

        ctx = ToolContext(executor=SafeCommandExecutor(300), cache=ResultCache())

    graph = build_graph(
        ctx,
        llm=llm,
        registry=registry,
        agent_factory=agent_factory,
        router=router,
        checkpointer=checkpointer,
        interrupt_exploitation=interrupt_exploitation,
        reflect=reflect,
        scorer=scorer,
        verifier=verifier,
    )
    state = new_state(
        target=target, objective=objective, authorized=authorized, verify_budget=verify_budget
    )
    # Keep the recursion limit ahead of the step budget so FINISH is always
    # reachable even for large budgets (2 hops per supervisor cycle + slack).
    effective_limit = max(recursion_limit, state["step_budget"] * 2 + 10)
    config = {"configurable": {"thread_id": thread_id}, "recursion_limit": effective_limit}
    result = graph.invoke(state, config=config)
    return _finalize(graph, config, result)


def _finalize(graph: Any, config: dict, result: dict) -> dict:
    """If the graph paused at the HITL gate, surface a partial report plus the
    approval-request payload and marker; otherwise return the result as-is."""
    snapshot = graph.get_state(config)
    if not snapshot.next:
        return result

    out = dict(snapshot.values)
    interrupts = (result or {}).get("__interrupt__") or ()
    payload = getattr(interrupts[0], "value", None) if interrupts else None
    if isinstance(payload, dict) and payload.get("action"):
        out["awaiting_approval"] = [payload["action"]]
        out["approval_request"] = payload
    else:
        out["awaiting_approval"] = list(snapshot.next)
    if not out.get("report"):
        out["report"] = render_report(out)
    return out


def resume_after_approval(
    ctx: ToolContext,
    thread_id: str,
    decision: str | dict = "approve",
    edit: dict | None = None,
    llm: Any = None,
    registry: ToolRegistry = REGISTRY,
    agent_factory: Callable | None = None,
    router: Callable | None = None,
    checkpointer: Any = None,
    reflect: bool = True,
    scorer: Callable | None = None,
    verifier: Callable | None = None,
    recursion_limit: int = 50,
) -> dict:
    """Resume a run paused at the exploitation HITL gate (same thread_id).

    ``decision`` is ``"approve"`` or ``"deny"`` (or a payload dict). ``edit`` is
    an optional dict of state overrides applied before an approved exploitation
    step runs (e.g. a narrowed objective). The graph is rebuilt with the gate
    present so the pending interrupt can be resumed via ``Command(resume=...)``.
    """
    from langgraph.types import Command

    graph = build_graph(
        ctx,
        llm=llm,
        registry=registry,
        agent_factory=agent_factory,
        router=router,
        checkpointer=checkpointer,
        interrupt_exploitation=True,
        reflect=reflect,
        scorer=scorer,
        verifier=verifier,
    )
    config = {"configurable": {"thread_id": thread_id}, "recursion_limit": recursion_limit}

    # Normalize the decision into the payload the gate's _parse_decision expects.
    if isinstance(decision, dict):
        payload: dict = dict(decision)
        if edit is not None:
            payload.setdefault("edit", edit)
    else:
        payload = {"decision": decision}
        if edit is not None:
            payload["edit"] = edit

    result = graph.invoke(Command(resume=payload), config=config)
    return _finalize(graph, config, result)
