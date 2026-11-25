"""Assemble the supervisor/specialist assessment graph.

START → supervisor → (conditional) → specialist → supervisor → … → reporting → END

The supervisor routes; each specialist returns control to the supervisor; when
the supervisor decides FINISH (or the step budget runs out) the graph renders a
report and ends. Exploitation can be gated behind a human-in-the-loop interrupt.
"""

from __future__ import annotations

from typing import Any, Callable

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from pepperspray.agents.critic import critic_node, route_reflection, verify_node
from pepperspray.agents.specialists import build_specialists
from pepperspray.agents.supervisor import supervisor_node
from pepperspray.core.messages import AGENTS
from pepperspray.core.registry import REGISTRY, ToolContext, ToolRegistry
from pepperspray.core.state import AssessmentState, new_state
from pepperspray.graph.routing import route_from_supervisor
from pepperspray.reporting.report import render_report

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
):
    """Build and compile the assessment StateGraph.

    When ``reflect`` is set, the supervisor's FINISH routes into a critic →
    (verify → critic)* reflection loop before reporting, so findings are deduped,
    scored and optionally re-verified. Otherwise it goes straight to reporting.
    """
    graph = StateGraph(AssessmentState)

    graph.add_node("supervisor", lambda state: supervisor_node(state, llm=llm, router=router))

    specialists = build_specialists(ctx, llm=llm, registry=registry, agent_factory=agent_factory)
    for name, node in specialists.items():
        graph.add_node(name, node)

    graph.add_node("reporting", lambda state: {"report": render_report(state)})

    graph.add_edge(START, "supervisor")
    path_map = {name: name for name in _SPECIALISTS}
    # route_from_supervisor returns "reporting" on FINISH; send that into the
    # reflection loop first when enabled.
    path_map["reporting"] = "critic" if reflect else "reporting"
    graph.add_conditional_edges("supervisor", route_from_supervisor, path_map)
    for name in _SPECIALISTS:
        graph.add_edge(name, "supervisor")

    if reflect:
        graph.add_node("critic", lambda s: critic_node(s, scorer=scorer, llm=llm))
        graph.add_node("verify", lambda s: verify_node(s, verifier=verifier, ctx=ctx))
        graph.add_conditional_edges(
            "critic", route_reflection, {"verify": "verify", "reporting": "reporting"}
        )
        graph.add_edge("verify", "critic")

    graph.add_edge("reporting", END)

    compile_kwargs: dict[str, Any] = {"checkpointer": checkpointer or MemorySaver()}
    if interrupt_exploitation:
        compile_kwargs["interrupt_before"] = ["exploitation"]
    return graph.compile(**compile_kwargs)


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

    # If the graph paused at the exploitation HITL interrupt, it stopped before
    # the reporting node. Surface a partial report and an approval marker rather
    # than returning an empty, confusing result.
    snapshot = graph.get_state(config)
    if snapshot.next:
        result = dict(result)
        result["awaiting_approval"] = list(snapshot.next)
        if not result.get("report"):
            result["report"] = render_report(result)
    return result


def resume_after_approval(
    ctx: ToolContext,
    thread_id: str,
    llm: Any = None,
    registry: ToolRegistry = REGISTRY,
    agent_factory: Callable | None = None,
    router: Callable | None = None,
    checkpointer: Any = None,
    recursion_limit: int = 50,
) -> dict:
    """Resume a run paused at the exploitation interrupt (same thread_id)."""
    graph = build_graph(
        ctx,
        llm=llm,
        registry=registry,
        agent_factory=agent_factory,
        router=router,
        checkpointer=checkpointer,
        interrupt_exploitation=False,
    )
    config = {"configurable": {"thread_id": thread_id}, "recursion_limit": recursion_limit}
    return graph.invoke(None, config=config)
