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
):
    """Build and compile the assessment StateGraph."""
    graph = StateGraph(AssessmentState)

    graph.add_node("supervisor", lambda state: supervisor_node(state, llm=llm, router=router))

    specialists = build_specialists(ctx, llm=llm, registry=registry, agent_factory=agent_factory)
    for name, node in specialists.items():
        graph.add_node(name, node)

    graph.add_node("reporting", lambda state: {"report": render_report(state)})

    graph.add_edge(START, "supervisor")
    path_map = {name: name for name in _SPECIALISTS}
    path_map["reporting"] = "reporting"
    graph.add_conditional_edges("supervisor", route_from_supervisor, path_map)
    for name in _SPECIALISTS:
        graph.add_edge(name, "supervisor")
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
    )
    state = new_state(target=target, objective=objective, authorized=authorized)
    config = {"configurable": {"thread_id": thread_id}, "recursion_limit": recursion_limit}
    return graph.invoke(state, config=config)
