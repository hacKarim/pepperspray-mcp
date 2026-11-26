"""Assemble the supervisor/specialist assessment graph.

START → supervisor → (conditional) → specialist → supervisor → … → reporting → END

The supervisor routes; each specialist returns control to the supervisor; when
the supervisor decides FINISH (or the step budget runs out) the graph renders a
report and ends. Exploitation can be gated behind a human-in-the-loop interrupt.
"""

from __future__ import annotations

from typing import Any, Callable, Iterator

from langgraph.graph import END, START, StateGraph

from pepperspray.agents.critic import critic_node, route_reflection, verify_node
from pepperspray.agents.specialists import build_specialists
from pepperspray.agents.supervisor import supervisor_node
from pepperspray.core.messages import AGENTS
from pepperspray.core.registry import REGISTRY, ToolContext, ToolRegistry
from pepperspray.core.state import AssessmentState, new_state
from pepperspray.graph.persistence import get_checkpointer
from pepperspray.graph.resilience import DEFAULT_RETRY, specialist_cache_policy
from pepperspray.graph.routing import exploitation_gate, route_from_supervisor
from pepperspray.reporting.report import render_report

_EXPLOIT_GATE = "exploitation_gate"
_EXPLOIT = "exploitation"

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
    retry_policy: Any = DEFAULT_RETRY,
    node_cache: bool = True,
    cache_ttl: int | None = None,
):
    """Build and compile the assessment StateGraph.

    Each specialist is a nested plan→act→verify subgraph by default
    (``use_subgraphs``); set it False for the flat single-node specialists.

    When ``reflect`` is set, the supervisor's FINISH routes into a critic →
    (verify → critic)* reflection loop before reporting, so findings are deduped,
    scored and optionally re-verified. Otherwise it goes straight to reporting.

    Nodes that do I/O carry a ``retry_policy`` (transient-failure retry with
    backoff); specialist nodes also carry a per-run cache so re-dispatching the
    same specialist on the same target is served from cache (``node_cache``).
    """
    from pepperspray.config import get_settings

    ttl = cache_ttl if cache_ttl is not None else get_settings().cache_ttl
    graph = StateGraph(AssessmentState)

    graph.add_node(
        "supervisor",
        lambda state: supervisor_node(state, llm=llm, router=router),
        retry_policy=retry_policy,
    )

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
        graph.add_node(
            name,
            node,
            retry_policy=retry_policy,
            cache_policy=specialist_cache_policy(name, ttl) if node_cache else None,
        )

    graph.add_node("reporting", lambda state: {"report": render_report(state)})

    graph.add_edge(START, "supervisor")
    path_map = {name: name for name in _SPECIALISTS}
    # route_from_supervisor returns "reporting" on FINISH; send that into the
    # reflection loop first when enabled.
    path_map["reporting"] = "critic" if reflect else "reporting"
    # Exploitation is gated behind a dynamic human-in-the-loop interrupt: route
    # the supervisor's exploitation pick through the gate node, which then
    # self-routes to exploitation (approve) or back to supervisor (deny) via
    # Command(goto=...). ``destinations`` records those edges for the graph.
    if interrupt_exploitation:
        path_map["exploitation"] = _EXPLOIT_GATE
        graph.add_node(_EXPLOIT_GATE, exploitation_gate, destinations=(_EXPLOIT, "supervisor"))
    graph.add_conditional_edges("supervisor", route_from_supervisor, path_map)
    for name in _SPECIALISTS:
        graph.add_edge(name, "supervisor")

    if reflect:
        if verifier is None:
            from pepperspray.agents.critic import make_rerun_verifier

            verifier = make_rerun_verifier(registry)
        graph.add_node(
            "critic",
            lambda s: critic_node(s, scorer=scorer, llm=llm),
            retry_policy=retry_policy,
        )
        graph.add_node(
            "verify",
            lambda s: verify_node(s, verifier=verifier, ctx=ctx),
            retry_policy=retry_policy,
        )
        graph.add_conditional_edges(
            "critic", route_reflection, {"verify": "verify", "reporting": "reporting"}
        )
        graph.add_edge("verify", "critic")

    graph.add_edge("reporting", END)

    if checkpointer is None:
        checkpointer = get_checkpointer(get_settings().checkpoint_db)

    cache = None
    if node_cache:
        from langgraph.cache.memory import InMemoryCache

        cache = InMemoryCache()
    return graph.compile(checkpointer=checkpointer, cache=cache)


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
    retry_policy: Any = DEFAULT_RETRY,
) -> dict:
    """Run a full assessment and return the final state (incl. the report)."""
    graph, state, config = _assessment_graph(
        target,
        objective,
        authorized,
        ctx,
        llm,
        registry,
        agent_factory,
        router,
        checkpointer,
        interrupt_exploitation,
        reflect,
        scorer,
        verifier,
        verify_budget,
        thread_id,
        recursion_limit,
        retry_policy,
    )
    result = graph.invoke(state, config=config)
    return _finalize(graph, config, result)


def _assessment_graph(
    target,
    objective,
    authorized,
    ctx,
    llm,
    registry,
    agent_factory,
    router,
    checkpointer,
    interrupt_exploitation,
    reflect,
    scorer,
    verifier,
    verify_budget,
    thread_id,
    recursion_limit,
    retry_policy=DEFAULT_RETRY,
):
    """Shared setup for both the blocking and streaming entry points."""
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
        retry_policy=retry_policy,
    )
    state = new_state(
        target=target,
        objective=objective,
        authorized=authorized,
        verify_budget=verify_budget,
        # Without the HITL gate the operator approved exploitation up front
        # (--allow-exploitation); with it, the gate sets this on approval.
        exploitation_approved=not interrupt_exploitation,
        reflect=reflect,
    )
    # Keep the recursion limit ahead of the step budget so FINISH is always
    # reachable even for large budgets (2 hops per supervisor cycle + slack).
    effective_limit = max(recursion_limit, state["step_budget"] * 2 + 10)
    config = {"configurable": {"thread_id": thread_id}, "recursion_limit": effective_limit}
    # Attach LangSmith trace metadata when tracing is enabled (no-op otherwise).
    from pepperspray.obs import trace_config

    config.update(trace_config(target, objective, thread_id))
    return graph, state, config


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


def _resolve_checkpointer(checkpointer):
    if checkpointer is not None:
        return checkpointer
    from pepperspray.config import get_settings

    return get_checkpointer(get_settings().checkpoint_db)


def _checkpointed_reflect(checkpointer, thread_id: str, default: bool) -> bool:
    """Read the ``reflect`` flag the paused run stored, so the resumed graph is
    the same topology that wrote the checkpoint. Falls back to ``default`` when
    the checkpoint predates this field or cannot be read."""
    cfg = {"configurable": {"thread_id": thread_id, "checkpoint_ns": ""}}
    try:
        tup = checkpointer.get_tuple(cfg)
    except Exception:
        return default
    values = (getattr(tup, "checkpoint", None) or {}).get("channel_values", {}) if tup else {}
    stored = values.get("reflect")
    return bool(stored) if stored is not None else default


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
    reflect: bool | None = None,
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

    checkpointer = _resolve_checkpointer(checkpointer)
    if reflect is None:
        reflect = _checkpointed_reflect(checkpointer, thread_id, default=True)
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
    result = graph.invoke(Command(resume=_decision_payload(decision, edit)), config=config)
    return _finalize(graph, config, result)


def _decision_payload(decision: str | dict, edit: dict | None) -> dict:
    """Normalize an operator decision into the payload the HITL gate expects."""
    if isinstance(decision, dict):
        payload: dict = dict(decision)
        if edit is not None:
            payload.setdefault("edit", edit)
    else:
        payload = {"decision": decision}
        if edit is not None:
            payload["edit"] = edit
    return payload


# --- Streaming -------------------------------------------------------------
#
# The streaming entry points mirror run_assessment / resume_after_approval but
# yield one event per graph superstep instead of blocking for the final state:
#
#   {"type": "step",     "node": str, "completed": [...], "findings_delta": int}
#   {"type": "approval", "request": {...}, "awaiting": ["exploitation"]}
#   {"type": "report",   "report": str, "state": {...}}
#
# so a CLI (or MCP client) can show each agent working live and still honor the
# human-in-the-loop pause.


def stream_assessment(
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
    retry_policy: Any = DEFAULT_RETRY,
) -> Iterator[dict]:
    """Stream a full assessment, yielding a typed event per superstep."""
    graph, state, config = _assessment_graph(
        target,
        objective,
        authorized,
        ctx,
        llm,
        registry,
        agent_factory,
        router,
        checkpointer,
        interrupt_exploitation,
        reflect,
        scorer,
        verifier,
        verify_budget,
        thread_id,
        recursion_limit,
        retry_policy,
    )
    yield from _stream_events(graph, state, config)


def stream_resume(
    ctx: ToolContext,
    thread_id: str,
    decision: str | dict = "approve",
    edit: dict | None = None,
    llm: Any = None,
    registry: ToolRegistry = REGISTRY,
    agent_factory: Callable | None = None,
    router: Callable | None = None,
    checkpointer: Any = None,
    reflect: bool | None = None,
    scorer: Callable | None = None,
    verifier: Callable | None = None,
    recursion_limit: int = 50,
) -> Iterator[dict]:
    """Stream a resume of a run paused at the HITL gate (same thread_id)."""
    from langgraph.types import Command

    checkpointer = _resolve_checkpointer(checkpointer)
    if reflect is None:
        reflect = _checkpointed_reflect(checkpointer, thread_id, default=True)
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
    yield from _stream_events(graph, Command(resume=_decision_payload(decision, edit)), config)


def _stream_events(graph: Any, graph_input: Any, config: dict) -> Iterator[dict]:
    """Drive graph.stream(updates) and translate chunks into typed events."""
    interrupt_payload: Any = None
    for chunk in graph.stream(graph_input, config=config, stream_mode="updates"):
        if "__interrupt__" in chunk:
            intr = chunk["__interrupt__"]
            interrupt_payload = getattr(intr[0], "value", None) if intr else None
            continue
        for node, update in chunk.items():
            update = update or {}
            yield {
                "type": "step",
                "node": node,
                "completed": list(update.get("completed_steps") or []),
                "findings_delta": len(update.get("findings") or []),
            }

    snapshot = graph.get_state(config)
    if snapshot.next:
        action = interrupt_payload.get("action") if isinstance(interrupt_payload, dict) else None
        yield {
            "type": "approval",
            "request": interrupt_payload or {},
            "awaiting": [action] if action else list(snapshot.next),
        }
    else:
        vals = dict(snapshot.values)
        yield {
            "type": "report",
            "report": vals.get("report") or render_report(vals),
            "state": vals,
        }
