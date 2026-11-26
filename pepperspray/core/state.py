"""Shared LangGraph state for a security assessment.

The reducers make the graph append-only where it matters: findings, tool
results, completed steps, and chat messages accumulate across agent turns
instead of being overwritten when branches merge.
"""

import operator
from typing import Annotated, Any, TypedDict

from langgraph.graph.message import add_messages

from pepperspray.config import get_settings


class AssessmentState(TypedDict, total=False):
    target: str
    authorized: bool
    objective: str
    messages: Annotated[list, add_messages]
    plan: list[str]
    completed_steps: Annotated[list[str], operator.add]
    tool_results: Annotated[list[dict], operator.add]
    findings: Annotated[list[dict], operator.add]
    # The supervisor's dispatch: a single specialist name, "FINISH", or a list
    # of independent specialists to run concurrently in one superstep.
    next: str | list[str]
    step_budget: int
    report: str | None
    # Human-in-the-loop: the pending approval payload surfaced at the gate, and
    # a run-level approval flag so an approved run is not re-prompted per step.
    approval_request: dict
    exploitation_approved: bool
    # Parallel fan-out: sub-targets (subdomains/URLs/hosts) to scan concurrently.
    subtargets: list[str]
    # Reflection loop: remaining verification passes and current reflection phase.
    verify_budget: int
    reflection: str
    # Whether the reflection loop (critic/verify) is part of this run's graph.
    # Persisted so a resumed run rebuilds the same topology it checkpointed.
    reflect: bool
    # Critic output (overwrite, no reducer): curated/deduped findings + the subset
    # the critic flagged for a verification pass.
    curated_findings: list[dict]
    to_verify: list[dict]
    # Specialist subgraph scratch (overwrite): findings awaiting the subgraph's
    # local verify step before they enter the shared findings list.
    pending_findings: list[dict]


def new_state(
    target: str,
    objective: str = "comprehensive",
    authorized: bool = False,
    step_budget: int | None = None,
    verify_budget: int = 1,
    subtargets: list[str] | None = None,
    exploitation_approved: bool = False,
    reflect: bool = True,
) -> AssessmentState:
    budget = step_budget if step_budget is not None else get_settings().step_budget
    return AssessmentState(
        target=target,
        authorized=authorized,
        objective=objective,
        messages=[],
        plan=[],
        completed_steps=[],
        tool_results=[],
        findings=[],
        next="supervisor",
        step_budget=budget,
        report=None,
        subtargets=list(subtargets or []),
        verify_budget=verify_budget,
        reflection="pending",
        exploitation_approved=exploitation_approved,
        reflect=reflect,
    )


def record_finding(
    title: str, severity: str = "info", detail: str = "", source: str = ""
) -> dict[str, Any]:
    return {"title": title, "severity": severity, "detail": detail, "source": source}
