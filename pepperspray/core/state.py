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
    next: str
    step_budget: int
    report: str | None


def new_state(target: str, objective: str = "comprehensive",
              authorized: bool = False, step_budget: int | None = None) -> AssessmentState:
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
    )


def record_finding(title: str, severity: str = "info", detail: str = "",
                   source: str = "") -> dict[str, Any]:
    return {"title": title, "severity": severity, "detail": detail, "source": source}
