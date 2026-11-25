"""Supervisor agent: routes control to the next specialist or finishes.

The LLM returns a structured ``Route``. The node clamps unknown choices to
FINISH, enforces a step budget so the graph always terminates, and decrements
that budget on every hop.
"""

from __future__ import annotations

from typing import Any, Callable

from pydantic import BaseModel, Field

from pepperspray.core.messages import AGENTS

_SPECIALISTS = [a for a in AGENTS if a != "reporting"]
_CHOICES = _SPECIALISTS + ["FINISH"]


class Route(BaseModel):
    """Supervisor routing decision."""

    next: str = Field(description=f"One of {_CHOICES}")
    reason: str = Field(default="", description="Why this agent (or FINISH)")


def _llm_router(llm: Any) -> Callable[[dict], Route]:
    structured = llm.with_structured_output(Route)

    def route(state: dict) -> Route:
        completed = ", ".join(state.get("completed_steps", [])) or "none"
        findings = len(state.get("findings", []))
        prompt = (
            "You are the supervisor of a security-assessment agent team.\n"
            f"Objective: {state.get('objective', '')}\n"
            f"Specialists available: {_SPECIALISTS}\n"
            f"Already run: {completed}. Findings so far: {findings}.\n"
            "Choose the next specialist to run, or FINISH when the objective is "
            "sufficiently covered. Do not repeat a specialist without reason."
        )
        return structured.invoke(prompt)

    return route


def supervisor_node(
    state: dict,
    llm: Any = None,
    router: Callable[[dict], Route] | None = None,
) -> dict:
    budget = int(state.get("step_budget", 0))
    if budget <= 0:
        return {"next": "FINISH", "step_budget": 0}

    route_fn = router or _llm_router(llm)
    decision = route_fn(state)
    choice = decision.next if decision.next in _CHOICES else "FINISH"

    return {
        "next": choice,
        "step_budget": budget - 1,
        "messages": [],
    }
