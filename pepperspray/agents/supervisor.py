"""Supervisor agent: routes control to the next specialist or finishes.

The LLM returns a structured ``Route``. The node clamps unknown choices to
FINISH, enforces a step budget so the graph always terminates, and decrements
that budget on every hop.
"""

from __future__ import annotations

from typing import Any, Callable

from pydantic import BaseModel, Field, model_validator

from pepperspray.core.messages import AGENTS

_SPECIALISTS = [a for a in AGENTS if a != "reporting"]
_CHOICES = _SPECIALISTS + ["FINISH"]
_EXPLOIT = "exploitation"


class Route(BaseModel):
    """Supervisor routing decision.

    Set ``agents`` to one or more specialists to run; several run concurrently
    in the same superstep. Leave it empty (or set ``next='FINISH'``) to finish.
    ``next`` is the single-agent shorthand kept for convenience.
    """

    agents: list[str] = Field(
        default_factory=list,
        description=f"One or more of {_SPECIALISTS} to run (concurrently if several); empty = FINISH",
    )
    next: str | None = Field(default=None, description="Single-agent shorthand, or 'FINISH'")
    reason: str = Field(default="", description="Why these agents (or FINISH)")

    @model_validator(mode="after")
    def _normalize(self) -> "Route":
        # Fold the single-agent shorthand into the agents list.
        if not self.agents and self.next and self.next.upper() != "FINISH":
            self.agents = [self.next]
        return self


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
            "Choose the specialists to run next in `agents` — list several when "
            "they are independent (e.g. recon and cve) so they run concurrently. "
            "Leave `agents` empty to FINISH when the objective is sufficiently "
            "covered. Do not repeat a specialist without reason."
        )
        return structured.invoke(prompt)

    return route


def _select(decision: Route) -> list[str]:
    """Clamp a routing decision to known specialists, deduped, order preserved.

    Exploitation is gated behind a human-in-the-loop interrupt, so it never
    shares a superstep with other specialists: if chosen, it runs solo.
    """
    seen: set[str] = set()
    picked = [a for a in decision.agents if a in _SPECIALISTS and not (a in seen or seen.add(a))]
    if _EXPLOIT in picked:
        return [_EXPLOIT]
    return picked


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
    selected = _select(decision)

    if not selected:
        choice: str | list[str] = "FINISH"
    elif len(selected) == 1:
        choice = selected[0]
    else:
        choice = selected

    return {
        "next": choice,
        "step_budget": budget - 1,
        "messages": [],
    }
