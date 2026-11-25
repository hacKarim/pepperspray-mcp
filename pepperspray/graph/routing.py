"""Conditional-edge helpers and the human-in-the-loop gate for the graph."""

from __future__ import annotations

from typing import Any

from langgraph.types import Command, interrupt

from pepperspray.core.messages import AGENTS

EXPLOITATION_AGENT = "exploitation"
_SPECIALISTS = [a for a in AGENTS if a != "reporting"]


def route_from_supervisor(state: dict) -> str | list[str]:
    """Map the supervisor's decision to the next graph node(s).

    The decision is a single specialist, ``"FINISH"``, or a list of independent
    specialists to run concurrently. A list fans out via the conditional edge;
    unknown names are filtered, and an empty result falls back to reporting.
    """
    nxt = state.get("next", "FINISH")
    if isinstance(nxt, list):
        valid = [a for a in nxt if a in _SPECIALISTS]
        return valid or "reporting"
    if nxt == "FINISH" or nxt not in AGENTS:
        return "reporting"
    return nxt


def requires_human_approval(state: dict) -> bool:
    """True before an exploitation-class step (human-in-the-loop gate)."""
    nxt = state.get("next")
    if isinstance(nxt, list):
        return EXPLOITATION_AGENT in nxt
    return nxt == EXPLOITATION_AGENT


def authorization_gate(state: dict) -> bool:
    """True when the assessment is authorized to run active tools."""
    return bool(state.get("authorized", False))


def _parse_decision(decision: Any) -> tuple[str, dict]:
    """Normalize an operator decision into ``(verdict, edits)``.

    Accepts a bare verdict string (``"approve"``/``"deny"``) or a payload dict
    ``{"decision": ..., "edit": {state overrides}}``.
    """
    edits: dict = {}
    if isinstance(decision, dict):
        verdict = str(decision.get("decision", "deny")).strip().lower()
        raw = decision.get("edit")
        if isinstance(raw, dict):
            edits = raw
    else:
        verdict = str(decision).strip().lower()
    approve = verdict in {"approve", "approved", "yes", "y", "true", "ok"}
    return ("approve" if approve else "deny"), edits


def exploitation_gate(state: dict) -> Command:
    """Dynamic HITL gate before exploitation; self-routes via ``Command(goto=)``.

    Pauses the graph with an approval-request payload and resumes on the
    operator's decision: approve (optionally with state edits) routes to the
    exploitation specialist; deny records a finding and routes back to the
    supervisor instead of exploiting. An approval holds for the rest of the run
    so the operator is not re-prompted every exploitation hop.
    """
    if state.get("exploitation_approved"):
        return Command(goto=EXPLOITATION_AGENT)

    decision = interrupt(
        {
            "type": "approval_request",
            "action": EXPLOITATION_AGENT,
            "target": state.get("target"),
            "objective": state.get("objective"),
            "message": "Approve exploitation-class actions against this target?",
        }
    )
    verdict, edits = _parse_decision(decision)
    if verdict == "approve":
        update: dict = {"exploitation_approved": True}
        update.update(edits)
        return Command(goto=EXPLOITATION_AGENT, update=update)

    denial = {
        "title": f"exploitation step denied by operator on {state.get('target', '')}".strip(),
        "severity": "info",
        "source": "hitl",
        "detail": f"decision={decision!r}"[:160],
        "_status": "denied",
    }
    return Command(goto="supervisor", update={"findings": [denial]})
