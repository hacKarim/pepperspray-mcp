"""Conditional-edge helpers and safety gates for the assessment graph."""

from __future__ import annotations

from pepperspray.core.messages import AGENTS

EXPLOITATION_AGENT = "exploitation"


def route_from_supervisor(state: dict) -> str:
    """Map the supervisor's decision to the next graph node."""
    nxt = state.get("next", "FINISH")
    if nxt == "FINISH" or nxt not in AGENTS:
        return "reporting"
    return nxt


def requires_human_approval(state: dict) -> bool:
    """True before an exploitation-class step (human-in-the-loop gate)."""
    return state.get("next") == EXPLOITATION_AGENT


def authorization_gate(state: dict) -> bool:
    """True when the assessment is authorized to run active tools."""
    return bool(state.get("authorized", False))
