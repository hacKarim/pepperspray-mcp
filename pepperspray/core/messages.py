"""Inter-agent handoff messages used by the supervisor/specialist graph."""

from __future__ import annotations

from dataclasses import dataclass

AGENTS = [
    "recon",
    "web",
    "exploitation",
    "binary",
    "cloud",
    "forensics",
    "cve",
    "reporting",
]


@dataclass
class Handoff:
    """A supervisor decision to route control to a named agent (or FINISH)."""

    to: str
    reason: str = ""

    def is_finish(self) -> bool:
        return self.to.upper() == "FINISH"
