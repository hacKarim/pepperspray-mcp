from pepperspray.agents.supervisor import Route, supervisor_node
from pepperspray.graph.routing import (
    authorization_gate,
    requires_human_approval,
    route_from_supervisor,
)


class _StubRouter:
    def __init__(self, choice):
        self.choice = choice

    def __call__(self, state):
        return Route(next=self.choice, reason="stub")


def test_supervisor_clamps_unknown_next():
    out = supervisor_node(
        {"objective": "o", "findings": [], "step_budget": 5, "completed_steps": []},
        router=_StubRouter("bogus_agent"),
    )
    assert out["next"] in {
        "FINISH",
        "recon",
        "web",
        "exploitation",
        "binary",
        "cloud",
        "forensics",
        "cve",
    }
    assert out["next"] == "FINISH"  # unknown -> FINISH


def test_step_budget_forces_finish():
    out = supervisor_node(
        {"objective": "o", "findings": [], "step_budget": 0, "completed_steps": []},
        router=_StubRouter("recon"),
    )
    assert out["next"] == "FINISH"


def test_supervisor_decrements_budget():
    out = supervisor_node(
        {"objective": "o", "findings": [], "step_budget": 3, "completed_steps": []},
        router=_StubRouter("recon"),
    )
    assert out["next"] == "recon"
    assert out["step_budget"] == 2


def test_route_finish_goes_to_reporting():
    assert route_from_supervisor({"next": "FINISH"}) == "reporting"
    assert route_from_supervisor({"next": "recon"}) == "recon"


def test_exploitation_requires_approval():
    assert requires_human_approval({"next": "exploitation"}) is True
    assert requires_human_approval({"next": "recon"}) is False


def test_authorization_gate():
    assert authorization_gate({"authorized": True}) is True
    assert authorization_gate({"authorized": False}) is False
