"""Concurrent specialist dispatch: the supervisor can select more than one
independent specialist to run in the same superstep (e.g. recon + cve)."""

from langchain_core.messages import AIMessage

from pepperspray.agents.supervisor import Route, supervisor_node
from pepperspray.core.cache import ResultCache
from pepperspray.core.executor import SafeCommandExecutor
from pepperspray.core.registry import ToolContext
from pepperspray.graph.build import run_assessment
from pepperspray.graph.routing import route_from_supervisor
from pepperspray.tools import load_all


def _ctx():
    return ToolContext(executor=SafeCommandExecutor(5), cache=ResultCache(10, 100))


class _MultiRouter:
    """Dispatch recon + cve concurrently once, then FINISH."""

    def __call__(self, state):
        steps = state.get("completed_steps", [])
        if "recon" in steps and "cve" in steps:
            return Route(next="FINISH")
        return Route(agents=["recon", "cve"])


class _FakeAgent:
    def __init__(self, llm, tools):
        self.tools = tools

    def invoke(self, inputs):
        return {"messages": list(inputs["messages"]) + [AIMessage(content="done")]}


def test_supervisor_can_select_multiple_agents():
    out = supervisor_node(
        {"objective": "o", "findings": [], "step_budget": 5, "completed_steps": []},
        router=lambda s: Route(agents=["recon", "cve"]),
    )
    assert out["next"] == ["recon", "cve"]
    assert out["step_budget"] == 4


def test_exploitation_always_runs_solo():
    out = supervisor_node(
        {"objective": "o", "findings": [], "step_budget": 5, "completed_steps": []},
        router=lambda s: Route(agents=["web", "exploitation"]),
    )
    # exploitation is gated; it must never share a superstep with another agent.
    assert out["next"] == "exploitation"


def test_route_from_supervisor_passes_list_through():
    assert route_from_supervisor({"next": ["recon", "cve"]}) == ["recon", "cve"]
    # unknown names are filtered out of the batch
    assert route_from_supervisor({"next": ["recon", "bogus"]}) == ["recon"]
    # an all-unknown batch falls back to reporting
    assert route_from_supervisor({"next": ["bogus"]}) == "reporting"


def test_concurrent_specialists_run_in_one_pass():
    load_all()
    final = run_assessment(
        "example.com",
        objective="recon",
        authorized=True,
        ctx=_ctx(),
        router=_MultiRouter(),
        agent_factory=_FakeAgent,
        interrupt_exploitation=False,
        reflect=False,
        thread_id="concurrent-1",
    )
    steps = final.get("completed_steps", [])
    assert "recon" in steps and "cve" in steps
    assert final.get("report")
