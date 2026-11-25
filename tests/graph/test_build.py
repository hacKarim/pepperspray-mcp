from langchain_core.messages import AIMessage, ToolMessage

from pepperspray.agents.supervisor import Route
from pepperspray.core.cache import ResultCache
from pepperspray.core.executor import SafeCommandExecutor
from pepperspray.core.registry import ToolContext
from pepperspray.graph.build import build_graph, run_assessment
from pepperspray.tools import load_all


def _ctx():
    return ToolContext(executor=SafeCommandExecutor(5), cache=ResultCache(10, 100))


class _SeqRouter:
    """Routes recon once, then FINISH."""

    def __init__(self):
        self.calls = 0

    def __call__(self, state):
        self.calls += 1
        return Route(next="recon" if self.calls == 1 else "FINISH")


class _FakeAgent:
    def __init__(self, llm, tools):
        self.tools = tools

    def invoke(self, inputs):
        msgs = list(inputs["messages"])
        if self.tools:
            t = self.tools[0]
            out = t.invoke({"target": "example.com", "extra": ""})
            msgs += [
                AIMessage(
                    content="",
                    tool_calls=[{"name": t.name, "args": {"target": "example.com"}, "id": "1"}],
                ),
                ToolMessage(content=out, tool_call_id="1", name=t.name),
            ]
        msgs.append(AIMessage(content="done"))
        return {"messages": msgs}


def test_graph_compiles_with_expected_nodes():
    load_all()
    g = build_graph(_ctx(), router=_SeqRouter(), agent_factory=_FakeAgent)
    nodes = set(g.get_graph().nodes)
    assert {"supervisor", "recon", "web", "exploitation", "reporting"} <= nodes


def test_end_to_end_stub_produces_report():
    load_all()
    final = run_assessment(
        "example.com",
        objective="recon",
        authorized=True,
        ctx=_ctx(),
        router=_SeqRouter(),
        agent_factory=_FakeAgent,
        interrupt_exploitation=False,
    )
    assert final.get("report")
    assert "example.com" in final["report"]
    assert any(s == "recon" for s in final.get("completed_steps", []))


def test_recon_chain_runs():
    load_all()
    from pepperspray.graph.chains import run_chain

    final = run_chain(
        "recon_chain", "example.com", authorized=True, ctx=_ctx(), agent_factory=_FakeAgent
    )
    assert final.get("report") and "example.com" in final["report"]
    assert "recon" in final.get("completed_steps", [])


def test_unknown_chain_raises():
    import pytest

    from pepperspray.graph.chains import build_chain

    with pytest.raises(KeyError):
        build_chain("nope", _ctx())


def test_reflection_loop_verifies_findings():
    load_all()
    from pepperspray.agents.critic import Critique, FindingScore

    def scorer(findings):
        # flag every finding for verification
        return Critique(
            scores=[
                FindingScore(index=i, confidence=0.5, needs_verification=True)
                for i in range(len(findings))
            ]
        )

    def verifier(finding, ctx):
        return True  # confirm

    final = run_assessment(
        "example.com",
        objective="recon",
        authorized=True,
        ctx=_ctx(),
        router=_SeqRouter(),
        agent_factory=_FakeAgent,
        reflect=True,
        scorer=scorer,
        verifier=verifier,
        verify_budget=1,
        interrupt_exploitation=False,
        thread_id="reflect-e2e",
    )
    assert final.get("curated_findings"), "critic should produce curated findings"
    assert any(f.get("verified") for f in final["curated_findings"]), "verify pass should run"
    assert final.get("report") and "Verified" in final["report"]
