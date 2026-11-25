from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from pepperspray.agents.subgraph import build_specialist_subgraphs, make_specialist_subgraph
from pepperspray.core.cache import ResultCache
from pepperspray.core.executor import SafeCommandExecutor
from pepperspray.core.registry import ToolContext, ToolRegistry, ToolSpec
from pepperspray.core.state import AssessmentState


def _ctx():
    return ToolContext(executor=SafeCommandExecutor(5), cache=ResultCache(10, 100))


def _reg_echo():
    r = ToolRegistry()
    r.register(
        ToolSpec(
            name="echo_tool",
            family="recon",
            executor_kind="shell",
            build_argv=lambda p: ["echo", p.get("target", "")],
        )
    )
    return r


class _FakeAgent:
    def __init__(self, llm, tools):
        self.tools = tools

    def invoke(self, inputs):
        msgs = list(inputs["messages"])
        if self.tools:
            t = self.tools[0]
            out = t.invoke({"target": "example.com"})
            msgs += [
                AIMessage(content="", tool_calls=[{"name": t.name, "args": {}, "id": "1"}]),
                ToolMessage(content=out, tool_call_id="1", name=t.name),
            ]
        return {"messages": msgs + [AIMessage(content="done")]}


def test_subgraph_runs_plan_act_verify():
    reg = _reg_echo()
    sg = make_specialist_subgraph(
        "recon", ["recon"], "p", ctx=_ctx(), registry=reg, llm=None, agent_factory=_FakeAgent
    )
    nodes = set(sg.get_graph().nodes)
    assert {"plan", "act", "verify"} <= nodes


def test_subgraph_produces_scored_findings():
    reg = _reg_echo()
    sg = make_specialist_subgraph(
        "recon", ["recon"], "p", ctx=_ctx(), registry=reg, llm=None, agent_factory=_FakeAgent
    )
    state = AssessmentState(
        target="example.com",
        objective="recon",
        authorized=True,
        messages=[HumanMessage("go")],
        findings=[],
        tool_results=[],
        completed_steps=[],
        pending_findings=[],
    )
    out = sg.invoke(state)
    assert out["findings"], "verify step should promote findings"
    assert out["findings"][0].get("confidence") is not None  # locally scored
    assert "recon" in out["completed_steps"]
    assert out["pending_findings"] == []  # cleared after verify


def test_build_specialist_subgraphs_covers_roster():
    from pepperspray.tools import load_all

    load_all()
    graphs = build_specialist_subgraphs(_ctx(), llm=None, agent_factory=_FakeAgent)
    assert {"recon", "web", "exploitation", "cve"} <= set(graphs)
