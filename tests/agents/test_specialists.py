from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from pepperspray.agents.base import make_specialist
from pepperspray.core.cache import ResultCache
from pepperspray.core.executor import SafeCommandExecutor
from pepperspray.core.registry import ToolContext, ToolRegistry, ToolSpec


def _ctx():
    return ToolContext(executor=SafeCommandExecutor(5), cache=ResultCache(10, 100))


def _reg_with_echo():
    reg = ToolRegistry()
    reg.register(
        ToolSpec(
            name="echo_tool",
            family="recon",
            executor_kind="shell",
            build_argv=lambda p: ["echo", p.get("target", "")],
        )
    )
    return reg


class _FakeAgent:
    """Stands in for a compiled react agent: 'calls' one tool, returns messages."""

    def __init__(self, llm, tools):
        self.tools = {t.name: t for t in tools}

    def invoke(self, inputs):
        msgs = list(inputs["messages"])
        # simulate the model invoking echo_tool then answering
        out = self.tools["echo_tool"].invoke({"target": "example.com"})
        msgs.append(
            AIMessage(
                content="",
                tool_calls=[{"name": "echo_tool", "args": {"target": "example.com"}, "id": "1"}],
            )
        )
        msgs.append(ToolMessage(content=out, tool_call_id="1", name="echo_tool"))
        msgs.append(AIMessage(content="done"))
        return {"messages": msgs}


def test_specialist_node_runs_and_records():
    reg = _reg_with_echo()
    node = make_specialist(
        "recon",
        ["recon"],
        "be a recon agent",
        ctx=_ctx(),
        registry=reg,
        llm=None,
        agent_factory=_FakeAgent,
    )
    state = {
        "target": "example.com",
        "objective": "recon",
        "authorized": True,
        "messages": [HumanMessage("go")],
        "tool_results": [],
    }
    out = node(state)
    # Routing is a static edge now; the specialist no longer writes `next`.
    assert "next" not in out
    assert len(out["tool_results"]) == 1
    assert out["completed_steps"] == ["recon"]


def test_unauthorized_active_tool_records_refusal():
    reg = ToolRegistry()
    reg.register(
        ToolSpec(
            name="echo_tool",
            family="recon",
            executor_kind="shell",
            active=True,
            build_argv=lambda p: ["echo", "x"],
        )
    )

    class FakeAgentRefused(_FakeAgent):
        def invoke(self, inputs):
            # calling an active tool unauthorized returns an error string, not a crash
            out = self.tools["echo_tool"].invoke({"target": "x"})
            assert "authoriz" in out.lower()
            return {"messages": list(inputs["messages"]) + [AIMessage(content="blocked")]}

    node = make_specialist(
        "recon", ["recon"], "p", ctx=_ctx(), registry=reg, llm=None, agent_factory=FakeAgentRefused
    )
    state = {"target": "x", "objective": "o", "authorized": False, "messages": [HumanMessage("go")]}
    out = node(state)  # must not raise
    assert "next" not in out


def test_build_specialists_covers_roster():
    from pepperspray.agents.specialists import SPECIALISTS, build_specialists
    from pepperspray.tools import load_all

    load_all()
    nodes = build_specialists(_ctx(), llm=None, agent_factory=_FakeAgent)
    assert set(nodes) == set(SPECIALISTS)
    assert "recon" in nodes and "cve" in nodes
    assert callable(nodes["recon"])


def test_specialist_emits_findings_from_tool_runs():
    reg = _reg_with_echo()
    node = make_specialist(
        "recon", ["recon"], "p", ctx=_ctx(), registry=reg, llm=None, agent_factory=_FakeAgent
    )
    state = {
        "target": "example.com",
        "objective": "recon",
        "authorized": True,
        "messages": [HumanMessage("go")],
        "tool_results": [],
    }
    out = node(state)
    assert out["findings"], "specialist should emit a finding per tool run"
    f = out["findings"][0]
    assert f["source"] == "recon" and "echo_tool" in f["title"]
