"""Streaming: watch the assessment graph emit per-step events live, including
the HITL pause, and stream a resume to completion."""

from langchain_core.messages import AIMessage
from langgraph.checkpoint.memory import MemorySaver

from pepperspray.agents.supervisor import Route
from pepperspray.core.cache import ResultCache
from pepperspray.core.executor import SafeCommandExecutor
from pepperspray.core.registry import ToolContext
from pepperspray.graph.build import stream_assessment, stream_resume
from pepperspray.tools import load_all


def _ctx():
    return ToolContext(executor=SafeCommandExecutor(5), cache=ResultCache(10, 100))


class _SeqRouter:
    def __init__(self):
        self.calls = 0

    def __call__(self, state):
        self.calls += 1
        return Route(next="recon" if self.calls == 1 else "FINISH")


class _StateExploitRouter:
    def __call__(self, state):
        steps = state.get("completed_steps", [])
        denied = any(f.get("source") == "hitl" for f in state.get("findings", []))
        if "exploitation" in steps or denied:
            return Route(next="FINISH")
        return Route(next="exploitation")


class _FakeAgent:
    def __init__(self, llm, tools):
        self.tools = tools

    def invoke(self, inputs):
        return {"messages": list(inputs["messages"]) + [AIMessage(content="done")]}


def test_stream_emits_step_events_then_report():
    load_all()
    events = list(
        stream_assessment(
            "example.com",
            objective="recon",
            authorized=True,
            ctx=_ctx(),
            router=_SeqRouter(),
            agent_factory=_FakeAgent,
            interrupt_exploitation=False,
            reflect=False,
            thread_id="stream-1",
        )
    )
    types = [e["type"] for e in events]
    assert "step" in types, types
    assert types[-1] == "report"
    # a step event for the recon specialist appeared
    assert any(e["type"] == "step" and e["node"] == "recon" for e in events)
    assert "example.com" in events[-1]["report"]


def test_stream_pauses_with_approval_event():
    load_all()
    cp = MemorySaver()
    events = list(
        stream_assessment(
            "example.com",
            objective="exploit",
            authorized=True,
            ctx=_ctx(),
            router=_StateExploitRouter(),
            agent_factory=_FakeAgent,
            interrupt_exploitation=True,
            reflect=False,
            checkpointer=cp,
            thread_id="stream-pause",
        )
    )
    types = [e["type"] for e in events]
    assert types[-1] == "approval", types
    approval = events[-1]
    assert approval["awaiting"] == ["exploitation"]
    assert approval["request"].get("action") == "exploitation"
    assert "report" not in types  # paused before reporting


def test_stream_resume_completes_after_approval():
    load_all()
    cp = MemorySaver()
    list(
        stream_assessment(
            "example.com",
            objective="exploit",
            authorized=True,
            ctx=_ctx(),
            router=_StateExploitRouter(),
            agent_factory=_FakeAgent,
            interrupt_exploitation=True,
            reflect=False,
            checkpointer=cp,
            thread_id="stream-resume",
        )
    )
    events = list(
        stream_resume(
            _ctx(),
            thread_id="stream-resume",
            decision="approve",
            checkpointer=cp,
            router=_StateExploitRouter(),
            agent_factory=_FakeAgent,
            reflect=False,
        )
    )
    types = [e["type"] for e in events]
    assert types[-1] == "report", types
    assert any(e["type"] == "step" and e["node"] == "exploitation" for e in events)
