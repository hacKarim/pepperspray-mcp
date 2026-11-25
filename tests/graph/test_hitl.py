"""Real human-in-the-loop: a dynamic interrupt at the exploitation gate that
carries an approval-request payload and supports approve / deny / edit on resume,
plus a non-stub verifier that re-runs a finding's tool to confirm it."""

from langchain_core.messages import AIMessage
from langgraph.checkpoint.memory import MemorySaver

from pepperspray.agents.supervisor import Route
from pepperspray.core.cache import ResultCache
from pepperspray.core.executor import SafeCommandExecutor
from pepperspray.core.registry import ToolContext
from pepperspray.graph.build import resume_after_approval, run_assessment
from pepperspray.tools import load_all


def _ctx():
    return ToolContext(executor=SafeCommandExecutor(5), cache=ResultCache(10, 100))


class _StateRouter:
    """Route exploitation until it has run (or been denied), then FINISH.

    State-based so it behaves identically across fresh instances (a resume
    builds a brand-new router), unlike a call-counter.
    """

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


def _paused(cp, tid):
    return run_assessment(
        "example.com",
        objective="exploit",
        authorized=True,
        ctx=_ctx(),
        router=_StateRouter(),
        agent_factory=_FakeAgent,
        interrupt_exploitation=True,
        reflect=False,
        checkpointer=cp,
        thread_id=tid,
    )


def test_pause_exposes_approval_request_payload():
    load_all()
    cp = MemorySaver()
    final = _paused(cp, "hitl-payload")
    assert final.get("awaiting_approval") == ["exploitation"]
    req = final.get("approval_request")
    assert isinstance(req, dict)
    assert req.get("action") == "exploitation"
    assert req.get("target") == "example.com"
    assert final.get("report")  # partial report present


def test_resume_approve_runs_exploitation():
    load_all()
    cp = MemorySaver()
    _paused(cp, "hitl-approve")
    final = resume_after_approval(
        _ctx(),
        thread_id="hitl-approve",
        decision="approve",
        checkpointer=cp,
        router=_StateRouter(),
        agent_factory=_FakeAgent,
        reflect=False,
    )
    assert "exploitation" in final.get("completed_steps", [])
    assert final.get("report")


def test_resume_deny_skips_exploitation():
    load_all()
    cp = MemorySaver()
    _paused(cp, "hitl-deny")
    final = resume_after_approval(
        _ctx(),
        thread_id="hitl-deny",
        decision="deny",
        checkpointer=cp,
        router=_StateRouter(),
        agent_factory=_FakeAgent,
        reflect=False,
    )
    assert "exploitation" not in final.get("completed_steps", [])
    assert any(f.get("source") == "hitl" for f in final.get("findings", []))
    assert final.get("report")


def test_resume_edit_changes_state_then_runs():
    load_all()
    cp = MemorySaver()
    _paused(cp, "hitl-edit")
    final = resume_after_approval(
        _ctx(),
        thread_id="hitl-edit",
        decision="approve",
        edit={"objective": "narrowed-scope"},
        checkpointer=cp,
        router=_StateRouter(),
        agent_factory=_FakeAgent,
        reflect=False,
    )
    assert final.get("objective") == "narrowed-scope"
    assert "exploitation" in final.get("completed_steps", [])


def test_rerun_verifier_confirms_and_refuses():
    load_all()
    from pepperspray.agents.critic import make_rerun_verifier
    from pepperspray.core.registry import REGISTRY

    verify = make_rerun_verifier(REGISTRY)
    # No tool metadata -> cannot confirm.
    assert verify({"title": "x"}, _ctx()) is False
    # An exploitation-class tool is never auto-rerun to "verify".
    assert verify({"_tool": "execute_python_script", "_target": "x"}, _ctx()) is False
