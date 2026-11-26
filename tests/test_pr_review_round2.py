"""Regression tests for the second PR #5 review round: python-tool input
aliasing, result-serialization truncation, parallel-scan auth safety, resume
topology, and the subgraph message echo."""

import json

import pytest
from langchain_core.messages import AIMessage, ToolMessage
from langgraph.checkpoint.memory import MemorySaver

from pepperspray.agents.base import _harvest_tool_results, _serialize_result
from pepperspray.agents.supervisor import Route
from pepperspray.core.cache import ResultCache
from pepperspray.core.executor import SafeCommandExecutor, ToolResult
from pepperspray.core.registry import REGISTRY, ToolContext, spread_target
from pepperspray.tools import load_all


def _ctx():
    return ToolContext(executor=SafeCommandExecutor(5), cache=ResultCache(10, 100))


# --- Finding 1: cve/flag/jwt tools reachable through the single-target wrapper -
def test_spread_target_populates_python_tool_keys():
    p = spread_target("CVE-2024-0001")
    for key in ("cve_id", "text", "flag", "token", "jwt_token"):
        assert p[key] == "CVE-2024-0001"


def test_flag_tools_receive_input_via_registry():
    load_all()
    out = REGISTRY.execute(
        "flag_extract", spread_target("flag{abc_123}"), _ctx(), authorized=False
    ).to_dict()
    assert "flag{abc_123}" in out["stdout"]


def test_jwt_analyzer_receives_token_via_registry():
    load_all()
    # A syntactically valid JWT header.payload.signature.
    tok = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"
    out = REGISTRY.execute("jwt_analyzer", spread_target(tok), _ctx(), authorized=False).to_dict()
    assert '"alg"' in out["stdout"] and "HS256" in out["stdout"]


# --- Finding 2: large tool output stays valid JSON, status survives ----------
def test_serialize_result_truncates_but_stays_valid_json():
    big = "A" * 50_000
    text = _serialize_result(ToolResult(tool="nmap", status="success", stdout=big))
    data = json.loads(text)  # must not raise
    assert data["status"] == "success"
    assert data["stdout"].endswith("…[truncated]")
    assert len(text) < 6000


def test_harvest_recovers_status_from_large_output():
    big = "B" * 20_000
    msg = ToolMessage(
        content=_serialize_result(ToolResult(tool="nuclei", status="success", stdout=big)),
        tool_call_id="1",
        name="nuclei",
    )
    harvested = _harvest_tool_results([msg])
    assert harvested[0]["result"]["status"] == "success"  # not {"raw": ...}


# --- Finding 3: unauthorized parallel scan degrades, never crashes -----------
def test_parallel_scan_unauthorized_does_not_crash():
    load_all()
    from pepperspray.graph.parallel import run_parallel_scan

    final = run_parallel_scan("example.com", subtargets=["a.com", "b.com"], authorized=False)
    assert final.get("report")
    statuses = {tr["result"]["status"] for tr in final["tool_results"]}
    assert statuses == {"unavailable"}


# --- Finding 5: subgraph returns only its own messages -----------------------
def test_subgraph_does_not_echo_parent_messages():
    from pepperspray.agents.subgraph import _as_node

    captured = {}

    class _Compiled:
        def invoke(self, sub_state):
            captured["messages_in"] = list(sub_state.get("messages", []))
            return {"messages": [AIMessage(content="mine")], "findings": []}

    node = _as_node(_Compiled())
    node({"messages": [AIMessage(content="old1"), AIMessage(content="old2")], "findings": []})
    assert captured["messages_in"] == []  # parent transcript withheld


# --- Finding 4: resume rebuilds the same (reflect) topology ------------------
class _ExploitThenFinish:
    def __call__(self, state):
        if "exploitation" in state.get("completed_steps", []):
            return Route(next="FINISH")
        return Route(next="exploitation")


class _FakeAgent:
    def __init__(self, llm, tools):
        self.tools = tools

    def invoke(self, inputs):
        return {"messages": list(inputs["messages"]) + [AIMessage(content="done")]}


@pytest.mark.parametrize("reflect", [True, False])
def test_resume_preserves_reflect_topology(reflect):
    from pepperspray.graph.build import resume_after_approval, run_assessment

    cp = MemorySaver()
    kw = dict(agent_factory=_FakeAgent, checkpointer=cp)
    paused = run_assessment(
        "example.com",
        authorized=True,
        ctx=_ctx(),
        router=_ExploitThenFinish(),
        interrupt_exploitation=True,
        reflect=reflect,
        thread_id=f"r2-{reflect}",
        **kw,
    )
    assert paused.get("awaiting_approval") == ["exploitation"]
    # reflect is NOT passed here; resume must recover it from the checkpoint.
    final = resume_after_approval(
        _ctx(), f"r2-{reflect}", "approve", router=_ExploitThenFinish(), **kw
    )
    assert final.get("report")
    steps = final.get("completed_steps", [])
    assert "exploitation" in steps
