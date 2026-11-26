"""Regression tests for the PR #5 review: exploitation gating outside the
exploitation family, httpx binary name, CVSS v2 scoring, parallel-scan report
shape, and verify matching on the dedupe key."""

import pytest
from langchain_core.messages import AIMessage
from langgraph.checkpoint.memory import MemorySaver

from pepperspray.agents.base import _make_lc_tool, specialist_specs
from pepperspray.agents.critic import verify_node
from pepperspray.agents.supervisor import Route
from pepperspray.core.cache import ResultCache
from pepperspray.core.errors import AuthorizationError
from pepperspray.core.executor import SafeCommandExecutor, ToolResult
from pepperspray.core.registry import REGISTRY, ToolContext, ToolRegistry, ToolSpec
from pepperspray.tools import load_all


def _ctx():
    return ToolContext(executor=SafeCommandExecutor(5), cache=ResultCache(10, 100))


def _exploit_registry(calls: list) -> ToolRegistry:
    """A registry with an exploitation-class tool filed under the recon family."""

    def run(params, ctx):
        calls.append(params.get("target"))
        return ToolResult(tool="poison", status="success", stdout="poisoned")

    reg = ToolRegistry()
    reg.register(
        ToolSpec(
            name="poison",
            family="recon",
            executor_kind="python",
            run=run,
            active=True,
            exploitation=True,
        )
    )
    reg.register(
        ToolSpec(
            name="lookup",
            family="recon",
            executor_kind="python",
            run=lambda p, c: ToolResult(tool="lookup", status="success"),
        )
    )
    return reg


class _CallAllTools:
    """Fake ReAct agent: calls every tool it was bound to once."""

    def __init__(self, llm, tools):
        self.tools = tools

    def invoke(self, inputs):
        for t in self.tools:
            t.invoke({"target": "example.com"})
        return {"messages": list(inputs["messages"]) + [AIMessage(content="done")]}


class _Router:
    def __init__(self, agent):
        self.agent = agent

    def __call__(self, state):
        done = self.agent in state.get("completed_steps", [])
        return Route(next="FINISH" if done else self.agent)


# --- Exploitation gating -----------------------------------------------------
def test_registry_refuses_exploitation_tool_without_approval():
    reg = _exploit_registry([])
    with pytest.raises(AuthorizationError, match="exploitation-class"):
        reg.execute("poison", {"target": "x"}, _ctx(), authorized=True)
    assert (
        reg.execute(
            "poison", {"target": "x"}, _ctx(), authorized=True, allow_exploitation=True
        ).status
        == "success"
    )


def test_exploitation_tools_only_bound_to_exploitation_specialist():
    load_all()
    recon = {s.name for s in specialist_specs("recon", ["recon"], REGISTRY)}
    web = {s.name for s in specialist_specs("web", ["web", "web_http", "utility"], REGISTRY)}
    exploit = {s.name for s in specialist_specs("exploitation", ["exploitation"], REGISTRY)}
    gated = {"responder_credential_harvest", "install_python_package", "execute_python_script"}
    assert not gated & recon
    assert not gated & web
    assert gated <= exploit
    assert "nmap_scan" in recon  # ordinary tools are untouched


def test_lc_tool_reports_refusal_for_unapproved_exploitation():
    load_all()
    spec = REGISTRY.get("execute_python_script")
    tool = _make_lc_tool(spec, _ctx(), REGISTRY, authorized=True)
    out = tool.invoke({"target": "print(1)"})
    assert "exploitation-class" in out


def test_non_exploitation_specialist_cannot_run_exploitation_tool():
    from pepperspray.graph.build import run_assessment

    calls: list = []
    run_assessment(
        "example.com",
        authorized=True,
        ctx=_ctx(),
        registry=_exploit_registry(calls),
        router=_Router("recon"),
        agent_factory=_CallAllTools,
        interrupt_exploitation=False,
        reflect=False,
        checkpointer=MemorySaver(),
        thread_id="gate-recon",
    )
    assert calls == []


def test_exploitation_specialist_runs_tool_once_allowed_upfront():
    from pepperspray.graph.build import run_assessment

    calls: list = []
    run_assessment(
        "example.com",
        authorized=True,
        ctx=_ctx(),
        registry=_exploit_registry(calls),
        router=_Router("exploitation"),
        agent_factory=_CallAllTools,
        interrupt_exploitation=False,
        reflect=False,
        checkpointer=MemorySaver(),
        thread_id="gate-allowed",
    )
    assert calls == ["example.com"]


def test_exploitation_tool_runs_only_after_hitl_approval():
    from pepperspray.graph.build import resume_after_approval, run_assessment

    calls: list = []
    reg = _exploit_registry(calls)
    cp = MemorySaver()
    kw = dict(registry=reg, agent_factory=_CallAllTools, checkpointer=cp, reflect=False)
    paused = run_assessment(
        "example.com",
        authorized=True,
        ctx=_ctx(),
        router=_Router("exploitation"),
        interrupt_exploitation=True,
        thread_id="gate-hitl",
        **kw,
    )
    assert paused.get("awaiting_approval") == ["exploitation"]
    assert calls == []
    resume_after_approval(_ctx(), "gate-hitl", "approve", router=_Router("exploitation"), **kw)
    assert calls == ["example.com"]


@pytest.mark.parametrize("allow, expected", [(False, []), (True, ["example.com"])])
def test_chain_exploitation_step_needs_explicit_opt_in(allow, expected):
    from pepperspray.graph.chains import run_chain

    calls: list = []
    run_chain(
        "bugbounty_auth_bypass",
        "example.com",
        authorized=True,
        ctx=_ctx(),
        registry=_exploit_registry(calls),
        agent_factory=_CallAllTools,
        allow_exploitation=allow,
    )
    assert calls == expected


def test_mcp_wrapper_requires_allow_exploitation():
    load_all()
    from pepperspray.interfaces.mcp_server import _make_tool_wrapper

    out = _make_tool_wrapper("execute_python_script", _ctx())(target="print(1)", authorized=True)
    assert out["status"] == "failed" and "exploitation-class" in out["error"]


# --- httpx binary name -------------------------------------------------------
def test_httpx_prefers_kali_toolkit_binary(monkeypatch):
    from pepperspray.tools.specs import web

    monkeypatch.setattr(web.shutil, "which", lambda b: "/usr/bin/" + b)
    assert web._httpx({"target": "x"})[0] == "httpx-toolkit"
    monkeypatch.setattr(web.shutil, "which", lambda b: None)
    assert web._httpx({"target": "x"})[0] == "httpx"


# --- CVSS v2 -----------------------------------------------------------------
def test_cvss_v2_is_normalized_for_scoring():
    from pepperspray.tools.cve_intel import extract_cvss, score_exploitability

    metrics = {
        "cvssMetricV2": [
            {
                "cvssData": {
                    "version": "2.0",
                    "accessVector": "NETWORK",
                    "accessComplexity": "LOW",
                    "authentication": "NONE",
                    "baseScore": 10.0,
                },
                "baseSeverity": "HIGH",
                "userInteractionRequired": False,
            }
        ]
    }
    cvss = extract_cvss(metrics)
    assert cvss["baseSeverity"] == "HIGH"
    assert cvss["attackVector"] == "NETWORK"
    assert cvss["privilegesRequired"] == "NONE"
    assert cvss["userInteraction"] == "NONE"
    assert score_exploitability(cvss, "")["exploitability_level"] == "HIGH"


def test_cvss_v3_unchanged():
    from pepperspray.tools.cve_intel import extract_cvss

    v3 = {"attackVector": "NETWORK", "baseSeverity": "critical"}
    out = extract_cvss({"cvssMetricV31": [{"cvssData": v3}]})
    assert out == {"attackVector": "NETWORK", "baseSeverity": "CRITICAL"}


# --- parallel_scan report ----------------------------------------------------
def test_parallel_report_shows_tool_status():
    load_all()
    from pepperspray.graph import parallel

    out = parallel.default_worker({"target": "example.com", "authorized": True}, _ctx())
    entry = out["tool_results"][0]
    assert entry["tool"] == "httpx_probe"
    status = entry["result"]["status"]
    assert status != "?"

    from pepperspray.reporting.report import render_report

    report = render_report({"target": "t", "tool_results": out["tool_results"]})
    assert f"`httpx_probe` → {status}" in report


# --- verify matches on (title, source) ---------------------------------------
def test_verify_annotates_the_finding_that_was_checked():
    web = {"title": "nuclei on example.com", "source": "web"}
    cve = {"title": "nuclei on example.com", "source": "cve"}
    state = {
        "curated_findings": [dict(web), dict(cve)],
        "to_verify": [dict(web)],
        "verify_budget": 1,
    }
    out = verify_node(state, verifier=lambda f, ctx: True)
    by_source = {f["source"]: f for f in out["curated_findings"]}
    assert by_source["web"].get("verified") is True
    assert "verified" not in by_source["cve"]
