"""Regression tests for whole-branch review findings."""

from pepperspray.core.cache import ResultCache
from pepperspray.core.executor import SafeCommandExecutor
from pepperspray.core.registry import ToolContext, spread_target
from pepperspray.tools import load_all


def _ctx():
    return ToolContext(executor=SafeCommandExecutor(5), cache=ResultCache(10, 100))


# --- Finding #1: file/path params reach binary/forensics/cloud tools ---------
def test_spread_target_populates_file_keys():
    p = spread_target("/bin/ls", extra="-n 8")
    assert p["file_path"] == "/bin/ls"
    assert p["memory_file"] == "/bin/ls"
    assert p["additional_args"] == "-n 8"


def test_binary_tool_gets_filepath_via_spread():
    load_all()
    from pepperspray.core.registry import REGISTRY

    argv = REGISTRY.get("strings_extract").build_argv(spread_target("/bin/ls"))
    assert "/bin/ls" in argv
    assert "" not in argv  # no empty trailing positional


def test_mcp_wrapper_maps_target_to_filepath():
    load_all()
    from pepperspray.interfaces import mcp_server as ms

    entries = {n: fn for n, _d, fn in ms.iter_mcp_tools(_ctx())}
    out = entries["strings_extract"](target="/bin/ls", authorized=True)
    assert "/bin/ls" in out.get("argv", [])


# --- Finding #2: httpx_probe builds a usable command -------------------------
def test_httpx_probe_uses_single_host_not_file_flag():
    load_all()
    from pepperspray.core.registry import REGISTRY

    argv = REGISTRY.get("httpx_probe").build_argv(spread_target("example.com"))
    assert "-l" not in argv  # -l reads a FILE of targets; wrong for a single host
    assert "example.com" in argv


# --- Finding #4: a leading-dash target is refused, not passed as an option ---
def test_leading_dash_target_is_refused():
    load_all()
    from pepperspray.core.registry import REGISTRY

    # A target that is really an option (e.g. nmap --script=...) must not run.
    result = REGISTRY.execute("nmap_scan", spread_target("--script=evil"), _ctx(), authorized=True)
    assert result.status == "failed"
    assert "option" in (result.error or "").lower()


def test_normal_target_still_runs():
    load_all()
    from pepperspray.core.registry import REGISTRY

    # A normal hostname must NOT be rejected by the guard.
    r = REGISTRY.execute("nmap_scan", spread_target("scanme.nmap.org"), _ctx(), authorized=True)
    assert r.status in {"success", "failed", "timeout", "unavailable"}
    assert "looks like an option" not in (r.error or "")


# --- Finding #6: pip/exec gated behind the exploitation HITL interrupt -------
def test_dangerous_python_tools_are_exploitation_gated():
    load_all()
    from pepperspray.core.registry import REGISTRY

    assert REGISTRY.get("install_python_package").exploitation is True
    assert REGISTRY.get("execute_python_script").exploitation is True


# --- Finding #3: HITL interrupt surfaces a report + approval marker ----------
class _ExploitRouter:
    def __init__(self):
        self.n = 0

    def __call__(self, state):
        from pepperspray.agents.supervisor import Route

        self.n += 1
        return Route(next="exploitation" if self.n == 1 else "FINISH")


class _FakeAgent:
    def __init__(self, llm, tools):
        self.tools = tools

    def invoke(self, inputs):
        from langchain_core.messages import AIMessage

        return {"messages": list(inputs["messages"]) + [AIMessage(content="done")]}


def test_hitl_pause_surfaces_report_and_marker():
    load_all()
    from pepperspray.graph.build import run_assessment

    final = run_assessment(
        "example.com",
        objective="exploit",
        authorized=True,
        ctx=_ctx(),
        router=_ExploitRouter(),
        agent_factory=_FakeAgent,
        interrupt_exploitation=True,
        thread_id="hitl-pause",
    )
    assert final.get("awaiting_approval") == ["exploitation"]
    assert final.get("report")  # partial report, not an empty None


def test_allow_exploitation_runs_to_completion():
    load_all()
    from pepperspray.graph.build import run_assessment

    final = run_assessment(
        "example.com",
        objective="exploit",
        authorized=True,
        ctx=_ctx(),
        router=_ExploitRouter(),
        agent_factory=_FakeAgent,
        interrupt_exploitation=False,
        thread_id="hitl-run",
    )
    assert not final.get("awaiting_approval")
    assert final.get("report") and "example.com" in final["report"]
