import pytest

from pepperspray.core.cache import ResultCache
from pepperspray.core.errors import AuthorizationError, classify_error
from pepperspray.core.executor import SafeCommandExecutor
from pepperspray.core.registry import ToolContext, ToolRegistry, ToolSpec


def _ctx():
    return ToolContext(
        executor=SafeCommandExecutor(default_timeout=10),
        cache=ResultCache(maxsize=10, ttl=100),
    )


def test_register_and_get():
    reg = ToolRegistry()
    spec = ToolSpec(name="t", family="recon", executor_kind="shell",
                    build_argv=lambda p: ["echo", p["x"]])
    reg.register(spec)
    assert reg.get("t") is spec
    assert reg.by_family("recon") == [spec]


def test_execute_shell_builds_argv():
    reg = ToolRegistry()
    reg.register(ToolSpec(name="t", family="recon", executor_kind="shell",
                          build_argv=lambda p: ["echo", p["x"]]))
    r = reg.execute("t", {"x": "hi"}, _ctx(), authorized=True)
    assert r.status == "success" and "hi" in r.stdout


def test_execute_active_unauthorized_raises():
    reg = ToolRegistry()
    reg.register(ToolSpec(name="scan", family="recon", executor_kind="shell",
                          active=True, build_argv=lambda p: ["echo", "x"]))
    with pytest.raises(AuthorizationError):
        reg.execute("scan", {}, _ctx(), authorized=False)


def test_argv_injection_is_arg():
    reg = ToolRegistry()
    reg.register(ToolSpec(name="t", family="recon", executor_kind="shell",
                          build_argv=lambda p: ["echo", p["x"]]))
    r = reg.execute("t", {"x": "a; id"}, _ctx(), authorized=True)
    assert "a; id" in r.stdout


def test_cache_hit_skips_second_run():
    reg = ToolRegistry()
    calls = {"n": 0}

    def build(p):
        calls["n"] += 1
        return ["echo", "x"]

    reg.register(ToolSpec(name="t", family="recon", executor_kind="shell",
                          cacheable=True, build_argv=build))
    ctx = _ctx()
    reg.execute("t", {"a": 1}, ctx, authorized=True)
    reg.execute("t", {"a": 1}, ctx, authorized=True)
    assert calls["n"] == 1  # second call served from cache


def test_classify_error_known():
    assert classify_error("command not found", 127) == "tool_not_found"
    assert classify_error("Connection timed out", 1) == "timeout"
