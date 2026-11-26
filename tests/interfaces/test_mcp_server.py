from pepperspray.core.cache import ResultCache
from pepperspray.core.executor import SafeCommandExecutor
from pepperspray.core.registry import ToolContext
from pepperspray.interfaces import mcp_server as ms
from pepperspray.tools import load_all


def _ctx():
    return ToolContext(executor=SafeCommandExecutor(5), cache=ResultCache(10, 100))


def test_iter_mcp_tools_covers_registry_plus_highlevel():
    load_all()
    from pepperspray.core.registry import REGISTRY

    entries = list(ms.iter_mcp_tools(_ctx()))
    names = {name for name, _desc, _fn in entries}
    # every registry tool exposed, plus high-level entrypoints
    assert {s.name for s in REGISTRY.all()} <= names
    assert {"run_assessment", "run_chain", "list_tools"} <= names
    assert len(entries) == len(REGISTRY.all()) + len(ms.HIGH_LEVEL)


def test_individual_tool_wrapper_invokes_registry():
    load_all()
    entries = {name: fn for name, _d, fn in ms.iter_mcp_tools(_ctx())}
    # a pure-python tool that needs no binary: jwt_analyzer
    out = entries["jwt_analyzer"](target="", extra="")
    assert isinstance(out, dict) and "status" in out


def test_build_mcp_constructs():
    load_all()
    server = ms.build_mcp(_ctx())
    assert server is not None
