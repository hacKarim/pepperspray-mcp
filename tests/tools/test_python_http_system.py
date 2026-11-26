import types

import httpx

from pepperspray.core.cache import ResultCache
from pepperspray.core.executor import SafeCommandExecutor
from pepperspray.core.registry import ToolContext, ToolRegistry
from pepperspray.tools.specs import http_framework, python_tools, system


def _ctx(tmp_path=None):
    settings = types.SimpleNamespace(results_dir=str(tmp_path)) if tmp_path else None
    return ToolContext(
        executor=SafeCommandExecutor(10), cache=ResultCache(10, 100), settings=settings
    )


def test_jwt_decode_and_alg_none():
    # header {"alg":"none"}, payload {"user":"admin"}
    out = python_tools.analyze_jwt("eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.")
    assert out["valid_structure"] is True
    assert out["algorithm"] == "none"
    assert any(v["type"] == "alg_none" for v in out["vulnerabilities"])


def test_jwt_bad_structure():
    assert python_tools.analyze_jwt("notajwt")["valid_structure"] is False


def test_file_ops_sandboxed(tmp_path):
    ctx = _ctx(tmp_path)
    reg = ToolRegistry()
    python_tools.register(reg)
    r = reg.execute("create_file", {"path": "a/b.txt", "content": "hi"}, ctx, authorized=True)
    assert r.status == "success"
    # escape attempt rejected
    bad = reg.execute(
        "create_file", {"path": "../escape.txt", "content": "x"}, ctx, authorized=True
    )
    assert bad.status == "failed"


def test_generate_payload():
    out = python_tools.generate_payload("sqli")
    assert out["type"] == "sqli" and out["payloads"]


def test_install_package_is_active():
    reg = ToolRegistry()
    python_tools.register(reg)
    assert reg.get("install_python_package").active is True


def test_http_repeater_mocked(monkeypatch):
    def fake_request(method, url, **kw):
        req = httpx.Request(method, url)
        return httpx.Response(200, text="hello", request=req)

    monkeypatch.setattr(httpx, "request", fake_request)
    ctx = _ctx()
    out = http_framework._run_repeater({"url": "http://t", "method": "GET"}, ctx)
    assert out.status == "success" and "200" in out.stdout


def test_http_intruder_iterates(monkeypatch):
    seen = []

    def fake_request(method, url, **kw):
        seen.append(url)
        return httpx.Response(200, text="x", request=httpx.Request(method, url))

    monkeypatch.setattr(httpx, "request", fake_request)
    out = http_framework._run_intruder({"url": "http://t/FUZZ", "payloads": ["a", "b"]}, _ctx())
    assert out.status == "success"
    assert "http://t/a" in seen and "http://t/b" in seen


def test_system_health_shape():
    reg = ToolRegistry()
    system.register(reg)
    out = reg.execute("server_health", {}, _ctx(), authorized=False)
    assert out.status == "success" and "tool_count" in out.stdout
