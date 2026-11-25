"""HTTP framework tool specs — a lightweight, Burp-like request toolkit built on
httpx (no external proxy). Covers repeater, intruder, scope/rules state, and
simple API/GraphQL probes. For authorized testing only.
"""

from __future__ import annotations

import json

import httpx

from pepperspray.core.executor import ToolResult
from pepperspray.core.registry import REGISTRY, ToolContext, ToolRegistry, ToolSpec

# In-memory session state (scope + rules), per process.
_STATE: dict = {"scope": [], "rules": []}


def _ok(name: str, payload) -> ToolResult:
    return ToolResult(
        tool=name, status="success", stdout=json.dumps(payload, indent=2, default=str)
    )


def _send(method: str, url: str, **kw) -> dict:
    resp = httpx.request(method, url, timeout=kw.pop("timeout", 30), follow_redirects=True, **kw)
    return {
        "status_code": resp.status_code,
        "headers": dict(resp.headers),
        "length": len(resp.content),
        "body": resp.text[:4000],
    }


def _run_repeater(params: dict, ctx: ToolContext) -> ToolResult:
    url = params.get("url", "")
    if not url:
        return ToolResult(tool="http_repeater", status="failed", error="url required")
    try:
        out = _send(
            params.get("method", "GET"),
            url,
            headers=params.get("headers") or {},
            data=params.get("data") or None,
        )
    except httpx.HTTPError as exc:
        return ToolResult(tool="http_repeater", status="failed", error=str(exc))
    return _ok("http_repeater", out)


def _run_intruder(params: dict, ctx: ToolContext) -> ToolResult:
    """Replace FUZZ in the URL with each payload and report status/length."""
    template = params.get("url", "")
    payloads = params.get("payloads") or []
    results = []
    for p in payloads:
        target = template.replace("FUZZ", str(p))
        try:
            r = _send(params.get("method", "GET"), target, headers=params.get("headers") or {})
            results.append({"payload": p, "status_code": r["status_code"], "length": r["length"]})
        except httpx.HTTPError as exc:
            results.append({"payload": p, "error": str(exc)})
    return _ok("http_intruder", {"results": results})


def _run_framework_test(params: dict, ctx: ToolContext) -> ToolResult:
    action = params.get("action", "request")
    if action in ("request", "repeater"):
        return _run_repeater(params, ctx)
    if action == "intruder":
        return _run_intruder(params, ctx)
    return _ok("http_framework_test", {"action": action, "state": _STATE})


def _run_set_scope(params: dict, ctx: ToolContext) -> ToolResult:
    _STATE["scope"] = params.get("scope") or []
    return _ok("http_set_scope", {"scope": _STATE["scope"]})


def _run_set_rules(params: dict, ctx: ToolContext) -> ToolResult:
    _STATE["rules"] = params.get("rules") or []
    return _ok("http_set_rules", {"rules": _STATE["rules"]})


def _run_api_fuzzer(params: dict, ctx: ToolContext) -> ToolResult:
    base = params.get("base_url", "").rstrip("/")
    endpoints = params.get("endpoints") or []
    methods = params.get("methods") or ["GET"]
    results = []
    for ep in endpoints:
        for method in methods:
            url = f"{base}/{str(ep).lstrip('/')}"
            try:
                r = _send(method, url)
                results.append(
                    {
                        "endpoint": ep,
                        "method": method,
                        "status_code": r["status_code"],
                        "length": r["length"],
                    }
                )
            except httpx.HTTPError as exc:
                results.append({"endpoint": ep, "method": method, "error": str(exc)})
    return _ok("api_fuzzer", {"results": results})


_GRAPHQL_INTROSPECTION = {"query": "{__schema{types{name kind}}}"}


def _run_graphql_scanner(params: dict, ctx: ToolContext) -> ToolResult:
    url = params.get("url", "")
    if not url:
        return ToolResult(tool="graphql_scanner", status="failed", error="url required")
    try:
        resp = httpx.post(url, json=_GRAPHQL_INTROSPECTION, timeout=30)
        introspection_enabled = resp.status_code == 200 and "__schema" in resp.text
    except httpx.HTTPError as exc:
        return ToolResult(tool="graphql_scanner", status="failed", error=str(exc))
    return _ok(
        "graphql_scanner",
        {"introspection_enabled": introspection_enabled, "status_code": resp.status_code},
    )


def _run_schema_analyzer(params: dict, ctx: ToolContext) -> ToolResult:
    schema = params.get("schema") or {}
    if isinstance(schema, str):
        try:
            schema = json.loads(schema)
        except json.JSONDecodeError:
            return ToolResult(
                tool="api_schema_analyzer", status="failed", error="invalid schema json"
            )
    paths = list((schema.get("paths") or {}).keys())
    return _ok("api_schema_analyzer", {"path_count": len(paths), "paths": paths[:50]})


_HTTP_SPECS = [
    (
        "http_repeater",
        _run_repeater,
        {"active": True, "description": "Send a single crafted HTTP request"},
    ),
    (
        "http_intruder",
        _run_intruder,
        {"active": True, "description": "Fuzz a FUZZ marker with payloads"},
    ),
    (
        "http_framework_test",
        _run_framework_test,
        {"active": True, "description": "HTTP framework dispatcher"},
    ),
    ("http_set_scope", _run_set_scope, {"description": "Set the testing scope"}),
    ("http_set_rules", _run_set_rules, {"description": "Set match/replace rules"}),
    ("api_fuzzer", _run_api_fuzzer, {"active": True, "description": "Probe API endpoints"}),
    (
        "graphql_scanner",
        _run_graphql_scanner,
        {"active": True, "description": "Check GraphQL introspection"},
    ),
    (
        "api_schema_analyzer",
        _run_schema_analyzer,
        {"description": "Analyze an OpenAPI/GraphQL schema"},
    ),
]


def register(registry: ToolRegistry = REGISTRY) -> None:
    for name, fn, kw in _HTTP_SPECS:
        registry.register(
            ToolSpec(name=name, family="web_http", executor_kind="http", run=fn, **kw)
        )


register()
