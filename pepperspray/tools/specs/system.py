"""System / introspection tool specs: health, cache stats, telemetry, and
process listing. These operate on local state only (never a remote target).
"""

from __future__ import annotations

import json

import psutil

from pepperspray.core.executor import ToolResult
from pepperspray.core.registry import REGISTRY, ToolContext, ToolRegistry, ToolSpec


def _ok(name: str, payload) -> ToolResult:
    return ToolResult(
        tool=name, status="success", stdout=json.dumps(payload, indent=2, default=str)
    )


def _run_health(params: dict, ctx: ToolContext) -> ToolResult:
    return _ok(
        "server_health",
        {
            "status": "healthy",
            "tool_count": len(REGISTRY.all()),
            "families": REGISTRY.families(),
        },
    )


def _run_cache_stats(params: dict, ctx: ToolContext) -> ToolResult:
    cache = ctx.cache
    return _ok(
        "get_cache_stats",
        {
            "size": len(getattr(cache, "_cache", {})),
            "maxsize": getattr(getattr(cache, "_cache", None), "maxsize", None),
        },
    )


def _run_clear_cache(params: dict, ctx: ToolContext) -> ToolResult:
    inner = getattr(ctx.cache, "_cache", None)
    if inner is not None:
        inner.clear()
    return _ok("clear_cache", {"cleared": True})


def _run_telemetry(params: dict, ctx: ToolContext) -> ToolResult:
    return _ok(
        "get_telemetry",
        {
            "cpu_percent": psutil.cpu_percent(interval=0.0),
            "memory_percent": psutil.virtual_memory().percent,
            "tool_count": len(REGISTRY.all()),
        },
    )


def _run_list_processes(params: dict, ctx: ToolContext) -> ToolResult:
    procs = []
    for p in psutil.process_iter(["pid", "name", "status"]):
        try:
            procs.append(p.info)
        except psutil.Error:
            continue
    return _ok("list_active_processes", {"count": len(procs), "processes": procs[:50]})


def _run_process_status(params: dict, ctx: ToolContext) -> ToolResult:
    pid = params.get("pid")
    try:
        p = psutil.Process(int(pid))
        info = {"pid": p.pid, "name": p.name(), "status": p.status()}
    except (psutil.Error, ValueError, TypeError) as exc:
        return ToolResult(tool="get_process_status", status="failed", error=str(exc))
    return _ok("get_process_status", info)


def _run_dashboard(params: dict, ctx: ToolContext) -> ToolResult:
    return _ok(
        "get_process_dashboard",
        {
            "cpu_percent": psutil.cpu_percent(interval=0.0),
            "memory_percent": psutil.virtual_memory().percent,
            "process_count": len(psutil.pids()),
        },
    )


_SYS_SPECS = [
    ("server_health", _run_health, "Framework health and tool count"),
    ("get_cache_stats", _run_cache_stats, "Result-cache statistics"),
    ("clear_cache", _run_clear_cache, "Clear the result cache"),
    ("get_telemetry", _run_telemetry, "Host CPU/memory telemetry"),
    ("list_active_processes", _run_list_processes, "List running processes"),
    ("get_process_status", _run_process_status, "Status of a given PID"),
    ("get_process_dashboard", _run_dashboard, "Process/resource dashboard"),
]


def register(registry: ToolRegistry = REGISTRY) -> None:
    for name, fn, desc in _SYS_SPECS:
        registry.register(
            ToolSpec(name=name, family="system", executor_kind="python", run=fn, description=desc)
        )


register()
