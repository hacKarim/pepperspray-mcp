"""Observability: opt-in LangSmith tracing for the assessment graph.

LangChain/LangGraph emit traces to LangSmith automatically when the standard
``LANGCHAIN_*`` environment variables are set. Tracing is **off by default** and
only enabled when ``PEPPERSPRAY_LANGSMITH_TRACING`` is true — so no target or
run data leaves the host unless the operator asks for it. When enabled,
``trace_config`` attaches a run name, tags and metadata so runs are findable in
the LangSmith UI.
"""

from __future__ import annotations

import os
from typing import Any


def configure_tracing(settings: Any = None) -> bool:
    """Enable LangSmith tracing from settings. Returns whether it was enabled."""
    if settings is None:
        from pepperspray.config import get_settings

        settings = get_settings()

    if not getattr(settings, "langsmith_tracing", False):
        return False

    os.environ["LANGCHAIN_TRACING_V2"] = "true"
    os.environ["LANGCHAIN_PROJECT"] = settings.langsmith_project
    if settings.langsmith_api_key:
        os.environ.setdefault("LANGCHAIN_API_KEY", settings.langsmith_api_key)
    return True


def trace_config(
    target: str,
    objective: str,
    thread_id: str,
    run_name: str | None = None,
    enabled: bool | None = None,
) -> dict:
    """Run-config additions (run_name/tags/metadata) for a traced run.

    Returns an empty dict unless tracing is enabled, so it can be merged into
    the graph config unconditionally without leaking metadata when tracing off.
    """
    if enabled is None:
        from pepperspray.config import get_settings

        enabled = getattr(get_settings(), "langsmith_tracing", False)
    if not enabled:
        return {}

    return {
        "run_name": run_name or f"assessment:{target}",
        "tags": ["pepperspray", objective],
        "metadata": {"target": target, "objective": objective, "thread_id": thread_id},
    }
