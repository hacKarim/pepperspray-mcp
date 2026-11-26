"""Headless-browser inspection (``browser_agent_inspect``).

Loads a URL in a real headless Chromium via Playwright and reports the page
title, final URL, HTTP status, and link/form counts. Playwright is optional:
if it is not installed the tool returns a structured ``unavailable`` result
rather than crashing. For authorized testing only.
"""

from __future__ import annotations

import json
from typing import Callable

from pepperspray.core.executor import ToolResult
from pepperspray.core.registry import REGISTRY, ToolContext, ToolRegistry, ToolSpec


def _load_playwright() -> Callable | None:
    """Return a context-manager factory for Playwright, or None if unavailable."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None
    return sync_playwright


def inspect(params: dict, ctx: ToolContext) -> ToolResult:
    url = params.get("url") or params.get("target", "")
    if not url:
        return ToolResult(tool="browser_agent_inspect", status="failed", error="url required")

    factory = _load_playwright()
    if factory is None:
        return ToolResult(
            tool="browser_agent_inspect",
            status="unavailable",
            error="playwright is not installed (pip install playwright && playwright install chromium)",
        )

    wait_ms = int(params.get("wait_time", 5)) * 1000
    try:
        pw = factory()
        # sync_playwright() returns a context manager; support both that and a
        # pre-started object (tests inject the latter).
        pw = pw.__enter__() if hasattr(pw, "__enter__") else pw
        browser = pw.chromium.launch(headless=bool(params.get("headless", True)))
        page = browser.new_page()
        response = page.goto(url, timeout=wait_ms or 30000)
        info = {
            "url": url,
            "final_url": getattr(page, "url", url),
            "status_code": getattr(response, "status", None),
            "title": page.title(),
            "links": page.eval_on_selector_all("a", "els => els.length"),
            "forms": page.eval_on_selector_all("form", "els => els.length"),
        }
        browser.close()
        if hasattr(pw, "stop"):
            pw.stop()
    except Exception as exc:  # noqa: BLE001 - browser automation surfaces many errors
        return ToolResult(tool="browser_agent_inspect", status="failed", error=str(exc))

    return ToolResult(
        tool="browser_agent_inspect", status="success", stdout=json.dumps(info, indent=2)
    )


def register(registry: ToolRegistry = REGISTRY) -> None:
    registry.register(
        ToolSpec(
            name="browser_agent_inspect",
            family="web_http",
            executor_kind="python",
            run=inspect,
            active=True,
            description="Headless-browser page inspection (title, links, forms, status)",
        )
    )


register()
