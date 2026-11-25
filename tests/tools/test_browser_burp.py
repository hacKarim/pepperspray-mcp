import httpx

from pepperspray.core.cache import ResultCache
from pepperspray.core.executor import SafeCommandExecutor
from pepperspray.core.registry import ToolContext
from pepperspray.tools.specs import browser, http_framework


def _ctx():
    return ToolContext(executor=SafeCommandExecutor(5), cache=ResultCache(10, 100))


# --- browser_agent_inspect ---------------------------------------------------
def test_browser_tool_registered():
    from pepperspray.core.registry import ToolRegistry

    r = ToolRegistry()
    browser.register(r)
    spec = r.get("browser_agent_inspect")
    assert spec.active is True and spec.executor_kind == "python"


def test_browser_inspect_graceful_without_playwright(monkeypatch):
    # Force the lazy import to fail -> must return a structured 'unavailable', not crash.
    monkeypatch.setattr(browser, "_load_playwright", lambda: None)
    out = browser.inspect({"url": "https://example.com"}, _ctx())
    assert out.status == "unavailable"
    assert "playwright" in (out.error or "").lower()


def test_browser_inspect_parses_page(monkeypatch):
    class _Page:
        url = "https://example.com/final"

        def goto(self, url, **kw):
            class R:
                status = 200

            return R()

        def title(self):
            return "Example Domain"

        def eval_on_selector_all(self, sel, js):
            return 3 if "a" in sel else 1

        def content(self):
            return "<html></html>"

    class _Browser:
        def new_page(self):
            return _Page()

        def close(self):
            pass

    class _Chromium:
        def launch(self, headless=True):
            return _Browser()

    class _PW:
        chromium = _Chromium()

        def stop(self):
            pass

    monkeypatch.setattr(browser, "_load_playwright", lambda: (lambda: _PW()))
    out = browser.inspect({"url": "https://example.com"}, _ctx())
    assert out.status == "success"
    assert "Example Domain" in out.stdout
    assert "final" in out.stdout


# --- burpsuite_scan (real Burp REST API) -------------------------------------
def test_burpsuite_scan_posts_to_rest_api(monkeypatch):
    posted = {}

    def fake_post(url, **kw):
        posted["url"] = url
        posted["json"] = kw.get("json")
        return httpx.Response(
            201, headers={"Location": "/v0.1/scan/42"}, request=httpx.Request("POST", url)
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    out = http_framework._run_burpsuite_scan(
        {"url": "https://t.example", "api_url": "http://127.0.0.1:1337"}, _ctx()
    )
    assert out.status == "success"
    assert "/v0.1/scan" in posted["url"]
    assert posted["json"]["urls"] == ["https://t.example"]
    assert "42" in out.stdout


def test_burpsuite_scan_graceful_when_burp_down(monkeypatch):
    def fake_post(url, **kw):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(httpx, "post", fake_post)
    out = http_framework._run_burpsuite_scan({"url": "https://t"}, _ctx())
    assert out.status == "failed"
