from pepperspray.core.cache import ResultCache
from pepperspray.core.executor import SafeCommandExecutor
from pepperspray.core.registry import ToolContext
from pepperspray.graph import parallel
from pepperspray.tools import load_all


def _ctx():
    return ToolContext(executor=SafeCommandExecutor(5), cache=ResultCache(10, 100))


def test_fan_out_emits_one_send_per_subtarget():
    sends = parallel.fan_out({"subtargets": ["a.com", "b.com", "c.com"], "authorized": True})
    assert len(sends) == 3
    assert all(s.node == "probe_worker" for s in sends)
    assert {s.arg["target"] for s in sends} == {"a.com", "b.com", "c.com"}


def test_fan_out_falls_back_to_main_target():
    sends = parallel.fan_out({"subtargets": [], "target": "only.com", "authorized": False})
    assert len(sends) == 1
    assert sends[0].arg["target"] == "only.com"


def test_parallel_scan_runs_workers_concurrently_and_reduces():
    load_all()
    seen = []

    def fake_worker(payload, ctx):
        seen.append(payload["target"])
        return {
            "tool_results": [{"tool": "probe", "target": payload["target"], "status": "success"}],
            "findings": [
                {
                    "title": f"host up: {payload['target']}",
                    "severity": "info",
                    "source": "probe",
                    "detail": "",
                }
            ],
        }

    final = parallel.run_parallel_scan(
        "example.com",
        subtargets=["a.com", "b.com", "c.com"],
        authorized=True,
        ctx=_ctx(),
        worker=fake_worker,
    )
    assert set(seen) == {"a.com", "b.com", "c.com"}  # all three ran
    assert len(final["findings"]) == 3  # reducers merged parallel outputs
    assert final.get("report") and "host up: a.com" in final["report"]


def test_probe_worker_executes_registry_tool():
    load_all()
    # default worker runs httpx_probe; binary likely absent -> unavailable, not crash
    out = parallel.default_worker({"target": "example.com", "authorized": True}, _ctx())
    assert "tool_results" in out and "findings" in out
    assert out["tool_results"][0]["tool"] == "httpx_probe"
