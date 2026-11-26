"""LangSmith tracing: opt-in configuration and per-run trace metadata."""

import pepperspray.config as config_mod
from pepperspray.config import Settings
from pepperspray.obs import configure_tracing, trace_config


def test_configure_tracing_disabled_by_default(monkeypatch):
    monkeypatch.delenv("LANGCHAIN_TRACING_V2", raising=False)
    enabled = configure_tracing(Settings(langsmith_tracing=False))
    assert enabled is False
    # It must not force tracing on when disabled.
    import os

    assert os.environ.get("LANGCHAIN_TRACING_V2") != "true"


def test_configure_tracing_enables_env(monkeypatch):
    for var in ("LANGCHAIN_TRACING_V2", "LANGCHAIN_PROJECT", "LANGCHAIN_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    enabled = configure_tracing(
        Settings(
            langsmith_tracing=True,
            langsmith_project="pepperspray-test",
            langsmith_api_key="secret-key",
        )
    )
    import os

    assert enabled is True
    assert os.environ["LANGCHAIN_TRACING_V2"] == "true"
    assert os.environ["LANGCHAIN_PROJECT"] == "pepperspray-test"
    assert os.environ["LANGCHAIN_API_KEY"] == "secret-key"


def test_trace_config_is_opt_in():
    assert trace_config("example.com", "recon", "t1", enabled=False) == {}


def test_trace_config_carries_metadata_when_enabled():
    cfg = trace_config("example.com", "recon", "t1", enabled=True)
    assert "pepperspray" in cfg["tags"]
    assert cfg["metadata"]["target"] == "example.com"
    assert cfg["metadata"]["thread_id"] == "t1"
    assert "example.com" in cfg["run_name"]


def test_settings_tracing_defaults_off():
    # The config singleton field exists and defaults to off (no surprise traces).
    assert config_mod.Settings().langsmith_tracing is False
