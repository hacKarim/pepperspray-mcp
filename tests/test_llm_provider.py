import pytest

from pepperspray.llm import provider as p


def _settings(**kw):
    class S:
        llm_provider = kw.get("llm_provider", "anthropic")
        model = kw.get("model", "claude-opus-4-8")
        anthropic_api_key = kw.get("anthropic_api_key", None)
        openai_api_key = kw.get("openai_api_key", None)
        ollama_base_url = "http://localhost:11434"

    return S()


def test_unknown_provider_raises(monkeypatch):
    monkeypatch.setattr(p, "get_settings", lambda: _settings(llm_provider="bogus"))
    with pytest.raises(p.ConfigurationError):
        p.get_llm()


def test_anthropic_missing_key_raises(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(p, "get_settings", lambda: _settings(anthropic_api_key=None))
    with pytest.raises(p.ConfigurationError):
        p.get_llm()


def test_returns_chat_model(monkeypatch):
    monkeypatch.setattr(p, "get_settings", lambda: _settings(anthropic_api_key="sk-x"))
    sentinel = object()
    monkeypatch.setattr(p, "_build_anthropic", lambda s, **kw: sentinel)
    assert p.get_llm() is sentinel
