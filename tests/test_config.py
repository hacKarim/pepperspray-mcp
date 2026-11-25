import importlib


def test_settings_defaults_and_env_override(monkeypatch):
    monkeypatch.delenv("PEPPERSPRAY_MODEL", raising=False)
    import pepperspray.config as cfg

    importlib.reload(cfg)
    cfg.get_settings.cache_clear()
    s = cfg.get_settings()
    assert s.llm_provider == "anthropic"
    assert s.command_timeout == 300

    monkeypatch.setenv("PEPPERSPRAY_MODEL", "foo-model")
    cfg.get_settings.cache_clear()
    s2 = cfg.get_settings()
    assert s2.model == "foo-model"
