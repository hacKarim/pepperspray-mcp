from typer.testing import CliRunner

from pepperspray.interfaces import cli

runner = CliRunner()


def test_list_tools_lists_families():
    result = runner.invoke(cli.app, ["list-tools"])
    assert result.exit_code == 0
    assert "recon" in result.stdout and "nmap_scan" in result.stdout


def test_list_tools_filter_family():
    result = runner.invoke(cli.app, ["list-tools", "--family", "cve"])
    assert result.exit_code == 0
    assert "cve_exploitability" in result.stdout
    assert "nmap_scan" not in result.stdout


def test_run_requires_authorization():
    result = runner.invoke(cli.app, ["run", "--target", "example.com"])
    assert result.exit_code != 0
    assert "authoriz" in result.stdout.lower()


def test_run_with_stub(monkeypatch):
    monkeypatch.setattr(cli, "get_llm", lambda *a, **k: object())
    monkeypatch.setattr(
        cli, "run_assessment", lambda **kw: {"report": "# Report for " + kw["target"]}
    )
    result = runner.invoke(cli.app, ["run", "--target", "example.com", "--authorized"])
    assert result.exit_code == 0
    assert "Report for example.com" in result.stdout


def test_run_surfaces_exploitation_pause(monkeypatch):
    monkeypatch.setattr(cli, "get_llm", lambda *a, **k: object())
    monkeypatch.setattr(
        cli,
        "run_assessment",
        lambda **kw: {"report": "# partial", "awaiting_approval": ["exploitation"]},
    )
    result = runner.invoke(cli.app, ["run", "--target", "t", "--authorized"])
    assert result.exit_code == 0
    assert "Paused before exploitation" in result.stdout
    assert "--allow-exploitation" in result.stdout


def test_run_stream_prints_steps_and_report(monkeypatch):
    monkeypatch.setattr(cli, "get_llm", lambda *a, **k: object())

    def fake_stream(**kw):
        yield {"type": "step", "node": "recon", "completed": ["recon"], "findings_delta": 2}
        yield {"type": "report", "report": "# Report for " + kw["target"], "state": {}}

    monkeypatch.setattr(cli, "stream_assessment", fake_stream)
    result = runner.invoke(cli.app, ["run", "--target", "example.com", "--authorized", "--stream"])
    assert result.exit_code == 0
    assert "→ recon" in result.stdout
    assert "+2 findings" in result.stdout
    assert "Report for example.com" in result.stdout


def test_run_stream_shows_approval_pause(monkeypatch):
    monkeypatch.setattr(cli, "get_llm", lambda *a, **k: object())

    def fake_stream(**kw):
        yield {"type": "step", "node": "recon", "completed": ["recon"], "findings_delta": 0}
        yield {
            "type": "approval",
            "request": {"action": "exploitation", "message": "Approve?"},
            "awaiting": ["exploitation"],
        }

    monkeypatch.setattr(cli, "stream_assessment", fake_stream)
    result = runner.invoke(cli.app, ["run", "--target", "t", "--authorized", "--stream"])
    assert result.exit_code == 0
    assert "Paused before exploitation" in result.stdout
    assert "resume" in result.stdout.lower()


def test_resume_requires_checkpoint_db(monkeypatch):
    import pepperspray.config as cfg

    monkeypatch.setattr(cli, "get_settings", lambda: cfg.Settings(checkpoint_db=None))
    monkeypatch.setattr(cli, "get_llm", lambda *a, **k: object())
    result = runner.invoke(cli.app, ["resume", "some-thread"])
    assert result.exit_code == 2
    assert "CHECKPOINT_DB" in result.stdout


def test_history_handles_empty(monkeypatch):
    import pepperspray.config as cfg

    monkeypatch.setattr(cli, "get_settings", lambda: cfg.Settings(checkpoint_db=None))
    result = runner.invoke(cli.app, ["history", "nope-thread"])
    assert result.exit_code == 0
    assert "No checkpoints" in result.stdout
