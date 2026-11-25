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
