from pepperspray.core.executor import SafeCommandExecutor, ToolResult


def _ex():
    return SafeCommandExecutor(default_timeout=10)


def test_runs_echo():
    r = _ex().run("echo", ["echo", "hi"])
    assert isinstance(r, ToolResult)
    assert r.status == "success"
    assert "hi" in r.stdout


def test_missing_binary():
    r = _ex().run("nope", ["definitely_not_a_binary_xyz_123"])
    assert r.status == "unavailable"
    assert r.returncode is None


def test_timeout():
    r = _ex().run("sleep", ["sleep", "5"], timeout=1)
    assert r.status == "timeout"


def test_argv_is_not_shell():
    r = _ex().run("echo", ["echo", "a; whoami"])
    assert r.status == "success"
    assert "a; whoami" in r.stdout
