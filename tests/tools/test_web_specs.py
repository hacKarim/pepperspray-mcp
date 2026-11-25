import pytest

from pepperspray.core.registry import ToolRegistry
from pepperspray.tools.specs import web


@pytest.fixture
def reg():
    r = ToolRegistry()
    web.register(r)
    return r


def test_registers_all_web_tools(reg):
    assert len(reg.by_family("web")) == len(web._SHELL_SPECS)


def test_all_web_active(reg):
    assert all(s.active for s in reg.by_family("web"))


def test_every_builder_injection_safe(reg):
    # A hostile value in any core param must never be shell-split into loose
    # command fragments; it stays contained inside a single argv element.
    hostile = "x; id && whoami"
    for spec in reg.by_family("web"):
        argv = spec.build_argv({"url": hostile, "target": hostile,
                                "domain": hostile, "data": hostile,
                                "param": hostile})
        assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
        # no loose shell fragment of the payload leaked as its own token
        assert not any(tok in (";", "&&", "id", "whoami") for tok in argv)
        # wherever the value reaches argv it is a single element, verbatim
        for a in argv:
            if "whoami" in a:
                assert hostile in a


def test_gobuster_argv_shape(reg):
    argv = reg.get("gobuster_scan").build_argv({"url": "http://t", "mode": "dir"})
    assert argv[:4] == ["gobuster", "dir", "-u", "http://t"]
    assert "-w" in argv


def test_ffuf_argv_shape(reg):
    argv = reg.get("ffuf_scan").build_argv({"url": "http://t", "mode": "directory"})
    assert argv[0] == "ffuf"
    assert "http://t/FUZZ" in argv  # url+FUZZ stays one token
    assert argv[-2] == "-mc" and argv[-1] == "200,204,301,302,307,401,403"


def test_nuclei_argv_shape(reg):
    argv = reg.get("nuclei_scan").build_argv(
        {"target": "http://t", "severity": "high", "tags": "cve"})
    assert argv[:3] == ["nuclei", "-u", "http://t"]
    assert "-severity" in argv and "high" in argv
    assert "-tags" in argv and "cve" in argv


def test_stdin_tools_pipe_value(reg):
    for name in ("anew_data_processing", "qsreplace_parameter_replacement",
                 "uro_url_filtering"):
        spec = reg.get(name)
        assert spec.build_input({"text": "http://a\nhttp://b"}) == "http://a\nhttp://b"
        assert spec.build_input({"input": "http://c"}) == "http://c"
        # argv is just the binary (+ any additional_args), value flows via stdin
        assert spec.build_argv({"text": "http://a"}) == [spec.binary]
