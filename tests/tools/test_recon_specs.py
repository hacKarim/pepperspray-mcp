import pytest

from pepperspray.core.registry import ToolRegistry
from pepperspray.tools.specs import recon


@pytest.fixture
def reg():
    r = ToolRegistry()
    recon.register(r)
    return r


def test_registers_all_recon_tools(reg):
    assert len(reg.by_family("recon")) == len(recon._SHELL_SPECS)


def test_every_builder_injection_safe(reg):
    # A hostile param must stay a single argv element, never split into tokens.
    hostile = "x; id && whoami"
    for spec in reg.by_family("recon"):
        argv = spec.build_argv({"target": hostile, "domain": hostile, "url": hostile,
                                "user": hostile, "interface": "eth0"})
        assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
        # the hostile value, when present, is exactly one element (not shell-split)
        assert "; id" not in " ".join(a for a in argv if a != hostile) or hostile in argv


def test_nmap_argv_shape(reg):
    argv = reg.get("nmap_scan").build_argv({"target": "scanme.org", "ports": "80,443"})
    assert argv[0] == "nmap" and "scanme.org" == argv[-1] and "-p" in argv and "80,443" in argv


def test_katana_argv(reg):
    argv = reg.get("katana_crawl").build_argv({"url": "http://t", "depth": 2})
    assert argv[:5] == ["katana", "-u", "http://t", "-d", "2"]


def test_hakrawler_stdin(reg):
    spec = reg.get("hakrawler_crawl")
    assert spec.build_input({"url": "http://t"}) == "http://t"
    assert spec.build_argv({"depth": 2})[0] == "hakrawler"


def test_all_recon_active(reg):
    assert all(s.active for s in reg.by_family("recon"))
