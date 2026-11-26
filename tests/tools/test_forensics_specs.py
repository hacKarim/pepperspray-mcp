import pytest

from pepperspray.core.registry import ToolRegistry
from pepperspray.tools.specs import forensics


@pytest.fixture
def reg():
    r = ToolRegistry()
    forensics.register(r)
    return r


def test_registers_all(reg):
    assert len(reg.all()) == len(forensics._SHELL_SPECS) == 5
    assert len(reg.by_family("forensics")) == 5


def test_none_active(reg):
    assert all(not s.active for s in reg.by_family("forensics"))


def test_every_builder_injection_safe(reg):
    hostile = "x; id && whoami"
    keys = ["memory_file", "file", "input_file", "cover_file", "file_path", "plugin", "embed_file"]
    for spec in reg.all():
        argv = spec.build_argv({k: hostile for k in keys})
        assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
        for a in argv:
            if "whoami" in a or "; id" in a:
                assert a == hostile, (spec.name, a)


def test_volatility3_argv_shape(reg):
    argv = reg.get("volatility3_analyze").build_argv(
        {"memory_file": "/cases/mem.raw", "plugin": "windows.pslist"}
    )
    assert argv == ["vol", "-f", "/cases/mem.raw", "windows.pslist"]


def test_steghide_info_has_no_passphrase_flag(reg):
    argv = reg.get("steghide_analysis").build_argv({"action": "info", "cover_file": "a.jpg"})
    assert argv == ["steghide", "info", "a.jpg"]
    assert "-p" not in argv
