import pytest

from pepperspray.core.registry import ToolRegistry
from pepperspray.tools.specs import binary


@pytest.fixture
def reg():
    r = ToolRegistry()
    binary.register(r)
    return r


def test_registers_all(reg):
    assert len(reg.all()) == len(binary._SHELL_SPECS) == 16
    assert len(reg.by_family("binary")) == 16


def test_all_passive_and_cacheable(reg):
    for spec in reg.by_family("binary"):
        assert spec.active is False
        assert spec.cacheable is True


def test_every_builder_injection_safe(reg):
    hostile = "x; id && whoami"
    keys = ["binary", "file_path", "libc_path", "commands", "search_string"]
    for spec in reg.all():
        argv = spec.build_argv({k: hostile for k in keys})
        assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
        for a in argv:
            if "whoami" in a or "; id" in a:
                assert a == hostile, (spec.name, a)


def test_strings_argv_shape(reg):
    argv = reg.get("strings_extract").build_argv({"file_path": "/bin/ls", "min_len": 8})
    assert argv[:3] == ["strings", "-n", "8"]
    assert argv[-1] == "/bin/ls"


def test_checksec_argv_shape(reg):
    argv = reg.get("checksec_analyze").build_argv({"binary": "/bin/ls"})
    assert argv == ["checksec", "--file", "/bin/ls"]
