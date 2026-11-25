import pytest

from pepperspray.core.registry import ToolRegistry
from pepperspray.tools.specs import cloud_forensics


@pytest.fixture
def reg():
    r = ToolRegistry()
    cloud_forensics.register(r)
    return r


def test_registers_all_tools(reg):
    assert len(reg.by_family("cloud")) == 11
    assert len(reg.by_family("forensics")) == 5
    assert len(reg.all()) == len(cloud_forensics._SHELL_SPECS) == 16


def test_cloud_tools_active(reg):
    assert all(s.active for s in reg.by_family("cloud"))


def test_forensics_tools_not_active(reg):
    assert all(not s.active for s in reg.by_family("forensics"))


def test_all_cacheable(reg):
    assert all(s.cacheable for s in reg.all())


def test_every_builder_injection_safe(reg):
    # A hostile param must stay a single argv element, never split into tokens
    # and never concatenated into a flag.
    hostile = "x; id && whoami"
    params = {
        "target": hostile,
        "file": hostile,
        "account": hostile,
        "directory": hostile,
        # real per-tool user-value keys, all set hostile for coverage
        "image": hostile,
        "memory_file": hostile,
        "input_file": hostile,
        "cover_file": hostile,
        "file_path": hostile,
        "iac_dir": hostile,
        "plugin": hostile,
        "embed_file": hostile,
    }
    for spec in reg.all():
        argv = spec.build_argv(dict(params))
        assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
        # Wherever the hostile value surfaces it is exactly one argv element,
        # never shell-split and never fused onto a flag token.
        for a in argv:
            if "whoami" in a or "; id" in a:
                assert a == hostile, (spec.name, a)


def test_trivy_argv_shape(reg):
    argv = reg.get("trivy_scan").build_argv({"target": "alpine:3.19"})
    assert argv[:3] == ["trivy", "image", "alpine:3.19"]
    assert "--format" in argv and "json" in argv


def test_prowler_argv_shape(reg):
    argv = reg.get("prowler_scan").build_argv({})
    assert argv[:2] == ["prowler", "aws"]
    assert "--output-format" in argv and "json" in argv


def test_volatility3_argv_shape(reg):
    argv = reg.get("volatility3_analyze").build_argv(
        {"memory_file": "/cases/mem.raw", "plugin": "windows.pslist"}
    )
    assert argv == ["vol", "-f", "/cases/mem.raw", "windows.pslist"]
