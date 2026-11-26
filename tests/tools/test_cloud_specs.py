import pytest

from pepperspray.core.registry import ToolRegistry
from pepperspray.tools.specs import cloud


@pytest.fixture
def reg():
    r = ToolRegistry()
    cloud.register(r)
    return r


def test_registers_all(reg):
    assert len(reg.all()) == len(cloud._SHELL_SPECS) == 11
    assert len(reg.by_family("cloud")) == 11


def test_all_active_and_cacheable(reg):
    for spec in reg.by_family("cloud"):
        assert spec.active is True
        assert spec.cacheable is True


def test_every_builder_injection_safe(reg):
    hostile = "x; id && whoami"
    keys = ["target", "account", "directory", "image", "iac_dir", "file"]
    for spec in reg.all():
        argv = spec.build_argv({k: hostile for k in keys})
        assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
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
