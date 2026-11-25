import pytest

from pepperspray.core.registry import ToolRegistry
from pepperspray.tools.specs import offense


@pytest.fixture
def reg():
    r = ToolRegistry()
    offense.register(r)
    return r


def _count(family):
    return len([s for s in offense._SHELL_SPECS if s[1] == family])


def test_registers_all_offense_tools(reg):
    assert len(reg.all()) == len(offense._SHELL_SPECS)


def test_exploitation_family_count(reg):
    assert len(reg.by_family("exploitation")) == 8


def test_binary_family_count(reg):
    # 16 local-file binary-analysis tools.
    assert len(reg.by_family("binary")) == _count("binary") == 16


def test_all_exploitation_active_and_flagged(reg):
    for spec in reg.by_family("exploitation"):
        assert spec.active is True
        assert spec.exploitation is True
        assert spec.cacheable is False


def test_all_binary_passive_and_cacheable(reg):
    for spec in reg.by_family("binary"):
        assert spec.active is False
        assert spec.cacheable is True


def test_every_builder_injection_safe(reg):
    # A hostile param must stay a single argv element, never split into tokens.
    hostile = "x; id && whoami"
    keys = ["target", "url", "binary", "file", "options",
            "file_path", "libc_path"]
    for spec in reg.all():
        params = {k: hostile for k in keys}
        argv = spec.build_argv(params)
        assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
        # the hostile value, when present, is exactly one element (not shell-split)
        assert "; id" not in " ".join(a for a in argv if a != hostile) or hostile in argv


def test_sqlmap_argv_shape(reg):
    argv = reg.get("sqlmap_scan").build_argv({"url": "http://t/?id=1", "data": "a=b"})
    assert argv[0] == "sqlmap"
    assert argv[1:3] == ["-u", "http://t/?id=1"]
    assert "--batch" in argv
    assert "--data=a=b" in argv


def test_msfvenom_argv_shape(reg):
    argv = reg.get("msfvenom_generate").build_argv(
        {"payload": "linux/x86/meterpreter/reverse_tcp", "format": "elf", "encoder": "x86/shikata_ga_nai"})
    assert argv[:3] == ["msfvenom", "-p", "linux/x86/meterpreter/reverse_tcp"]
    assert "-f" in argv and "elf" in argv
    assert "-e" in argv and "x86/shikata_ga_nai" in argv


def test_strings_argv_shape(reg):
    argv = reg.get("strings_extract").build_argv({"file_path": "/bin/ls", "min_len": 8})
    assert argv[0] == "strings"
    assert argv[1:3] == ["-n", "8"]
    assert argv[-1] == "/bin/ls"


def test_metasploit_writes_resource_file(reg):
    argv = reg.get("metasploit_run").build_argv(
        {"module": "exploit/multi/handler", "options": {"LHOST": "10.0.0.1"}})
    assert argv[:3] == ["msfconsole", "-q", "-r"]
    with open(argv[3]) as fh:
        content = fh.read()
    assert "use exploit/multi/handler" in content
    assert "set LHOST 10.0.0.1" in content


def test_pacu_stdin_sequence(reg):
    spec = reg.get("pacu_exploitation")
    stdin = spec.build_input({"session_name": "s1", "modules": "iam__enum_users,ec2__enum"})
    assert stdin.splitlines()[0] == "set_session s1"
    assert "run iam__enum_users" in stdin
    assert "run ec2__enum" in stdin
    assert stdin.splitlines()[-1] == "exit"
    assert spec.build_argv({})[0] == "pacu"
