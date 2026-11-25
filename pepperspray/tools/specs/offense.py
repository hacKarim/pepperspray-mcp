"""Offensive tool specs: exploitation + binary analysis.

Two families live here. ``exploitation`` tools actively engage remote targets
(``active=True``, ``exploitation=True``, never cached). ``binary`` tools analyze
*local* files (``active=False``, ``cacheable=True``).

Each ToolSpec builds an argv ``list[str]`` (no shell). Defaults mirror the legacy
Flask command-builders. User values (target/url/binary/file paths, options) are
appended as single argv elements; only free-form ``additional_args`` is tokenized
(via :func:`extra`, which uses shlex). Values are never f-strung into a token.

A few legacy tools wrote a temp script/resource file and invoked an interpreter
on it; those are mirrored here with :func:`tempfile`.

For authorized security testing only.
"""

from __future__ import annotations

import os
import tempfile

from pepperspray.core.registry import REGISTRY, ToolRegistry, ToolSpec
from pepperspray.tools.specs._helpers import extra, flag, opt


def _write_temp(content: str, prefix: str, suffix: str) -> str:
    """Write *content* to a fresh temp file and return its path (mirrors legacy)."""
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=suffix)
    with os.fdopen(fd, "w") as fh:
        fh.write(content if isinstance(content, str) else str(content))
    return path


# --------------------------------------------------------------------------- #
# Family: exploitation
# --------------------------------------------------------------------------- #


def _sqlmap(p: dict) -> list[str]:
    argv = ["sqlmap", "-u", p.get("url", ""), "--batch"]
    data = p.get("data")
    if data:
        argv.append(f"--data={data}")
    argv += extra(p)
    return argv


def _metasploit(p: dict) -> list[str]:
    # Legacy writes a .rc resource file then runs: msfconsole -q -r <file>
    module = p.get("module", "")
    options = p.get("options", {})
    content = f"use {module}\n"
    if isinstance(options, dict):
        for key, value in options.items():
            content += f"set {key} {value}\n"
    path = _write_temp(content, "mcp_msf_resource_", ".rc")
    return ["msfconsole", "-q", "-r", path]


def _msfvenom(p: dict) -> list[str]:
    argv = ["msfvenom", "-p", p.get("payload", "")]
    argv += opt("-f", p.get("format"))
    argv += opt("-o", p.get("output_file"))
    argv += opt("-e", p.get("encoder"))
    argv += opt("-i", p.get("iterations"))
    argv += extra(p)
    return argv


def _hydra(p: dict) -> list[str]:
    argv = ["hydra", "-t", "4"]
    argv += opt("-l", p.get("username"))
    argv += opt("-L", p.get("username_file"))
    argv += opt("-p", p.get("password"))
    argv += opt("-P", p.get("password_file"))
    argv += extra(p)
    argv += [p.get("target", ""), p.get("service", "")]
    return argv


def _pacu_input(p: dict) -> str:
    # Legacy writes a command sequence file and runs `pacu < file`; mirror via stdin.
    session_name = p.get("session_name", "pepperspray_session")
    commands = [f"set_session {session_name}"]
    if p.get("data_services"):
        commands.append(f"data {p['data_services']}")
    if p.get("regions"):
        commands.append(f"set_regions {p['regions']}")
    modules = p.get("modules", "")
    if modules:
        mods = modules.split(",") if isinstance(modules, str) else modules
        for module in mods:
            module = str(module).strip()
            if module:
                commands.append(f"run {module}")
    commands.append("exit")
    return "\n".join(commands)


def _pacu(p: dict) -> list[str]:
    return ["pacu"] + extra(p)


def _john(p: dict) -> list[str]:
    argv = ["john"]
    fmt = p.get("format")
    if fmt:
        argv.append(f"--format={fmt}")
    wordlist = p.get("wordlist", "/usr/share/wordlists/rockyou.txt")
    if wordlist:
        argv.append(f"--wordlist={wordlist}")
    argv += extra(p)
    argv += [p.get("hash_file", "")]
    return argv


def _hashcat(p: dict) -> list[str]:
    attack_mode = str(p.get("attack_mode", "0"))
    argv = ["hashcat", "-m", str(p.get("hash_type", "")), "-a", attack_mode, p.get("hash_file", "")]
    if attack_mode == "0":
        wordlist = p.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        if wordlist:
            argv.append(wordlist)
    else:
        mask = p.get("mask")
        if mask:
            argv.append(mask)
    argv += extra(p)
    return argv


def _hashpump(p: dict) -> list[str]:
    argv = [
        "hashpump",
        "-s",
        p.get("signature", ""),
        "-d",
        p.get("data", ""),
        "-k",
        str(p.get("key_length", "")),
        "-a",
        p.get("append_data", ""),
    ]
    argv += extra(p)
    return argv


# --------------------------------------------------------------------------- #
# Family: binary (local file analysis)
# --------------------------------------------------------------------------- #


def _gdb(p: dict) -> list[str]:
    argv = ["gdb", p.get("binary", "")]
    script_file = p.get("script_file")
    if script_file:
        argv += ["-x", script_file]
    commands = p.get("commands")
    if commands:
        path = _write_temp(commands, "gdb_commands_", ".txt")
        argv += ["-x", path]
    argv += extra(p)
    argv += ["-batch"]
    return argv


def _gdb_peda(p: dict) -> list[str]:
    argv = ["gdb", "-q"]
    if p.get("binary"):
        argv.append(p["binary"])
    if p.get("core_file"):
        argv.append(p["core_file"])
    if p.get("attach_pid"):
        argv += ["-p", str(p["attach_pid"])]
    commands = p.get("commands")
    if commands:
        path = _write_temp(commands, "gdb_peda_commands_", ".txt")
        argv += ["-x", path]
    argv += ["-ex", "source ~/peda/peda.py", "-ex", "quit"]
    argv += extra(p)
    return argv


def _radare2(p: dict) -> list[str]:
    argv = ["r2"]
    commands = p.get("commands")
    if commands:
        path = _write_temp(commands, "r2_commands_", ".txt")
        argv += ["-i", path]
    argv += ["-q", p.get("binary", "")]
    argv += extra(p)
    return argv


def _ghidra(p: dict) -> list[str]:
    project_name = p.get("project_name", "pepperspray_analysis")
    project_dir = f"/tmp/ghidra_projects/{project_name}"
    argv = [
        "analyzeHeadless",
        project_dir,
        project_name,
        "-import",
        p.get("binary", ""),
        "-deleteProject",
    ]
    script_file = p.get("script_file")
    if script_file:
        argv += ["-postScript", script_file]
    else:
        argv += ["-postScript", "ExportXml.java", f"{project_dir}/analysis.xml"]
    argv += extra(p)
    return argv


def _binwalk(p: dict) -> list[str]:
    argv = ["binwalk"]
    argv += flag("-e", p.get("extract"))
    argv += extra(p)
    argv += [p.get("file_path", "")]
    return argv


def _ropgadget(p: dict) -> list[str]:
    argv = ["ROPgadget", "--binary", p.get("binary", "")]
    gadget_type = p.get("gadget_type")
    if gadget_type:
        argv += ["--only", gadget_type]
    argv += extra(p)
    return argv


def _ropper(p: dict) -> list[str]:
    argv = ["ropper", "--file", p.get("binary", "")]
    gadget_type = p.get("gadget_type", "rop")
    _rop_flag = {"rop": "--rop", "jop": "--jop", "sys": "--sys", "all": "--all"}.get(gadget_type)
    if _rop_flag:
        argv.append(_rop_flag)
    if p.get("quality"):
        argv += ["--quality", str(p["quality"])]
    if p.get("arch"):
        argv += ["--arch", p["arch"]]
    if p.get("search_string"):
        argv += ["--search", p["search_string"]]
    argv += extra(p)
    return argv


def _checksec(p: dict) -> list[str]:
    # Legacy used --file={binary}; keep the value a separate argv element so a
    # hostile path can never ride inside a single token.
    return ["checksec", "--file", p.get("binary", "")]


def _xxd(p: dict) -> list[str]:
    argv = ["xxd", "-s", str(p.get("offset", "0"))]
    argv += opt("-l", p.get("length"))
    argv += extra(p)
    argv += [p.get("file_path", "")]
    return argv


def _strings(p: dict) -> list[str]:
    argv = ["strings", "-n", str(p.get("min_len", 4))]
    argv += extra(p)
    argv += [p.get("file_path", "")]
    return argv


def _objdump(p: dict) -> list[str]:
    argv = ["objdump"]
    argv.append("-d" if p.get("disassemble", True) else "-x")
    argv += extra(p)
    argv += [p.get("binary", "")]
    return argv


_PWNTOOLS_TEMPLATE = """#!/usr/bin/env python3
from pwn import *

binary = {binary!r} or None
host = {host!r} or None
port = {port!r} or None

if binary:
    io = process(binary)
    log.info("Started local process: %s" % binary)
elif host and port:
    io = remote(host, port)
    log.info("Connected to %s:%s" % (host, port))
else:
    log.error("No target specified")

io.interactive()
"""


def _pwntools(p: dict) -> list[str]:
    content = p.get("script_content", "")
    if not content:
        content = _PWNTOOLS_TEMPLATE.format(
            binary=p.get("target_binary", ""),
            host=p.get("target_host", ""),
            port=p.get("target_port", 0),
        )
    path = _write_temp(content, "pwntools_exploit_", ".py")
    return ["python3", path] + extra(p)


def _one_gadget(p: dict) -> list[str]:
    argv = ["one_gadget", p.get("libc_path", ""), "--level", str(p.get("level", 1))]
    argv += extra(p)
    return argv


_LIBC_DATABASE_DIR = "/opt/libc-database"


def _libc_database(p: dict) -> list[str]:
    # Legacy did `cd /opt/libc-database && ./<action> ...` through a shell; here
    # we invoke the script by absolute path (no shell, no cd) to stay argv-safe.
    action = p.get("action", "find")
    script = {"find": "find", "dump": "dump", "download": "download"}.get(action, "find")
    argv = [f"{_LIBC_DATABASE_DIR}/{script}"]
    if action == "find":
        argv += extra(p, "symbols")
    else:
        argv += [p.get("libc_id", "")]
    argv += extra(p)
    return argv


_ANGR_TEMPLATE = """#!/usr/bin/env python3
import angr

binary = {binary!r}
project = angr.Project(binary, auto_load_libs=False)
print("Loaded binary: %s" % binary)
print("Architecture: %s" % project.arch)
print("Entry point: %s" % hex(project.entry))
"""


def _angr(p: dict) -> list[str]:
    content = p.get("script_content", "")
    if not content:
        content = _ANGR_TEMPLATE.format(binary=p.get("binary", ""))
    path = _write_temp(content, "angr_analysis_", ".py")
    return ["python3", path] + extra(p)


def _pwninit(p: dict) -> list[str]:
    argv = ["pwninit", "--bin", p.get("binary", "")]
    argv += opt("--libc", p.get("libc"))
    argv += opt("--ld", p.get("ld"))
    argv += opt("--template", p.get("template_type"))
    argv += extra(p)
    return argv


# --------------------------------------------------------------------------- #
# Registry wiring
# --------------------------------------------------------------------------- #

# Per-family flags applied to every spec in that family.
_FAMILY_FLAGS = {
    "exploitation": {"active": True, "exploitation": True, "cacheable": False},
    "binary": {"active": False, "exploitation": False, "cacheable": True},
}

# (name, family, binary, builder, kwargs)
_SHELL_SPECS = [
    # --- exploitation -----------------------------------------------------
    (
        "sqlmap_scan",
        "exploitation",
        "sqlmap",
        _sqlmap,
        {"description": "sqlmap SQL injection scan"},
    ),
    (
        "metasploit_run",
        "exploitation",
        "msfconsole",
        _metasploit,
        {"description": "Metasploit module run (resource file)"},
    ),
    (
        "msfvenom_generate",
        "exploitation",
        "msfvenom",
        _msfvenom,
        {"description": "msfvenom payload generation"},
    ),
    (
        "hydra_attack",
        "exploitation",
        "hydra",
        _hydra,
        {"description": "Hydra online password attack"},
    ),
    (
        "pacu_exploitation",
        "exploitation",
        "pacu",
        _pacu,
        {"description": "Pacu AWS exploitation", "build_input": _pacu_input},
    ),
    ("john_crack", "exploitation", "john", _john, {"description": "John the Ripper hash cracking"}),
    (
        "hashcat_crack",
        "exploitation",
        "hashcat",
        _hashcat,
        {"description": "Hashcat hash cracking"},
    ),
    (
        "hashpump_attack",
        "exploitation",
        "hashpump",
        _hashpump,
        {"description": "HashPump hash length-extension"},
    ),
    # --- binary -----------------------------------------------------------
    ("gdb_analyze", "binary", "gdb", _gdb, {"description": "GDB binary analysis (batch)"}),
    ("gdb_peda_debug", "binary", "gdb", _gdb_peda, {"description": "GDB-PEDA debugging"}),
    ("radare2_analyze", "binary", "r2", _radare2, {"description": "Radare2 binary analysis"}),
    (
        "ghidra_analysis",
        "binary",
        "analyzeHeadless",
        _ghidra,
        {"description": "Ghidra headless analysis"},
    ),
    (
        "binwalk_analyze",
        "binary",
        "binwalk",
        _binwalk,
        {"description": "Binwalk firmware analysis"},
    ),
    (
        "ropgadget_search",
        "binary",
        "ROPgadget",
        _ropgadget,
        {"description": "ROPgadget gadget search"},
    ),
    ("ropper_gadget_search", "binary", "ropper", _ropper, {"description": "ropper gadget search"}),
    (
        "checksec_analyze",
        "binary",
        "checksec",
        _checksec,
        {"description": "checksec binary hardening check"},
    ),
    ("xxd_hexdump", "binary", "xxd", _xxd, {"description": "xxd hex dump"}),
    ("strings_extract", "binary", "strings", _strings, {"description": "strings extraction"}),
    ("objdump_analyze", "binary", "objdump", _objdump, {"description": "objdump disassembly"}),
    (
        "pwntools_exploit",
        "binary",
        "python3",
        _pwntools,
        {"description": "pwntools exploit script"},
    ),
    (
        "one_gadget_search",
        "binary",
        "one_gadget",
        _one_gadget,
        {"description": "one_gadget search"},
    ),
    (
        "libc_database_lookup",
        "binary",
        "libc-database",
        _libc_database,
        {"description": "libc-database lookup"},
    ),
    (
        "angr_symbolic_execution",
        "binary",
        "python3",
        _angr,
        {"description": "angr symbolic execution script"},
    ),
    (
        "pwninit_setup",
        "binary",
        "pwninit",
        _pwninit,
        {"description": "pwninit exploit scaffolding"},
    ),
]


def register(registry: ToolRegistry = REGISTRY) -> None:
    for name, family, binary, builder, kw in _SHELL_SPECS:
        kwargs = dict(kw)
        build_input = kwargs.pop("build_input", None)
        registry.register(
            ToolSpec(
                name=name,
                family=family,
                executor_kind="shell",
                binary=binary,
                build_argv=builder,
                build_input=build_input,
                **_FAMILY_FLAGS[family],
                **kwargs,
            )
        )


register()
