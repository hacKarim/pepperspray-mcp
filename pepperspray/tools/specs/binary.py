"""Binary-analysis / CTF-family tool specs.

These analyze *local* files (``active=False``, ``cacheable=True``) and touch no
network. Each builds an argv ``list[str]`` — no shell. A few tools whose legacy
form wrote a script and ran an interpreter on it use :func:`write_temp`.
For authorized security research / CTF use only.
"""

from __future__ import annotations

from pepperspray.core.registry import REGISTRY, ToolRegistry, ToolSpec
from pepperspray.tools.specs._helpers import extra, flag, opt, write_temp


def _gdb(p: dict) -> list[str]:
    argv = ["gdb", p.get("binary", "")]
    script_file = p.get("script_file")
    if script_file:
        argv += ["-x", script_file]
    commands = p.get("commands")
    if commands:
        path = write_temp(commands, "gdb_commands_", ".txt")
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
        path = write_temp(commands, "gdb_peda_commands_", ".txt")
        argv += ["-x", path]
    argv += ["-ex", "source ~/peda/peda.py", "-ex", "quit"]
    argv += extra(p)
    return argv


def _radare2(p: dict) -> list[str]:
    argv = ["r2"]
    commands = p.get("commands")
    if commands:
        path = write_temp(commands, "r2_commands_", ".txt")
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
    # Keep the value a separate argv element so a hostile path can never ride
    # inside a single token.
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
    path = write_temp(content, "pwntools_exploit_", ".py")
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
    path = write_temp(content, "angr_analysis_", ".py")
    return ["python3", path] + extra(p)


def _pwninit(p: dict) -> list[str]:
    argv = ["pwninit", "--bin", p.get("binary", "")]
    argv += opt("--libc", p.get("libc"))
    argv += opt("--ld", p.get("ld"))
    argv += opt("--template", p.get("template_type"))
    argv += extra(p)
    return argv


# (name, binary, builder, kwargs)
_SHELL_SPECS = [
    ("gdb_analyze", "gdb", _gdb, {"description": "GDB binary analysis (batch)"}),
    ("gdb_peda_debug", "gdb", _gdb_peda, {"description": "GDB-PEDA debugging"}),
    ("radare2_analyze", "r2", _radare2, {"description": "Radare2 binary analysis"}),
    ("ghidra_analysis", "analyzeHeadless", _ghidra, {"description": "Ghidra headless analysis"}),
    ("binwalk_analyze", "binwalk", _binwalk, {"description": "Binwalk firmware analysis"}),
    ("ropgadget_search", "ROPgadget", _ropgadget, {"description": "ROPgadget gadget search"}),
    ("ropper_gadget_search", "ropper", _ropper, {"description": "ropper gadget search"}),
    ("checksec_analyze", "checksec", _checksec, {"description": "checksec binary hardening check"}),
    ("xxd_hexdump", "xxd", _xxd, {"description": "xxd hex dump"}),
    ("strings_extract", "strings", _strings, {"description": "strings extraction"}),
    ("objdump_analyze", "objdump", _objdump, {"description": "objdump disassembly"}),
    ("pwntools_exploit", "python3", _pwntools, {"description": "pwntools exploit script"}),
    ("one_gadget_search", "one_gadget", _one_gadget, {"description": "one_gadget search"}),
    (
        "libc_database_lookup",
        "libc-database",
        _libc_database,
        {"description": "libc-database lookup"},
    ),
    (
        "angr_symbolic_execution",
        "python3",
        _angr,
        {"description": "angr symbolic execution script"},
    ),
    ("pwninit_setup", "pwninit", _pwninit, {"description": "pwninit exploit scaffolding"}),
]


def register(registry: ToolRegistry = REGISTRY) -> None:
    for name, binary, builder, kw in _SHELL_SPECS:
        registry.register(
            ToolSpec(
                name=name,
                family="binary",
                executor_kind="shell",
                binary=binary,
                build_argv=builder,
                active=False,
                cacheable=True,
                **kw,
            )
        )


register()
