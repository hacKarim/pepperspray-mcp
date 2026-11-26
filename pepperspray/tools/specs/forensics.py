"""Digital-forensics tool specs: memory, disk and file-artifact analysis.

These operate on LOCAL files only and touch no network (``active=False``,
``cacheable=True``). Each builds an argv list — no shell; user values are single
argv elements, only ``additional_args`` is tokenized (shlex). For authorized use.
"""

from __future__ import annotations

from pepperspray.core.registry import REGISTRY, ToolRegistry, ToolSpec
from pepperspray.tools.specs._helpers import extra, opt


def _volatility(p: dict) -> list[str]:
    argv = ["volatility", "-f", p.get("memory_file") or p.get("file", "")]
    if p.get("profile"):
        argv += [f"--profile={p.get('profile')}"]
    argv += [p.get("plugin", "")]
    argv += extra(p)
    return argv


def _volatility3(p: dict) -> list[str]:
    argv = ["vol", "-f", p.get("memory_file") or p.get("file", ""), p.get("plugin", "")]
    argv += opt("-o", p.get("output_file"))
    argv += extra(p)
    return argv


def _foremost(p: dict) -> list[str]:
    argv = ["foremost", "-o", str(p.get("output_dir", "/tmp/foremost_output"))]
    argv += opt("-t", p.get("file_types"))
    argv += extra(p)
    argv += [p.get("input_file") or p.get("file", "")]
    return argv


def _steghide(p: dict) -> list[str]:
    action = p.get("action", "extract")
    cover = p.get("cover_file") or p.get("file", "")
    if action == "embed":
        argv = ["steghide", "embed", "-cf", cover, "-ef", p.get("embed_file", "")]
        argv += ["-p", str(p.get("passphrase", ""))]
    elif action == "info":
        # `steghide info` does not accept -p.
        argv = ["steghide", "info", cover]
    else:
        argv = ["steghide", "extract", "-sf", cover]
        argv += opt("-xf", p.get("output_file"))
        argv += ["-p", str(p.get("passphrase", ""))]
    argv += extra(p)
    return argv


def _exiftool(p: dict) -> list[str]:
    argv = ["exiftool"]
    if p.get("output_format"):
        argv += [f"-{p.get('output_format')}"]
    if p.get("tags"):
        argv += [f"-{p.get('tags')}"]
    argv += extra(p)
    argv += [p.get("file_path") or p.get("file", "")]
    return argv


# (name, binary, builder, kwargs)
_SHELL_SPECS = [
    (
        "volatility_analyze",
        "volatility",
        _volatility,
        {"description": "Volatility 2 memory analysis"},
    ),
    ("volatility3_analyze", "vol", _volatility3, {"description": "Volatility 3 memory analysis"}),
    ("foremost_carving", "foremost", _foremost, {"description": "Foremost file carving"}),
    (
        "steghide_analysis",
        "steghide",
        _steghide,
        {"description": "Steghide steganography analysis"},
    ),
    ("exiftool_extract", "exiftool", _exiftool, {"description": "ExifTool metadata extraction"}),
]


def register(registry: ToolRegistry = REGISTRY) -> None:
    for name, binary, builder, kw in _SHELL_SPECS:
        registry.register(
            ToolSpec(
                name=name,
                family="forensics",
                executor_kind="shell",
                binary=binary,
                build_argv=builder,
                active=False,
                cacheable=True,
                **kw,
            )
        )


register()
