"""CTF flag extraction and validation — regexes preserved from the legacy
CTFChallengeAutomator. For authorized CTF/research use only."""

from __future__ import annotations

import json
import re

from pepperspray.core.executor import ToolResult
from pepperspray.core.registry import REGISTRY, ToolContext, ToolSpec

_EXTRACT_PATTERNS = [
    r"flag\{[^}]+\}",
    r"FLAG\{[^}]+\}",
    r"ctf\{[^}]+\}",
    r"CTF\{[^}]+\}",
    r"[a-zA-Z0-9_]+\{[^}]+\}",
    r"[0-9a-f]{32}",  # MD5
    r"[0-9a-f]{40}",  # SHA1
    r"[0-9a-f]{64}",  # SHA256
]

_VALIDATE_PATTERNS = [
    r"^flag\{.+\}$",
    r"^FLAG\{.+\}$",
    r"^ctf\{.+\}$",
    r"^CTF\{.+\}$",
    r"^[a-zA-Z0-9_]+\{.+\}$",
]


def extract_flags(text: str, fmt: str | None = None) -> list[str]:
    patterns = [fmt] if fmt else _EXTRACT_PATTERNS
    found: list[str] = []
    for pattern in patterns:
        found.extend(re.findall(pattern, text or "", re.IGNORECASE))
    # de-dup, preserve first-seen order
    seen: set[str] = set()
    ordered: list[str] = []
    for f in found:
        if f not in seen:
            seen.add(f)
            ordered.append(f)
    return ordered


def validate_flag(flag: str, fmt: str | None = None) -> bool:
    patterns = [fmt] if fmt else _VALIDATE_PATTERNS
    return any(re.match(p, flag or "", re.IGNORECASE) for p in patterns)


def _run_extract(params: dict, ctx: ToolContext) -> ToolResult:
    flags = extract_flags(params.get("text", ""), params.get("fmt"))
    return ToolResult(tool="flag_extract", status="success", stdout=json.dumps(flags))


def _run_validate(params: dict, ctx: ToolContext) -> ToolResult:
    ok = validate_flag(params.get("flag", ""), params.get("fmt"))
    return ToolResult(tool="flag_validate", status="success", stdout=json.dumps({"valid": ok}))


def register(registry=REGISTRY) -> None:
    registry.register(
        ToolSpec(
            name="flag_extract",
            family="binary",
            executor_kind="python",
            run=_run_extract,
            description="Extract CTF flag candidates from text",
        )
    )
    registry.register(
        ToolSpec(
            name="flag_validate",
            family="binary",
            executor_kind="python",
            run=_run_validate,
            description="Validate a CTF flag's format",
        )
    )


register()
