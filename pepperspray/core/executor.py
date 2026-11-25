"""Safe external-command execution.

Runs tools as an argv ``list[str]`` with ``shell=False`` — no shell, no string
interpolation, so a hostile parameter can never become a shell token. Every
failure mode (missing binary, timeout, non-zero exit) returns a structured
``ToolResult`` rather than raising.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Literal

Status = Literal["success", "failed", "timeout", "unavailable"]


@dataclass
class ToolResult:
    """Structured outcome of a single tool invocation."""

    tool: str
    status: Status
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    argv: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "status": self.status,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration": round(self.duration, 3),
            "argv": self.argv,
            "error": self.error,
        }


class SafeCommandExecutor:
    """Execute argv lists with a timeout and no shell."""

    def __init__(self, default_timeout: int = 300) -> None:
        self.default_timeout = default_timeout

    def run(
        self,
        tool: str,
        argv: list[str],
        timeout: int | None = None,
        input_text: str | None = None,
    ) -> ToolResult:
        if not argv:
            return ToolResult(tool=tool, status="failed", argv=argv, error="empty argv")

        if shutil.which(argv[0]) is None:
            return ToolResult(
                tool=tool,
                status="unavailable",
                argv=argv,
                error=f"binary not found on PATH: {argv[0]}",
            )

        effective_timeout = timeout if timeout is not None else self.default_timeout
        start = time.monotonic()
        try:
            proc = subprocess.run(  # noqa: S603 - argv list, shell=False, validated binary
                argv,
                input=input_text,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            return ToolResult(
                tool=tool,
                status="timeout",
                returncode=None,
                stdout=(exc.stdout or "") if isinstance(exc.stdout, str) else "",
                stderr=(exc.stderr or "") if isinstance(exc.stderr, str) else "",
                duration=time.monotonic() - start,
                argv=argv,
                error=f"timed out after {effective_timeout}s",
            )
        except (OSError, ValueError) as exc:
            return ToolResult(
                tool=tool,
                status="failed",
                duration=time.monotonic() - start,
                argv=argv,
                error=str(exc),
            )

        return ToolResult(
            tool=tool,
            status="success" if proc.returncode == 0 else "failed",
            returncode=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            duration=time.monotonic() - start,
            argv=argv,
        )
