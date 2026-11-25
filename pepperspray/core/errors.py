"""Error types and lightweight error classification.

The category map is migrated from the legacy IntelligentErrorHandler's error
patterns; the fake confidence scoring around it is dropped.
"""

from __future__ import annotations

import re

from pepperspray.core.executor import ToolResult  # noqa: F401 (re-export convenience)


class AuthorizationError(Exception):
    """Raised when an active tool runs without authorization."""


class ToolExecutionError(Exception):
    """Raised for unrecoverable tool execution problems."""


_PATTERNS: list[tuple[str, str]] = [
    (
        r"command not found|no such file or directory|executable not found|not found",
        "tool_not_found",
    ),
    (r"permission denied|access denied|not permitted", "permission_denied"),
    (r"timed out|timeout|connection timed out", "timeout"),
    (r"connection refused|could not connect|network unreachable|no route to host", "network_error"),
    (r"name or service not known|could not resolve|dns", "dns_error"),
    (r"rate limit|too many requests|429", "rate_limited"),
    (r"out of memory|memoryerror|cannot allocate", "resource_exhausted"),
]


def classify_error(stderr: str, returncode: int | None = None) -> str:
    """Return a coarse error category for a failed tool run."""
    text = (stderr or "").lower()
    for pattern, label in _PATTERNS:
        if re.search(pattern, text):
            return label
    if returncode == 127:
        return "tool_not_found"
    return "unknown_error"
