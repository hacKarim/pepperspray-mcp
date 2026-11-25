"""Helpers for declarative shell tool specs.

``extra()`` splits a free-form ``additional_args`` string into argv tokens with
shlex (honoring quotes), so even operator-supplied extra flags never pass
through a shell. Core parameters are always appended as single argv elements.
"""

from __future__ import annotations

import os
import shlex
import tempfile
from typing import Any


def write_temp(content: str, prefix: str, suffix: str) -> str:
    """Write *content* to a fresh temp file and return its path.

    Used by tools whose legacy form wrote a script/resource file and invoked an
    interpreter on it (metasploit .rc, gdb/r2 command files, pwntools/angr .py).
    """
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=suffix)
    with os.fdopen(fd, "w") as fh:
        fh.write(content if isinstance(content, str) else str(content))
    return path


def extra(params: dict, key: str = "additional_args") -> list[str]:
    raw = params.get(key, "")
    if not raw:
        return []
    if isinstance(raw, (list, tuple)):
        return [str(x) for x in raw]
    return shlex.split(str(raw))


def opt(flag: str, value: Any) -> list[str]:
    """Return ``[flag, str(value)]`` when value is truthy, else ``[]``."""
    if value in (None, "", False):
        return []
    return [flag, str(value)]


def flag(flag_str: str, value: Any) -> list[str]:
    """Return ``[flag_str]`` when value is truthy, else ``[]``."""
    return [flag_str] if value else []
