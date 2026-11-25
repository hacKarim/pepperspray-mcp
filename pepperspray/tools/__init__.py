"""Tool package. Importing ``load_all`` and calling it registers every tool
spec into the global REGISTRY (idempotent per process)."""

from __future__ import annotations

_LOADED = False


def load_all() -> None:
    """Import every spec module so all tools are registered."""
    global _LOADED
    if _LOADED:
        return
    from pepperspray.tools import cve_intel, flag_tools  # noqa: F401
    from pepperspray.tools.specs import (  # noqa: F401
        cloud_forensics,
        http_framework,
        offense,
        python_tools,
        recon,
        system,
        web,
    )

    _LOADED = True
