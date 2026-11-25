"""Specialist agent definitions: name -> (families, system prompt).

Each builds a LangGraph node via make_specialist. 'reporting' has no tools and
is handled as a dedicated node in the graph, so it is not built here.
"""

from __future__ import annotations

from typing import Any, Callable

from pepperspray.agents.base import make_specialist
from pepperspray.core.registry import REGISTRY, ToolContext, ToolRegistry

# name -> (families, prompt)
SPECIALISTS: dict[str, tuple[list[str], str]] = {
    "recon": (
        ["recon"],
        "You are the reconnaissance specialist. Discover hosts, open ports, "
        "services, subdomains and exposed surface using your scanning and "
        "enumeration tools. Report concrete findings only.",
    ),
    "web": (
        ["web", "web_http", "utility"],
        "You are the web application specialist. Probe web apps for "
        "misconfigurations, directories, parameters and common vulnerabilities "
        "using your fuzzing, crawling and vulnerability tools.",
    ),
    "exploitation": (
        ["exploitation"],
        "You are the exploitation specialist. Only act on authorized "
        "targets. Attempt validation of confirmed vulnerabilities using "
        "your exploitation tools; never pivot beyond scope.",
    ),
    "binary": (
        ["binary"],
        "You are the binary analysis / CTF specialist. Analyze binaries, "
        "extract strings and gadgets, and work pwn/reverse challenges.",
    ),
    "cloud": (
        ["cloud"],
        "You are the cloud and container security specialist. Assess cloud "
        "accounts, containers, Kubernetes and IaC for misconfigurations.",
    ),
    "forensics": (
        ["forensics"],
        "You are the forensics specialist. Analyze memory images, carve "
        "files, and extract metadata and hidden data.",
    ),
    "cve": (
        ["cve"],
        "You are the CVE intelligence specialist. Look up CVEs, score "
        "exploitability from NVD data, and find public exploits.",
    ),
}


def build_specialists(
    ctx: ToolContext,
    llm: Any = None,
    registry: ToolRegistry = REGISTRY,
    agent_factory: Callable | None = None,
) -> dict[str, Callable[[dict], dict]]:
    """Return {name: node} for every tool-backed specialist."""
    return {
        name: make_specialist(
            name, families, prompt, ctx=ctx, registry=registry, llm=llm, agent_factory=agent_factory
        )
        for name, (families, prompt) in SPECIALISTS.items()
    }
