"""Migrated domain knowledge from the legacy IntelligentDecisionEngine.

These tables are reference data for planning prompts — which tools tend to be
effective for which target type. The legacy confidence-scoring control flow is
NOT migrated; only the curated data.
"""

from __future__ import annotations

TOOL_EFFECTIVENESS: dict[str, dict[str, float]] = {
    "web_application": {
        "nuclei": 0.95, "wpscan": 0.95, "dalfox": 0.93, "jaeles": 0.92,
        "gobuster": 0.9, "sqlmap": 0.9, "ffuf": 0.9, "arjun": 0.9,
        "x8": 0.88, "katana": 0.88, "dirsearch": 0.87, "feroxbuster": 0.85,
        "httpx": 0.85, "nikto": 0.85, "paramspider": 0.85, "gau": 0.82,
        "nmap": 0.8, "waybackurls": 0.8,
    },
    "network_host": {
        "nmap": 0.95, "autorecon": 0.95, "masscan": 0.92, "rustscan": 0.9,
        "responder": 0.88, "smbmap": 0.85, "netexec": 0.85, "rpcclient": 0.82,
        "enum4linux": 0.8, "hydra": 0.8, "nbtscan": 0.75, "amass": 0.7,
    },
    "api_endpoint": {
        "arjun": 0.95, "nuclei": 0.9, "ffuf": 0.85, "httpx": 0.85,
        "paramspider": 0.85, "katana": 0.8,
    },
    "cloud": {
        "prowler": 0.95, "scout_suite": 0.92, "trivy": 0.9, "checkov": 0.88,
        "terrascan": 0.85, "kube_hunter": 0.85, "kube_bench": 0.83,
    },
}

# Ordered phase -> families, migrated from BugBountyWorkflowManager.
ASSESSMENT_PHASES: list[tuple[str, list[str]]] = [
    ("reconnaissance", ["recon"]),
    ("web_surface", ["web"]),
    ("cve_intelligence", ["cve"]),
    ("exploitation", ["exploitation"]),
    ("reporting", ["reporting"]),
]


def tools_for_target(target_type: str) -> list[str]:
    """Return tools ranked by effectiveness for a target type (best first)."""
    table = TOOL_EFFECTIVENESS.get(target_type, {})
    return [t for t, _ in sorted(table.items(), key=lambda kv: kv[1], reverse=True)]
