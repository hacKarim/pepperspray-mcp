"""CVE intelligence — preserved from the legacy CVEIntelligenceManager.

Real integrations: NVD REST API v2.0 and the GitHub search API. The CVSS-based
exploitability heuristic keeps the legacy weights verbatim; only the transport
(``requests`` → ``httpx``) and the structure changed.

For authorized security research only.
"""

from __future__ import annotations

import json
from datetime import datetime

import httpx

from pepperspray.core.executor import ToolResult
from pepperspray.core.registry import REGISTRY, ToolContext, ToolSpec

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"

_EXPLOIT_KEYWORDS = [
    "remote code execution",
    "rce",
    "buffer overflow",
    "stack overflow",
    "heap overflow",
    "use after free",
    "double free",
    "format string",
    "sql injection",
    "command injection",
    "authentication bypass",
    "privilege escalation",
    "directory traversal",
    "path traversal",
    "deserialization",
    "xxe",
    "ssrf",
    "csrf",
    "xss",
]
_EXPLOIT_REF_SOURCES = ["exploit-db.com", "github.com", "packetstormsecurity.com", "metasploit"]


def _get_json(url: str, params: dict, timeout: int = 30) -> dict:
    resp = httpx.get(
        url, params=params, timeout=timeout, headers={"User-Agent": "pepperspray-cve-intel"}
    )
    resp.raise_for_status()
    return resp.json()


def extract_cvss(metrics: dict) -> dict:
    """Pull the preferred CVSS metric block (v3.1 > v3.0 > v2), normalized."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        block = metrics.get(key)
        if block:
            data = dict(block[0].get("cvssData", {}))
            if "baseSeverity" in data and data["baseSeverity"]:
                data["baseSeverity"] = str(data["baseSeverity"]).upper()
            return data
    return {}


def score_exploitability(cvss: dict, description: str) -> dict:
    """CVSS-component exploitability heuristic (legacy weights preserved)."""
    attack_vector = cvss.get("attackVector", "UNKNOWN")
    attack_complexity = cvss.get("attackComplexity", "UNKNOWN")
    privileges_required = cvss.get("privilegesRequired", "UNKNOWN")
    user_interaction = cvss.get("userInteraction", "UNKNOWN")

    score = 0.0
    score += {"NETWORK": 0.4, "ADJACENT_NETWORK": 0.3, "LOCAL": 0.2, "PHYSICAL": 0.1}.get(
        attack_vector, 0.0
    )
    score += {"LOW": 0.3, "HIGH": 0.1}.get(attack_complexity, 0.0)
    score += {"NONE": 0.2, "LOW": 0.1}.get(privileges_required, 0.0)
    score += 0.1 if user_interaction == "NONE" else 0.0
    score = min(score, 1.0)

    desc = (description or "").lower()
    indicators = [kw for kw in _EXPLOIT_KEYWORDS if kw in desc]
    if any(kw in desc for kw in ("remote code execution", "rce", "buffer overflow")):
        score = min(score + 0.2, 1.0)
    elif any(kw in desc for kw in ("authentication bypass", "privilege escalation")):
        score = min(score + 0.15, 1.0)

    if score >= 0.8:
        level = "HIGH"
    elif score >= 0.6:
        level = "MEDIUM"
    elif score >= 0.3:
        level = "LOW"
    else:
        level = "VERY_LOW"

    return {
        "exploitability_score": round(score, 2),
        "exploitability_level": level,
        "exploit_indicators": indicators,
    }


def analyze_cve_exploitability(cve_id: str) -> dict:
    """Fetch a CVE from NVD and score its exploitability."""
    try:
        data = _get_json(NVD_URL, {"cveId": cve_id}, timeout=30)
    except httpx.HTTPError as exc:
        return {"success": False, "cve_id": cve_id, "error": f"NVD error: {exc}"}

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return {"success": False, "cve_id": cve_id, "error": "CVE not found in NVD"}

    cve = vulns[0].get("cve", {})
    cvss = extract_cvss(cve.get("metrics", {}))
    description = next(
        (d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        "",
    )
    scored = score_exploitability(cvss, description)

    references = cve.get("references", [])
    public_exploits = any(
        any(src in ref.get("url", "").lower() for src in _EXPLOIT_REF_SOURCES) for ref in references
    )

    return {
        "success": True,
        "cve_id": cve_id,
        "cvss_score": cvss.get("baseScore", 0.0),
        "severity": cvss.get("baseSeverity", "UNKNOWN"),
        "attack_vector": cvss.get("attackVector", "UNKNOWN"),
        **scored,
        "exploit_availability": {
            "public_exploits": public_exploits,
            "exploit_maturity": "PROOF_OF_CONCEPT" if public_exploits else "UNKNOWN",
        },
        "vulnerability_details": {
            "description": description[:500] + ("..." if len(description) > 500 else ""),
            "published_date": cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
            "references_count": len(references),
        },
        "data_source": "NVD API v2.0",
        "analysis_timestamp": datetime.now().isoformat(),
    }


def search_existing_exploits(cve_id: str) -> list[dict]:
    """Search GitHub for PoCs/exploits mentioning the CVE; rate by stars/forks."""
    try:
        data = _get_json(
            GITHUB_SEARCH_URL,
            {
                "q": f"{cve_id} exploit poc vulnerability",
                "sort": "updated",
                "order": "desc",
                "per_page": 10,
            },
            timeout=15,
        )
    except httpx.HTTPError:
        return []

    exploits: list[dict] = []
    for repo in data.get("items", [])[:10]:
        name = (repo.get("name") or "").lower()
        desc = (repo.get("description") or "").lower()
        if cve_id.lower() not in name and cve_id.lower() not in desc:
            continue
        stars = repo.get("stargazers_count", 0)
        forks = repo.get("forks_count", 0)
        reliability = "UNVERIFIED"
        if stars >= 50 or forks >= 10:
            reliability = "GOOD"
        elif stars >= 20 or forks >= 5:
            reliability = "FAIR"
        exploits.append(
            {
                "source": "github",
                "title": repo.get("name", ""),
                "description": repo.get("description", ""),
                "author": repo.get("owner", {}).get("login", "Unknown"),
                "url": repo.get("html_url", ""),
                "stars": stars,
                "forks": forks,
                "type": "proof-of-concept",
                "reliability": reliability,
            }
        )
    return exploits


def fetch_latest_cves(hours: int = 24, severity_filter: str = "HIGH,CRITICAL") -> list[dict]:
    """Fetch recently modified CVEs from NVD, filtered by severity."""
    from datetime import timedelta, timezone

    now = datetime.now(timezone.utc)
    params = {
        "lastModStartDate": (now - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 100,
    }
    try:
        data = _get_json(NVD_URL, params, timeout=30)
    except httpx.HTTPError:
        return []

    wanted = {s.strip().upper() for s in severity_filter.split(",") if s.strip()}
    out: list[dict] = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cvss = extract_cvss(cve.get("metrics", {}))
        severity = cvss.get("baseSeverity", "UNKNOWN")
        if wanted and severity not in wanted:
            continue
        out.append(
            {
                "cve_id": cve.get("id", ""),
                "severity": severity,
                "cvss_score": cvss.get("baseScore", 0.0),
                "published": cve.get("published", ""),
            }
        )
    return out


# --- registry wiring -------------------------------------------------------


def _run_cve_exploitability(params: dict, ctx: ToolContext) -> ToolResult:
    out = analyze_cve_exploitability(params.get("cve_id", ""))
    return ToolResult(
        tool="cve_exploitability",
        status="success" if out.get("success") else "failed",
        stdout=json.dumps(out, indent=2),
        error=out.get("error"),
    )


def _run_cve_search(params: dict, ctx: ToolContext) -> ToolResult:
    out = search_existing_exploits(params.get("cve_id", ""))
    return ToolResult(tool="cve_exploit_search", status="success", stdout=json.dumps(out, indent=2))


def _run_cve_monitor(params: dict, ctx: ToolContext) -> ToolResult:
    out = fetch_latest_cves(int(params.get("hours", 24)), params.get("severity", "HIGH,CRITICAL"))
    return ToolResult(tool="cve_monitor", status="success", stdout=json.dumps(out, indent=2))


def register(registry=REGISTRY) -> None:
    registry.register(
        ToolSpec(
            name="cve_exploitability",
            family="cve",
            executor_kind="python",
            run=_run_cve_exploitability,
            description="Score a CVE's exploitability from NVD CVSS data",
        )
    )
    registry.register(
        ToolSpec(
            name="cve_exploit_search",
            family="cve",
            executor_kind="python",
            run=_run_cve_search,
            description="Search GitHub for public exploits/PoCs for a CVE",
        )
    )
    registry.register(
        ToolSpec(
            name="cve_monitor",
            family="cve",
            executor_kind="python",
            run=_run_cve_monitor,
            description="List recently modified CVEs from NVD by severity",
        )
    )


register()
