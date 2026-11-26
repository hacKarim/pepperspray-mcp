"""Render an assessment state into a Markdown report."""

from __future__ import annotations

from datetime import datetime, timezone

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def render_report(state: dict) -> str:
    target = state.get("target", "unknown")
    objective = state.get("objective", "")
    # Prefer the critic's curated/verified findings when the reflection pass ran.
    source_findings = state.get("curated_findings") or state.get("findings", [])
    findings = sorted(
        source_findings,
        key=lambda f: _SEV_ORDER.get(str(f.get("severity", "info")).lower(), 5),
    )
    tool_results = state.get("tool_results", [])
    completed = state.get("completed_steps", [])

    lines = [
        f"# Security Assessment — {target}",
        "",
        f"*Generated {datetime.now(timezone.utc).isoformat(timespec='seconds')}*",
        "",
        f"- **Objective:** {objective or 'n/a'}",
        f"- **Agents run:** {', '.join(completed) or 'none'}",
        f"- **Tool invocations:** {len(tool_results)}",
        f"- **Findings:** {len(findings)}",
        "",
        "## Findings",
        "",
    ]

    if findings:
        lines += [
            "| Severity | Title | Source | Confidence | Verified | Detail |",
            "|---|---|---|---|---|---|",
        ]
        for f in findings:
            sev = str(f.get("severity", "info")).upper()
            conf = f.get("confidence")
            conf_str = f"{conf:.0%}" if isinstance(conf, (int, float)) else "—"
            verified = "✓" if f.get("verified") else ("✗" if "verified" in f else "—")
            lines.append(
                f"| {sev} | {f.get('title', '')} | {f.get('source', '')} | "
                f"{conf_str} | {verified} | {f.get('detail', '')} |"
            )
    else:
        lines.append("_No findings recorded._")

    lines += ["", "## Tool activity", ""]
    if tool_results:
        for tr in tool_results:
            status = (
                tr.get("result", {}).get("status", "?")
                if isinstance(tr.get("result"), dict)
                else "?"
            )
            lines.append(f"- `{tr.get('tool', '?')}` → {status}")
    else:
        lines.append("_No tools were executed._")

    lines += ["", "---", "", "*Authorized security testing only.*"]
    return "\n".join(lines)
