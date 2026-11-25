from pepperspray.reporting.report import render_report


def test_report_contains_findings_and_target():
    state = {
        "target": "example.com",
        "objective": "comprehensive",
        "findings": [
            {"title": "Open port 80", "severity": "info", "detail": "http", "source": "recon"},
            {"title": "SQLi in /login", "severity": "high", "detail": "param id", "source": "web"},
        ],
        "tool_results": [{"tool": "nmap_scan", "result": {"status": "success"}}],
        "completed_steps": ["recon", "web"],
    }
    md = render_report(state)
    assert "example.com" in md
    assert "Open port 80" in md and "SQLi in /login" in md
    assert "nmap_scan" in md
    assert md.lstrip().startswith("#")


def test_report_handles_empty():
    md = render_report({"target": "t", "findings": [], "tool_results": []})
    assert "t" in md and "No findings" in md
