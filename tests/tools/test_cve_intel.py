from pepperspray.tools import cve_intel as c


def test_score_network_lowcomplexity_scores_high():
    cvss = {
        "attackVector": "NETWORK",
        "attackComplexity": "LOW",
        "privilegesRequired": "NONE",
        "userInteraction": "NONE",
        "baseSeverity": "CRITICAL",
        "baseScore": 9.8,
    }
    out = c.score_exploitability(cvss, "Remote code execution in X")
    # 0.4 + 0.3 + 0.2 + 0.1 = 1.0, +0.2 RCE keyword, capped at 1.0
    assert out["exploitability_score"] == 1.0
    assert out["exploitability_level"] == "HIGH"


def test_score_local_highcomplexity_low():
    cvss = {
        "attackVector": "LOCAL",
        "attackComplexity": "HIGH",
        "privilegesRequired": "HIGH",
        "userInteraction": "REQUIRED",
        "baseSeverity": "MEDIUM",
        "baseScore": 5.0,
    }
    out = c.score_exploitability(cvss, "minor info leak")
    assert out["exploitability_score"] == 0.3  # 0.2 + 0.1
    assert out["exploitability_level"] == "LOW"


def test_extract_cvss_prefers_v31():
    metrics = {
        "cvssMetricV31": [
            {"cvssData": {"baseScore": 9.1, "baseSeverity": "critical", "attackVector": "NETWORK"}}
        ],
        "cvssMetricV30": [{"cvssData": {"baseScore": 1.0}}],
    }
    cvss = c.extract_cvss(metrics)
    assert cvss["baseScore"] == 9.1 and cvss["baseSeverity"] == "CRITICAL"


def test_analyze_uses_nvd(monkeypatch):
    fake = {
        "vulnerabilities": [
            {
                "cve": {
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                    "attackVector": "NETWORK",
                                    "attackComplexity": "LOW",
                                    "privilegesRequired": "NONE",
                                    "userInteraction": "NONE",
                                }
                            }
                        ]
                    },
                    "descriptions": [{"lang": "en", "value": "Remote code execution"}],
                    "references": [{"url": "https://github.com/x/poc"}],
                    "published": "2024-01-01",
                    "lastModified": "2024-01-02",
                }
            }
        ]
    }
    monkeypatch.setattr(c, "_get_json", lambda url, params, timeout=30: fake)
    out = c.analyze_cve_exploitability("CVE-2024-0001")
    assert out["success"] and out["severity"] == "CRITICAL"
    assert out["exploitability_level"] == "HIGH"
    assert out["exploit_availability"]["public_exploits"] is True


def test_search_exploits_filters_and_rates(monkeypatch):
    fake = {
        "items": [
            {
                "id": 1,
                "name": "CVE-2024-0001-poc",
                "description": "poc",
                "owner": {"login": "a"},
                "html_url": "u",
                "stargazers_count": 60,
                "forks_count": 2,
                "created_at": "",
                "updated_at": "",
            },
            {
                "id": 2,
                "name": "unrelated",
                "description": "nope",
                "owner": {"login": "b"},
                "html_url": "u2",
                "stargazers_count": 0,
                "forks_count": 0,
                "created_at": "",
                "updated_at": "",
            },
        ]
    }
    monkeypatch.setattr(c, "_get_json", lambda url, params, timeout=15: fake)
    out = c.search_existing_exploits("CVE-2024-0001")
    assert len(out) == 1  # unrelated repo filtered out
    assert out[0]["reliability"] == "GOOD"  # 60 stars
