from pepperspray.agents.critic import (
    Critique,
    FindingScore,
    critic_node,
    route_reflection,
    verify_node,
)


def _findings():
    return [
        {"title": "Open port 80", "severity": "info", "source": "recon", "detail": ""},
        {"title": "Open port 80", "severity": "info", "source": "recon", "detail": ""},  # dup
        {"title": "SQLi in /login", "severity": "high", "source": "web", "detail": "id"},
    ]


def _scorer(findings):
    # flag the SQLi for verification, keep the rest
    scores = []
    for i, f in enumerate(findings):
        needs = "sqli" in f["title"].lower()
        scores.append(
            FindingScore(index=i, confidence=0.5 if needs else 0.9, needs_verification=needs)
        )
    return Critique(scores=scores)


def test_critic_dedupes_and_flags():
    state = {"findings": _findings(), "verify_budget": 1}
    out = critic_node(state, scorer=_scorer)
    assert len(out["curated_findings"]) == 2  # duplicate removed
    assert len(out["to_verify"]) == 1
    assert out["to_verify"][0]["title"] == "SQLi in /login"
    assert out["reflection"] == "verify"  # budget available + something to verify


def test_critic_done_when_budget_exhausted():
    state = {"findings": _findings(), "verify_budget": 0}
    out = critic_node(state, scorer=_scorer)
    assert out["reflection"] == "done"


def test_route_reflection():
    assert route_reflection({"reflection": "verify", "verify_budget": 1}) == "verify"
    assert route_reflection({"reflection": "done", "verify_budget": 1}) == "reporting"
    assert route_reflection({"reflection": "verify", "verify_budget": 0}) == "reporting"


def test_verify_marks_and_decrements():
    state = {
        "curated_findings": [
            {"title": "SQLi in /login", "severity": "high", "source": "web", "confidence": 0.5}
        ],
        "to_verify": [{"title": "SQLi in /login", "severity": "high", "source": "web"}],
        "verify_budget": 1,
    }

    def verifier(finding, ctx):
        return True  # confirmed

    out = verify_node(state, verifier=verifier)
    assert out["verify_budget"] == 0
    cur = {f["title"]: f for f in out["curated_findings"]}
    assert cur["SQLi in /login"]["verified"] is True
