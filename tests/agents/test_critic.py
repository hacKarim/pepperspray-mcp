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


# --- make_rerun_verifier robustness / authorization ------------------------


class _FakeSpec:
    def __init__(self, exploitation=False):
        self.exploitation = exploitation


class _RecordingRegistry:
    """Minimal registry stand-in that records execute() authorization."""

    def __init__(self, known=True, exploitation=False):
        self._known = known
        self._exploitation = exploitation
        self.calls = []

    def get(self, name):
        if not self._known:
            raise KeyError(f"unknown tool: {name}")
        return _FakeSpec(exploitation=self._exploitation)

    def execute(self, name, params, ctx, authorized):
        self.calls.append(authorized)

        class _R:
            status = "success"

        return _R()


def test_rerun_verifier_unknown_tool_does_not_crash():
    from pepperspray.agents.critic import make_rerun_verifier

    reg = _RecordingRegistry(known=False)
    verify = make_rerun_verifier(reg)
    # A finding whose originating tool is not (or no longer) registered must be
    # reported unconfirmed, not raise KeyError and kill the verify node.
    assert verify({"_tool": "ghost_tool", "_target": "example.com"}, object()) is False


def test_rerun_verifier_respects_finding_authorization():
    from pepperspray.agents.critic import make_rerun_verifier

    reg = _RecordingRegistry(known=True)
    verify = make_rerun_verifier(reg)
    # A finding produced by an UNAUTHORIZED run must never be re-executed as if
    # it were authorized — that would run an active tool the operator refused.
    verify({"_tool": "nmap_scan", "_target": "x", "_authorized": False}, object())
    assert reg.calls == [False]
    reg.calls.clear()
    # An authorized finding re-runs with authorization (reproducible check).
    verify({"_tool": "nmap_scan", "_target": "x", "_authorized": True}, object())
    assert reg.calls == [True]
