"""Reflection: a critic agent that scores and dedupes findings, and a verify
node that re-checks the low-confidence ones. Together they form an
evaluator-optimizer loop bounded by ``verify_budget``:

    specialists → critic → (verify → critic)* → reporting

The critic's scorer is injectable (an LLM with structured output in production,
a stub in tests), the same pattern as the supervisor's router.
"""

from __future__ import annotations

from typing import Any, Callable

from pydantic import BaseModel, Field


class FindingScore(BaseModel):
    """The critic's judgement of one finding."""

    index: int
    confidence: float = Field(ge=0.0, le=1.0)
    needs_verification: bool = False
    reason: str = ""


class Critique(BaseModel):
    """The critic's judgement of a batch of findings."""

    scores: list[FindingScore]


def _dedupe(findings: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    out: list[dict] = []
    for f in findings:
        key = (str(f.get("title", "")).lower().strip(), str(f.get("source", "")))
        if key in seen:
            continue
        seen.add(key)
        out.append(dict(f))
    return out


def _llm_scorer(llm: Any) -> Callable[[list[dict]], Critique]:
    structured = llm.with_structured_output(Critique)

    def score(findings: list[dict]) -> Critique:
        lines = "\n".join(
            f"{i}. [{f.get('severity', 'info')}] {f.get('title', '')} "
            f"(source: {f.get('source', '')}) — {f.get('detail', '')}"
            for i, f in enumerate(findings)
        )
        prompt = (
            "You are a security findings reviewer. For each finding, estimate a "
            "confidence (0-1) that it is a real, correctly-identified issue, and "
            "set needs_verification=true for anything impactful but unconfirmed "
            "(e.g. injection, auth bypass, RCE) that a second check should confirm "
            "before it goes in the report.\n\nFindings:\n" + lines
        )
        return structured.invoke(prompt)

    return score


def critic_node(
    state: dict,
    scorer: Callable[[list[dict]], Critique] | None = None,
    llm: Any = None,
) -> dict:
    """Dedupe findings, score them, and decide whether a verify pass is needed.

    On a re-entry after a verify pass, build on the already-curated findings so
    confidence/verified annotations are preserved rather than recomputed.
    """
    base = state.get("curated_findings")
    deduped = list(base) if base else _dedupe(state.get("findings", []))
    if not deduped:
        return {"curated_findings": [], "to_verify": [], "reflection": "done"}

    # Degrade gracefully: with no scorer and no LLM, skip scoring and finish.
    if scorer is None and llm is None:
        return {"curated_findings": deduped, "to_verify": [], "reflection": "done"}

    score_fn = scorer or _llm_scorer(llm)
    critique = score_fn(deduped)
    by_index = {s.index: s for s in critique.scores}

    to_verify: list[dict] = []
    for i, finding in enumerate(deduped):
        s = by_index.get(i)
        if s is not None:
            finding["confidence"] = s.confidence
            if s.needs_verification and not finding.get("verified"):
                to_verify.append(finding)

    budget = int(state.get("verify_budget", 0))
    reflection = "verify" if (to_verify and budget > 0) else "done"
    return {"curated_findings": deduped, "to_verify": to_verify, "reflection": reflection}


def verify_node(
    state: dict,
    verifier: Callable[[dict, Any], bool] | None = None,
    ctx: Any = None,
) -> dict:
    """Attempt to confirm each flagged finding; annotate and decrement the budget."""
    curated = state.get("curated_findings", [])
    to_verify = state.get("to_verify", [])
    verify_fn = verifier or _default_verifier
    by_title = {f.get("title"): f for f in curated}

    for pending in to_verify:
        confirmed = bool(verify_fn(pending, ctx))
        target = by_title.get(pending.get("title"))
        if target is not None:
            target["verified"] = confirmed
            target["confidence"] = 0.95 if confirmed else 0.2

    return {
        "curated_findings": curated,
        "to_verify": [],
        "verify_budget": max(0, int(state.get("verify_budget", 0)) - 1),
        "reflection": "pending",
    }


def _default_verifier(finding: dict, ctx: Any) -> bool:
    """Conservative default: without a real re-check we cannot confirm, so don't."""
    return False


def route_reflection(state: dict) -> str:
    """Conditional edge after the critic: loop to verify, or go to reporting."""
    if state.get("reflection") == "verify" and int(state.get("verify_budget", 0)) > 0:
        return "verify"
    return "reporting"
