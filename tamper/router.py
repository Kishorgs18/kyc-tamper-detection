"""Router — the ONLY place a decision is made.

No-data policy: deliberately conservative because every error is costly.
  * any HARD finding  -> HOLD   (escalate / block pending human review)
  * any SOFT finding   -> REVIEW (route to a human)
  * nothing            -> CLEAR  (auto-pass candidate)

When labeled data later exists, THIS function is what you replace with a
trained classifier over the detector outputs — nothing else changes.

The tamper_score is INDICATIVE ONLY (uncalibrated): a noisy-OR combination of
finding confidences, weighted by severity. It orders cases for reviewers; it is
not a probability and must not be used for automated rejection.
"""
from __future__ import annotations

from .models import Decision, Finding, Severity

_SEVERITY_BASE = {Severity.HARD: 0.85, Severity.SOFT: 0.40, Severity.INFO: 0.08}


def compute_score(findings: list[Finding]) -> int:
    """Noisy-OR combine per-finding contributions into a 0..100 indicator."""
    prob_clean = 1.0
    for f in findings:
        contribution = _SEVERITY_BASE[f.severity] * max(f.score, 0.5)
        prob_clean *= (1.0 - min(contribution, 0.99))
    return int(round((1.0 - prob_clean) * 100))


def decide(findings: list[Finding]) -> tuple[Decision, int]:
    has_hard = any(f.severity == Severity.HARD for f in findings)
    has_soft = any(f.severity == Severity.SOFT for f in findings)

    if has_hard:
        decision = Decision.HOLD
    elif has_soft:
        decision = Decision.REVIEW
    else:
        decision = Decision.CLEAR

    return decision, compute_score(findings)
