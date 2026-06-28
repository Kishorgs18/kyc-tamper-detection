"""Aggregator — collect findings from all detectors into one ordered list.

Deliberately does NO scoring or decision logic. Keeping aggregation separate
from the router means decision policy can change without touching detectors.
"""
from __future__ import annotations

from .models import DetectorResult, Finding, Severity

_SEVERITY_ORDER = {Severity.HARD: 0, Severity.SOFT: 1, Severity.INFO: 2}


def aggregate(results: list[DetectorResult]) -> list[Finding]:
    findings: list[Finding] = []
    for r in results:
        findings.extend(r.findings)
    findings.sort(key=lambda f: (_SEVERITY_ORDER[f.severity], -f.score))
    return findings
