"""Report — assemble the final AnalysisResult from detector outputs.

Produces the reviewer-facing object used identically by the Streamlit demo and
the FastAPI response: decision, indicative score, plain-language findings,
per-detector heatmaps, and MASKED OCR fields (never the full identifiers).
"""
from __future__ import annotations

from .models import AnalysisResult, Decision, DetectorResult, Finding
from .utils import mask_identifier

_DECISION_BLURB = {
    Decision.CLEAR: "No tamper indicators found. Candidate for auto-pass.",
    Decision.REVIEW: "Soft anomalies detected — route to a human reviewer.",
    Decision.HOLD: "Strong tamper indicators — hold and escalate.",
}

_SENSITIVE_FIELDS = {"aadhaar", "pan", "dl"}


def _mask_fields(fields: dict) -> dict:
    out = {}
    for k, v in (fields or {}).items():
        out[k] = mask_identifier(str(v)) if k in _SENSITIVE_FIELDS else v
    return out


def build_report(
    *,
    decision: Decision,
    score: int,
    findings: list[Finding],
    detector_results: list[DetectorResult],
    doc_type: str | None,
    ocr_fields: dict,
) -> AnalysisResult:
    heatmaps = {
        r.detector: r.heatmap_b64 for r in detector_results if r.heatmap_b64
    }

    top = "; ".join(f"{f.explanation}" for f in findings[:3]) or "no findings"
    summary = f"{_DECISION_BLURB[decision]} ({len(findings)} finding(s)). {top}"

    return AnalysisResult(
        decision=decision,
        tamper_score=score,
        doc_type=doc_type,
        findings=findings,
        heatmaps=heatmaps,
        ocr_fields=_mask_fields(ocr_fields),
        summary=summary,
    )
