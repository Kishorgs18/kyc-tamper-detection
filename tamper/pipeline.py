"""Pipeline — orchestrates ingest -> detectors -> aggregate -> route -> report.

One public entry point, `analyze`, used by both the Streamlit app and the API.
Detectors are isolated: a failure in one is recorded as an INFO finding and
does not abort the analysis.
"""
from __future__ import annotations

from typing import Optional

from .aggregator import aggregate
from .detectors import ALL_DETECTORS
from .ingest import build_context
from .models import AnalysisResult, DetectorResult, Finding, Severity
from .report import build_report
from .router import decide
from .store import save_result


def analyze(
    raw_bytes: bytes,
    *,
    ocr_fields: Optional[dict] = None,
    ocr_boxes: Optional[dict] = None,
    source_text: str = "",
    doc_type: Optional[str] = None,
    persist: bool = False,
) -> AnalysisResult:
    ctx = build_context(
        raw_bytes,
        ocr_fields=ocr_fields,
        ocr_boxes=ocr_boxes,
        source_text=source_text,
        doc_type=doc_type,
    )

    results: list[DetectorResult] = []
    for module in ALL_DETECTORS:
        try:
            results.append(module.run(ctx))
        except Exception as exc:  # one detector must not break the run
            results.append(DetectorResult(
                detector=getattr(module, "NAME", module.__name__),
                findings=[Finding(
                    detector=getattr(module, "NAME", module.__name__),
                    code="DETECTOR_ERROR", severity=Severity.INFO,
                    explanation=f"Detector failed to run: {exc}", score=0.0,
                )],
            ))

    findings = aggregate(results)
    decision, score = decide(findings)
    report = build_report(
        decision=decision, score=score, findings=findings,
        detector_results=results, doc_type=ctx.doc_type,
        ocr_fields=ctx.ocr_fields,
    )

    if persist:
        save_result(report, raw_bytes=raw_bytes)

    return report
