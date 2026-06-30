"""Pipeline — orchestrates ingest -> detectors -> aggregate -> route -> report.

One public entry point, `analyze`, used by both the Streamlit app and the API.
Detectors are isolated: a failure in one is recorded as an INFO finding and
does not abort the analysis.
"""
from __future__ import annotations

from typing import Optional

from .aggregator import aggregate
from .detectors import ALL_DETECTORS
from .gate import extract_ocr_fields, looks_like_kyc
from .ingest import build_context
from .models import AnalysisResult, Decision, DetectorResult, Finding, Severity
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

    # Auto-extract the document type + identifier via OCR when the caller did not
    # supply them, so the semantic (checksum/format) checks can run without the
    # user typing anything.
    if not ctx.ocr_fields and not ctx.doc_type:
        found, found_type = extract_ocr_fields(ctx)
        if found:
            ctx.ocr_fields = found
        if found_type:
            ctx.doc_type = found_type

    # Front gate: only block clear non-KYC images (e.g. a selfie). Real document
    # photos that OCR can't read cleanly are analysed anyway (fail-open).
    status, reason = looks_like_kyc(ctx)
    if status == "not_kyc":
        return AnalysisResult(
            decision=Decision.UNSUPPORTED,
            tamper_score=0,
            doc_type=None,
            findings=[],
            heatmaps={},
            ocr_fields={},
            summary="This image does not appear to be a supported KYC document "
                    f"(Aadhaar / PAN / Driving Licence): {reason}. "
                    "Tamper analysis was skipped.",
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
        # Persistence is best-effort: a read-only/ephemeral cloud filesystem
        # must never crash the analysis.
        try:
            report.record_id = save_result(report, raw_bytes=raw_bytes)
        except Exception:
            pass

    return report
