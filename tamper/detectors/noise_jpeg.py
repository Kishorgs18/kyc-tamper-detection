"""Noise-consistency detector — looks for local residual-noise discontinuities.

A spliced/patched region usually carries a different noise floor than the host
document. We compute a high-pass residual and its local energy map. If OCR field
boxes are available, we compare each field's residual energy against the
document baseline — a patched DOB/number then stands out. This is the detector
that most directly leverages your existing OCR localisation.
"""
from __future__ import annotations

import cv2
import numpy as np

from ..config import FIELD_NOISE_RATIO_SOFT
from ..ingest import Context
from ..models import DetectorResult, Finding, Region, Severity
from ..utils import heatmap_overlay, to_b64_png

NAME = "noise_jpeg"


def _residual_energy(gray: np.ndarray) -> np.ndarray:
    """High-pass residual via median-blur subtraction; returns abs residual."""
    blur = cv2.medianBlur(gray, 3)
    residual = cv2.absdiff(gray, blur).astype(np.float32)
    return residual


def run(ctx: Context) -> DetectorResult:
    findings: list[Finding] = []
    gray = cv2.cvtColor(ctx.cv_image, cv2.COLOR_BGR2GRAY)
    residual = _residual_energy(gray)

    # Local energy map for the heatmap (mean abs residual in a window).
    energy_map = cv2.blur(residual, (15, 15))
    baseline = float(energy_map.mean()) + 1e-6

    overlay = heatmap_overlay(ctx.cv_image, energy_map)

    # Per-field comparison when OCR boxes are present (the strong path).
    worst_ratio = 0.0
    for fname, box in (ctx.ocr_boxes or {}).items():
        crop = energy_map[box.y:box.y + box.h, box.x:box.x + box.w]
        if crop.size == 0:
            continue
        ratio = float(crop.mean()) / baseline
        worst_ratio = max(worst_ratio, ratio)
        if ratio >= FIELD_NOISE_RATIO_SOFT or ratio <= 1.0 / FIELD_NOISE_RATIO_SOFT:
            findings.append(Finding(
                detector=NAME, code="FIELD_NOISE_MISMATCH", severity=Severity.SOFT,
                explanation=f"Field '{fname}' has a noise signature {ratio:.1f}x the "
                            "document baseline — possible local edit.",
                region=box, score=min(1.0, abs(ratio - 1.0)),
            ))

    return DetectorResult(
        detector=NAME, findings=findings, heatmap_b64=to_b64_png(overlay),
        meta={"baseline_energy": round(baseline, 4),
              "worst_field_ratio": round(worst_ratio, 3),
              "fields_compared": len(ctx.ocr_boxes or {})},
    )
