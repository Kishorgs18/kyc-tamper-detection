"""Error Level Analysis — recompress, diff, amplify.

Edited regions often compress differently than their surroundings, lighting up
in the residual. Treated as VISUAL EVIDENCE for a human, not an auto-verdict:
KYC photos are frequently already re-compressed/recaptured, which makes ELA
noisy. We surface the heatmap and only raise a SOFT flag on a strong response.
"""
from __future__ import annotations

from io import BytesIO

import numpy as np
from PIL import Image, ImageChops

from ..config import ELA_QUALITY, ELA_SOFT_THRESHOLD
from ..ingest import Context
from ..models import DetectorResult, Finding, Severity
from ..utils import heatmap_overlay, to_b64_png

NAME = "ela"


def run(ctx: Context) -> DetectorResult:
    findings: list[Finding] = []

    base = ctx.pil_image.convert("RGB")
    buf = BytesIO()
    base.save(buf, "JPEG", quality=ELA_QUALITY)
    buf.seek(0)
    recompressed = Image.open(buf)

    diff = ImageChops.difference(base, recompressed)
    ela_arr = np.asarray(diff).astype(np.float32)
    intensity = ela_arr.max(axis=2)  # per-pixel max channel difference

    # Normalized mean of the brightest residuals as a crude strength score.
    norm = intensity / 255.0
    bright = norm[norm > np.percentile(norm, 99)]
    strength = float(bright.mean()) if bright.size else 0.0

    overlay = heatmap_overlay(ctx.cv_image, intensity)
    heatmap_b64 = to_b64_png(overlay)

    if strength >= ELA_SOFT_THRESHOLD:
        findings.append(Finding(
            detector=NAME, code="ELA_HIGH_RESIDUAL", severity=Severity.SOFT,
            explanation="Localized high error-level regions detected — possible "
                        "edited area. Review the highlighted zones.",
            score=min(1.0, strength / (ELA_SOFT_THRESHOLD * 2)),
        ))

    return DetectorResult(
        detector=NAME, findings=findings, heatmap_b64=heatmap_b64,
        meta={"strength": round(strength, 4), "quality": ELA_QUALITY},
    )
