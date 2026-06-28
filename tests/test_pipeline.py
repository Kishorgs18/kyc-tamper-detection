"""End-to-end pipeline tests on synthetic in-memory images."""
from __future__ import annotations

import sys
from io import BytesIO
from pathlib import Path

import numpy as np
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tamper.models import Decision
from tamper.pipeline import analyze


def _png_bytes(color=(240, 240, 240)) -> bytes:
    img = Image.new("RGB", (256, 160), color)
    buf = BytesIO()
    img.save(buf, "JPEG", quality=95)
    return buf.getvalue()


def test_clean_image_no_fields_runs():
    result = analyze(_png_bytes())
    assert result.decision in {Decision.CLEAR, Decision.REVIEW}
    assert 0 <= result.tamper_score <= 100


def test_bad_aadhaar_forces_hold():
    result = analyze(_png_bytes(), ocr_fields={"aadhaar": "1234 5678 9012"})
    assert result.decision == Decision.HOLD
    assert result.tamper_score > 0


def test_identifiers_are_masked_in_output():
    result = analyze(_png_bytes(), ocr_fields={"aadhaar": "1234 5678 9012"})
    # full number must never appear in the masked report fields
    assert "1234" not in result.ocr_fields.get("aadhaar", "")
    assert result.ocr_fields["aadhaar"].startswith("X")


def test_heatmaps_present():
    result = analyze(_png_bytes())
    # ELA and noise detectors always emit a heatmap
    assert "ela" in result.heatmaps
    assert "noise_jpeg" in result.heatmaps
