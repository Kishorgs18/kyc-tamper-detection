"""Tests for the KYC front gate."""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tamper import gate
from tamper.ingest import Context
from tamper.models import Decision
from tamper.pipeline import analyze


def _ctx(fields=None) -> Context:
    img = Image.new("RGB", (32, 32), "white")
    return Context(raw_bytes=b"", pil_image=img,
                   cv_image=np.zeros((32, 32, 3), np.uint8),
                   ocr_fields=fields or {})


def test_ocr_fields_pass_gate():
    status, _ = gate.looks_like_kyc(_ctx({"aadhaar": "2345 6789 0124"}))
    assert status == "kyc"


def test_kyc_keywords_detected(monkeypatch):
    monkeypatch.setattr(gate, "_ocr_text",
                        lambda ctx: "GOVERNMENT OF INDIA\nAadhaar 2345 6789 0124")
    status, _ = gate.looks_like_kyc(_ctx())
    assert status == "kyc"


def test_random_image_rejected(monkeypatch):
    monkeypatch.setattr(gate, "_ocr_text", lambda ctx: "happy birthday party pizza")
    status, _ = gate.looks_like_kyc(_ctx())
    assert status == "not_kyc"


def test_pipeline_returns_unsupported_for_non_kyc(monkeypatch):
    monkeypatch.setattr(gate, "_ocr_text", lambda ctx: "just a holiday photo")
    img = Image.new("RGB", (200, 120), (180, 200, 220))
    from io import BytesIO
    buf = BytesIO(); img.save(buf, "JPEG")
    result = analyze(buf.getvalue())
    assert result.decision == Decision.UNSUPPORTED
    assert result.tamper_score == 0
