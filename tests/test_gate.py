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


def test_long_nonkyc_text_rejected(monkeypatch):
    # A clearly-readable NON-KYC text scene (lots of words, no KYC markers).
    monkeypatch.setattr(gate, "_ocr_text", lambda ctx:
                        "happy birthday party celebration with friends and family "
                        "at the downtown restaurant this weekend pizza cake balloons")
    status, _ = gate.looks_like_kyc(_ctx())
    assert status == "not_kyc"


def test_pipeline_returns_unsupported_for_long_nonkyc(monkeypatch):
    monkeypatch.setattr(gate, "_ocr_text", lambda ctx:
                        "a long holiday photo description with beach sunset mountains "
                        "and friends enjoying their summer vacation together by the sea")
    img = Image.new("RGB", (200, 120), (180, 200, 220))
    from io import BytesIO
    buf = BytesIO(); img.save(buf, "JPEG")
    result = analyze(buf.getvalue())
    assert result.decision == Decision.UNSUPPORTED


def test_unreadable_upload_is_analyzed_not_rejected(monkeypatch):
    # Fail-open: a real card photo OCR can't read should be ANALYSED, not rejected.
    monkeypatch.setattr(gate, "_ocr_text", lambda ctx: "blur")
    img = Image.new("RGB", (200, 120), (180, 200, 220))
    from io import BytesIO
    buf = BytesIO(); img.save(buf, "JPEG")
    result = analyze(buf.getvalue())
    assert result.decision != Decision.UNSUPPORTED
