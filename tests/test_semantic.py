"""Tests for the semantic detector — the strongest no-data signal."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tamper.detectors.semantic import verhoeff_valid
from tamper.ingest import Context
from tamper.detectors import semantic
from tamper.models import Severity
import numpy as np
from PIL import Image


def _ctx(fields: dict) -> Context:
    img = Image.new("RGB", (32, 32), "white")
    return Context(
        raw_bytes=b"", pil_image=img,
        cv_image=np.zeros((32, 32, 3), dtype=np.uint8),
        ocr_fields=fields,
    )


def test_verhoeff_known_values():
    # Classic Verhoeff example: check digit of 236 is 3 -> "2363" is valid.
    assert verhoeff_valid("2363") is True
    assert verhoeff_valid("2364") is False


def test_aadhaar_bad_checksum_is_hard():
    res = semantic.run(_ctx({"aadhaar": "1234 5678 9012"}))
    codes = {f.code: f.severity for f in res.findings}
    assert "AADHAAR_CHECKSUM_FAIL" in codes
    assert codes["AADHAAR_CHECKSUM_FAIL"] == Severity.HARD


def test_aadhaar_wrong_length():
    res = semantic.run(_ctx({"aadhaar": "12345"}))
    assert any(f.code == "AADHAAR_LENGTH_INVALID" for f in res.findings)


def test_pan_format():
    bad = semantic.run(_ctx({"pan": "ABC123"}))
    assert any(f.code == "PAN_FORMAT_INVALID" for f in bad.findings)
    good = semantic.run(_ctx({"pan": "ABCPK1234L"}))
    assert not any(f.code == "PAN_FORMAT_INVALID" for f in good.findings)


def test_dob_in_future_is_hard():
    res = semantic.run(_ctx({"dob": "01/01/2999"}))
    assert any(f.code == "DOB_IN_FUTURE" and f.severity == Severity.HARD
               for f in res.findings)
