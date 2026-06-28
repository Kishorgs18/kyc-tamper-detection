"""KYC gate — decide whether an upload is even a KYC document before analysing.

Rationale: the tamper module detects manipulation *within* a document; it does
not classify document type. In production, the existing OCR is that gate (only
KYC docs reach this module). In this standalone demo there is no OCR, so without
a gate any random image (a selfie, a WhatsApp photo) would get a tamper score.

Logic, in order of confidence:
  1. If OCR already supplied fields / a doc type -> it's a KYC doc (trust OCR).
  2. Else try lightweight OCR (pytesseract) and look for KYC markers.
  3. If OCR is unavailable, return "unknown" and let analysis proceed (so local
     dev without tesseract still works); production always has OCR.
"""
from __future__ import annotations

import re

import cv2

from .ingest import Context

# Words that appear on Indian KYC documents.
KYC_KEYWORDS = [
    "aadhaar", "aadhar", "government of india", "unique identification",
    "uidai", "vid", "income tax department", "permanent account",
    "driving licence", "driving license", "transport department",
    "date of birth", "year of birth",
]
_AADHAAR_RE = re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")
_PAN_RE = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")


def _ocr_text(ctx: Context) -> str | None:
    """Best-effort OCR. Returns None if tesseract/pytesseract is unavailable."""
    try:
        import pytesseract  # noqa: PLC0415
        from PIL import Image  # noqa: PLC0415

        rgb = cv2.cvtColor(ctx.cv_image, cv2.COLOR_BGR2RGB)
        return pytesseract.image_to_string(Image.fromarray(rgb))
    except Exception:
        return None


def looks_like_kyc(ctx: Context) -> tuple[str, str]:
    """Return (status, reason) where status is 'kyc' | 'not_kyc' | 'unknown'."""
    # 1) Trust upstream OCR if it already identified the document.
    if ctx.doc_type or ctx.ocr_fields:
        return "kyc", "document fields supplied by OCR"

    # 2) Try our own lightweight OCR.
    text = _ocr_text(ctx)
    if text is None:
        return "unknown", "OCR unavailable; proceeding without a document gate"

    low = text.lower()
    if any(k in low for k in KYC_KEYWORDS):
        return "kyc", "KYC keywords found in document text"
    if _AADHAAR_RE.search(text) or _PAN_RE.search(text.upper()):
        return "kyc", "an Aadhaar/PAN-style identifier was found"

    return "not_kyc", "no Aadhaar/PAN/Driving-Licence markers detected"
