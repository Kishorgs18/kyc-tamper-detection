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

# Words that appear on the supported Indian KYC documents:
# Aadhaar, PAN, Driving Licence, Passport.
# Keywords are matched loosely (substring, case-insensitive) AND against a
# space-stripped copy of the text, so noisy OCR like "INCOME  TAX" or
# "PERMANENTACCOUNT" still hits. Short, high-signal fragments are included on
# purpose to tolerate imperfect OCR on real phone photos.
KYC_KEYWORDS = [
    # Aadhaar
    "aadhaar", "aadhar", "government of india", "govt of india",
    "unique identification", "uidai", "vid",
    # PAN
    "income tax", "incometax", "tax department", "permanent account",
    "permanent account number", "account number",
    # Driving Licence
    "driving licence", "driving license", "driving", "licence", "license",
    "transport", "motor vehicle",
    # Passport
    "passport", "republic of india", "nationality", "place of issue",
    "place of birth", "date of issue", "date of expiry",
    # Voter ID (EPIC)
    "election commission", "elector", "electoral", "epic",
    # Common
    "date of birth", "year of birth", "father", "husband",
]
_AADHAAR_RE = re.compile(r"\d{4}\s?\d{4}\s?\d{4}")
_PAN_RE = re.compile(r"[A-Z]{5}\s?[0-9]{4}\s?[A-Z]")
# Indian passport: one letter followed by 7 digits (e.g. A1234567).
_PASSPORT_RE = re.compile(r"\b[A-PR-WYa-pr-wy]\s?[0-9]{7}\b")
# Voter ID / EPIC: three letters followed by 7 digits (e.g. ABC1234567).
_VOTER_RE = re.compile(r"\b[A-Za-z]{3}\s?[0-9]{7}\b")


def _preprocess_for_ocr(cv_image):
    """Grayscale + upscale small images so tesseract reads phone photos better."""
    gray = cv2.cvtColor(cv_image, cv2.COLOR_BGR2GRAY)
    h, w = gray.shape[:2]
    longest = max(h, w)
    if longest < 1600:                       # upscale low-res uploads
        scale = 1600.0 / longest
        gray = cv2.resize(gray, None, fx=scale, fy=scale,
                          interpolation=cv2.INTER_CUBIC)
    return gray


def _ocr_text(ctx: Context) -> str | None:
    """Best-effort OCR. Returns None if tesseract/pytesseract is unavailable."""
    try:
        import pytesseract  # noqa: PLC0415
        from PIL import Image  # noqa: PLC0415

        gray = _preprocess_for_ocr(ctx.cv_image)
        return pytesseract.image_to_string(Image.fromarray(gray))
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
    low_nospace = re.sub(r"\s+", "", low)
    if any(k in low or k.replace(" ", "") in low_nospace for k in KYC_KEYWORDS):
        return "kyc", "KYC keywords found in document text"

    # Match identifier patterns on a space-collapsed copy (OCR adds stray gaps).
    up = text.upper()
    up_nospace = re.sub(r"\s+", "", up)
    if (_AADHAAR_RE.search(up) or _AADHAAR_RE.search(up_nospace)
            or _PAN_RE.search(up) or _PAN_RE.search(up_nospace)
            or _PASSPORT_RE.search(up) or _VOTER_RE.search(up)):
        return "kyc", "an Aadhaar/PAN/Passport/Voter-ID-style identifier was found"

    # Fail open: real card photos often OCR poorly. Only reject when OCR clearly
    # read a substantial NON-KYC text scene; otherwise proceed and analyse, so a
    # genuine document is never wrongly rejected.
    alnum = re.sub(r"[^a-z0-9]", "", low)
    if len(alnum) < 40:
        return "unknown", "OCR could not read enough text to classify; analysing anyway"
    return ("not_kyc",
            "substantial text read but no Aadhaar / PAN / DL / Passport / Voter-ID markers")


def extract_ocr_fields(ctx: Context) -> tuple[dict, str | None]:
    """OCR the image, infer the document type, and pull out its identifier.

    Lets the app auto-fill fields (for the Verhoeff/format checks) without the
    user typing anything. Returns ({}, None) if OCR is unavailable.
    """
    text = _ocr_text(ctx)
    if not text:
        return {}, None
    low = text.lower()
    up_nospace = re.sub(r"\s+", "", text.upper())

    if any(k in low for k in ("aadhaar", "aadhar", "uidai", "unique identification",
                              "govt of india", "government of india")):
        doc_type = "aadhaar"
    elif any(k in low for k in ("income tax", "incometax", "permanent account")):
        doc_type = "pan"
    elif any(k in low for k in ("passport", "republic of india")):
        doc_type = "passport"
    elif any(k in low for k in ("election", "elector", "electoral", "epic")):
        doc_type = "voter"
    elif any(k in low for k in ("driving", "licence", "license", "transport")):
        doc_type = "dl"
    else:
        doc_type = None

    fields: dict = {}
    patterns = {"aadhaar": _AADHAAR_RE, "pan": _PAN_RE,
                "passport": _PASSPORT_RE, "voter": _VOTER_RE}
    if doc_type in patterns:
        m = patterns[doc_type].search(up_nospace)
        if m:
            fields[doc_type] = m.group()
    elif doc_type is None:
        m = _AADHAAR_RE.search(up_nospace)   # a bare 12-digit number ⇒ Aadhaar
        if m:
            fields["aadhaar"] = m.group()
            doc_type = "aadhaar"
    return fields, doc_type
