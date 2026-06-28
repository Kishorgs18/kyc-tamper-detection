"""Ingest stage: build the analysis Context from raw upload bytes.

Critical detail: we keep the ORIGINAL bytes untouched. Re-saving an image
through PIL/OpenCV destroys EXIF and the JPEG block grid — the very evidence
the metadata/noise detectors rely on. So raw_bytes is the source of truth for
forensic parsing; the decoded arrays are only for pixel-level analysis.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from io import BytesIO
from typing import Optional

import numpy as np
from PIL import Image

from .models import Region
from .utils import pil_to_cv

# Loose patterns used only to *infer* document type from OCR text.
_AADHAAR_RE = re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")
_PAN_RE = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
_DL_HINT_RE = re.compile(r"driving|licence|license|\bDL\b", re.IGNORECASE)
_PASSPORT_HINT_RE = re.compile(r"passport|republic of india|nationality",
                               re.IGNORECASE)


@dataclass
class Context:
    """Everything the detectors need about one document."""
    raw_bytes: bytes
    pil_image: Image.Image
    cv_image: np.ndarray                      # BGR
    doc_type: Optional[str] = None            # "aadhaar" | "pan" | "dl" | None
    ocr_fields: dict = field(default_factory=dict)   # {'aadhaar','pan','dob',...}
    ocr_boxes: dict[str, Region] = field(default_factory=dict)  # field -> Region
    source_text: str = ""                     # raw OCR text, if available


def infer_doc_type(text: str, fields: dict) -> Optional[str]:
    """Best-effort document type inference from OCR text/fields."""
    if fields.get("aadhaar") or _AADHAAR_RE.search(text or ""):
        return "aadhaar"
    if fields.get("pan") or _PAN_RE.search(text or ""):
        return "pan"
    if fields.get("passport") or _PASSPORT_HINT_RE.search(text or ""):
        return "passport"
    if fields.get("dl") or _DL_HINT_RE.search(text or ""):
        return "dl"
    return None


def build_context(
    raw_bytes: bytes,
    *,
    ocr_fields: Optional[dict] = None,
    ocr_boxes: Optional[dict] = None,
    source_text: str = "",
    doc_type: Optional[str] = None,
) -> Context:
    """Decode an upload and assemble a Context.

    OCR is supplied by the caller (the production system already has OCR).
    For the demo, fields can be typed in manually or filled by an optional
    pytesseract fallback — see app/streamlit_app.py.
    """
    pil = Image.open(BytesIO(raw_bytes))
    pil.load()
    cv = pil_to_cv(pil)

    ocr_fields = ocr_fields or {}
    resolved_type = doc_type or infer_doc_type(source_text, ocr_fields)

    return Context(
        raw_bytes=raw_bytes,
        pil_image=pil,
        cv_image=cv,
        doc_type=resolved_type,
        ocr_fields=ocr_fields,
        ocr_boxes=ocr_boxes or {},
        source_text=source_text,
    )
