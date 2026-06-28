"""Typed data model shared across the pipeline.

Keeping these strict and serializable means the same objects flow through
the Streamlit demo and the FastAPI JSON response unchanged.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"   # contextual, never drives a decision on its own
    SOFT = "soft"   # anomaly worth a human's eyes -> REVIEW
    HARD = "hard"   # strong evidence of manipulation -> HOLD


class Decision(str, Enum):
    CLEAR = "CLEAR"     # no findings; auto-pass candidate
    REVIEW = "REVIEW"   # soft findings; route to human reviewer
    HOLD = "HOLD"       # hard findings; escalate / block pending review
    UNSUPPORTED = "UNSUPPORTED"  # not a recognizable KYC document; not analyzed


class Region(BaseModel):
    """Axis-aligned bounding box in pixel coordinates."""
    x: int
    y: int
    w: int
    h: int


class Finding(BaseModel):
    detector: str
    code: str                       # stable machine code, e.g. "AADHAAR_CHECKSUM_FAIL"
    severity: Severity
    explanation: str                # plain-language, reviewer-facing
    region: Optional[Region] = None
    score: float = 0.0              # detector-local confidence in [0, 1]


class DetectorResult(BaseModel):
    detector: str
    findings: list[Finding] = Field(default_factory=list)
    heatmap_b64: Optional[str] = None   # optional PNG visual evidence (base64)
    meta: dict = Field(default_factory=dict)


class AnalysisResult(BaseModel):
    decision: Decision
    tamper_score: int                   # 0..100, INDICATIVE only (not calibrated)
    doc_type: Optional[str] = None
    findings: list[Finding] = Field(default_factory=list)
    heatmaps: dict[str, str] = Field(default_factory=dict)  # detector -> PNG b64
    ocr_fields: dict = Field(default_factory=dict)          # masked
    summary: str = ""
