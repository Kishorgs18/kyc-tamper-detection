"""Metadata detector — EXIF / embedded-string forensics on the ORIGINAL bytes.

Cheap and near-zero false positives for *positive* signals (an explicit
"Adobe Photoshop" tag is strong). Note the asymmetry: ABSENCE of camera EXIF
is weak evidence — messaging apps routinely strip metadata — so we flag it
only as INFO, never as proof.
"""
from __future__ import annotations

from io import BytesIO

from PIL import ExifTags, Image

from ..config import EDITOR_SIGNATURES
from ..ingest import Context
from ..models import DetectorResult, Finding, Severity

NAME = "metadata"

_TAG_BY_NAME = {v: k for k, v in ExifTags.TAGS.items()}
_SOFTWARE = _TAG_BY_NAME.get("Software")
_MAKE = _TAG_BY_NAME.get("Make")
_MODEL = _TAG_BY_NAME.get("Model")
_DATETIME = _TAG_BY_NAME.get("DateTime")


def _scan_raw_for_editors(raw: bytes) -> list[str]:
    """Search raw bytes (covers XMP/IPTC/ICC blocks PIL won't expose) for
    known editor signatures."""
    try:
        text = raw.decode("latin-1", errors="ignore").lower()
    except Exception:
        return []
    return [sig for sig in EDITOR_SIGNATURES if sig in text]


def run(ctx: Context) -> DetectorResult:
    findings: list[Finding] = []
    meta: dict = {}

    # 1) EXIF Software tag -------------------------------------------------
    software = ""
    make = model = None
    try:
        exif = Image.open(BytesIO(ctx.raw_bytes)).getexif()
        if exif:
            software = str(exif.get(_SOFTWARE, "") or "")
            make = exif.get(_MAKE)
            model = exif.get(_MODEL)
            meta["software"] = software
            meta["camera"] = f"{make or ''} {model or ''}".strip()
    except Exception:
        pass

    sw_lower = software.lower()
    hit = next((sig for sig in EDITOR_SIGNATURES if sig in sw_lower), None)
    if hit:
        findings.append(Finding(
            detector=NAME, code="EDITOR_IN_SOFTWARE_TAG", severity=Severity.HARD,
            explanation=f"Image metadata names editing software "
                        f"('{software}') — the file was processed by an editor.",
            score=0.9,
        ))

    # 2) Editor signatures anywhere in the raw bytes (XMP etc.) -----------
    raw_hits = _scan_raw_for_editors(ctx.raw_bytes)
    extra = [h for h in raw_hits if h not in sw_lower]
    if extra:
        findings.append(Finding(
            detector=NAME, code="EDITOR_SIGNATURE_IN_BYTES", severity=Severity.SOFT,
            explanation=f"Embedded metadata references an image editor "
                        f"({', '.join(sorted(set(extra)))}).",
            score=0.6,
        ))

    # 3) Missing camera provenance (weak — INFO only) ---------------------
    if not make and not model and not software:
        findings.append(Finding(
            detector=NAME, code="NO_CAMERA_METADATA", severity=Severity.INFO,
            explanation="No camera/software metadata present. Common for "
                        "messaging-app downloads and scans; not proof of tampering.",
            score=0.2,
        ))

    return DetectorResult(detector=NAME, findings=findings, meta=meta)
