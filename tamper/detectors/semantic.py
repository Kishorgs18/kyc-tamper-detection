"""Semantic detector — validates the OCR-extracted fields themselves.

This is the strongest signal available with NO training data, and it survives
the "edit then re-photograph" attack that erases pixel-level forensics:
a tampered Aadhaar number usually fails its Verhoeff checksum, and a patched
PAN often breaks the structural pattern. It reuses the OCR you already have.
"""
from __future__ import annotations

import re
from datetime import date, datetime

from ..ingest import Context
from ..models import DetectorResult, Finding, Severity

NAME = "semantic"

# --- Verhoeff checksum (used by UIDAI for the 12-digit Aadhaar number) ----
_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]

_PAN_RE = re.compile(r"^[A-Z]{5}[0-9]{4}[A-Z]$")
# 4th char of a PAN encodes holder type (P=individual, C=company, etc.)
_PAN_ENTITY_TYPES = set("ABCFGHLJPTK")
# Indian passport: one letter (excluding easily-confused I/O/Q) + 7 digits.
_PASSPORT_RE = re.compile(r"^[A-PR-WY][0-9]{7}$")


def verhoeff_valid(number: str) -> bool:
    """True if `number` (digits only, check digit included) passes Verhoeff."""
    digits = re.sub(r"\D", "", number)
    if not digits:
        return False
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def _parse_dob(value: str) -> date | None:
    value = value.strip()
    for fmt in ("%d/%m/%Y", "%d-%m-%Y", "%Y-%m-%d", "%d.%m.%Y", "%d %m %Y"):
        try:
            return datetime.strptime(value, fmt).date()
        except ValueError:
            continue
    return None


def run(ctx: Context) -> DetectorResult:
    findings: list[Finding] = []
    f = ctx.ocr_fields or {}

    # --- Aadhaar: 12 digits + Verhoeff checksum --------------------------
    aadhaar = re.sub(r"\D", "", str(f.get("aadhaar", "")))
    if aadhaar:
        if len(aadhaar) != 12:
            findings.append(Finding(
                detector=NAME, code="AADHAAR_LENGTH_INVALID", severity=Severity.HARD,
                explanation=f"Aadhaar number has {len(aadhaar)} digits, expected 12.",
                score=0.9,
            ))
        elif not verhoeff_valid(aadhaar):
            findings.append(Finding(
                detector=NAME, code="AADHAAR_CHECKSUM_FAIL", severity=Severity.HARD,
                explanation="Aadhaar number fails the Verhoeff checksum — a digit "
                            "was likely altered.",
                score=0.95,
            ))

    # --- PAN: structural pattern -----------------------------------------
    pan = str(f.get("pan", "")).strip().upper()
    if pan:
        if not _PAN_RE.match(pan):
            findings.append(Finding(
                detector=NAME, code="PAN_FORMAT_INVALID", severity=Severity.HARD,
                explanation="PAN does not match the AAAAA9999A pattern.",
                score=0.85,
            ))
        elif pan[3] not in _PAN_ENTITY_TYPES:
            findings.append(Finding(
                detector=NAME, code="PAN_ENTITY_CHAR_SUSPECT", severity=Severity.SOFT,
                explanation=f"PAN 4th character '{pan[3]}' is not a known holder type.",
                score=0.5,
            ))

    # --- Passport: structural pattern ------------------------------------
    passport = str(f.get("passport", "")).strip().upper()
    if passport:
        if not _PASSPORT_RE.match(passport):
            findings.append(Finding(
                detector=NAME, code="PASSPORT_FORMAT_INVALID", severity=Severity.HARD,
                explanation="Passport number does not match the expected "
                            "1-letter + 7-digit format (e.g. A1234567).",
                score=0.8,
            ))

    # --- Date of birth: must be a valid, plausible past date -------------
    dob_raw = str(f.get("dob", "")).strip()
    if dob_raw:
        dob = _parse_dob(dob_raw)
        if dob is None:
            findings.append(Finding(
                detector=NAME, code="DOB_UNPARSEABLE", severity=Severity.SOFT,
                explanation=f"Date of birth '{dob_raw}' is not a recognisable date.",
                score=0.4,
            ))
        else:
            today = date.today()
            age = (today - dob).days / 365.25
            if dob > today:
                findings.append(Finding(
                    detector=NAME, code="DOB_IN_FUTURE", severity=Severity.HARD,
                    explanation="Date of birth is in the future.", score=0.9,
                ))
            elif age > 120:
                findings.append(Finding(
                    detector=NAME, code="DOB_IMPLAUSIBLE", severity=Severity.SOFT,
                    explanation=f"Implied age (~{age:.0f}) is implausible.", score=0.5,
                ))
            # Cross-check against an explicit age field if present.
            age_field = f.get("age")
            if age_field:
                try:
                    stated = float(age_field)
                    if abs(stated - age) > 2:
                        findings.append(Finding(
                            detector=NAME, code="AGE_DOB_MISMATCH", severity=Severity.SOFT,
                            explanation=f"Stated age {stated:.0f} disagrees with DOB "
                                        f"(~{age:.0f}).",
                            score=0.6,
                        ))
                except ValueError:
                    pass

    return DetectorResult(detector=NAME, findings=findings,
                          meta={"fields_checked": list(f.keys())})
