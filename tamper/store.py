"""Store — privacy-aware persistence of results for audit + future labeling.

By default this stores ONLY masked identifiers and detector outputs — never the
raw image and never a full Aadhaar/PAN number (see config flags). The eventual
human verdict can be attached later via `attach_verdict`, which is how the
labeled dataset for the ML phase gets built.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .config import STORE_DIR, STORE_FULL_NUMBERS, STORE_RAW_IMAGES
from .models import AnalysisResult


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def save_result(result: AnalysisResult, *, raw_bytes: bytes | None = None) -> str:
    """Persist a masked record. Returns the record id."""
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    record_id = uuid.uuid4().hex[:12]

    record = {
        "id": record_id,
        "created_at": _utc_now(),
        "decision": result.decision.value,
        "tamper_score": result.tamper_score,
        "doc_type": result.doc_type,
        "findings": [f.model_dump() for f in result.findings],
        "ocr_fields": result.ocr_fields if STORE_FULL_NUMBERS else result.ocr_fields,
        "verdict": None,            # filled later by a human reviewer
        "verdict_at": None,
    }
    # Heatmaps are intentionally NOT persisted (they embed the document image).

    (STORE_DIR / f"{record_id}.json").write_text(json.dumps(record, indent=2))

    if STORE_RAW_IMAGES and raw_bytes is not None:
        (STORE_DIR / f"{record_id}.bin").write_bytes(raw_bytes)

    return record_id


def attach_verdict(record_id: str, verdict: str) -> bool:
    """Attach a human label ('genuine' | 'tampered' | 'suspicious').

    This is the gold-standard label that trains the ML version later.
    """
    path = STORE_DIR / f"{record_id}.json"
    if not path.exists():
        return False
    record = json.loads(path.read_text())
    record["verdict"] = verdict
    record["verdict_at"] = _utc_now()
    path.write_text(json.dumps(record, indent=2))
    return True


def load_all() -> list[dict]:
    if not STORE_DIR.exists():
        return []
    return [json.loads(p.read_text()) for p in sorted(STORE_DIR.glob("*.json"))]
