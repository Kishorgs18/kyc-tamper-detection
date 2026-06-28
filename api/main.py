"""FastAPI service — the same pipeline behind an HTTP endpoint.

Run:  uvicorn api.main:app --reload
Docs: http://localhost:8000/docs
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, UploadFile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tamper import __version__  # noqa: E402
from tamper.models import AnalysisResult  # noqa: E402
from tamper.pipeline import analyze  # noqa: E402

app = FastAPI(
    title="KYC Tamper Detection",
    version=__version__,
    description="Forensic flagger for KYC documents. Local-only demo. "
                "Indicative results assist human review; not a certified "
                "automated decision system.",
)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.post("/analyze", response_model=AnalysisResult)
async def analyze_endpoint(
    file: UploadFile = File(...),
    doc_type: Optional[str] = Form(None),
    aadhaar: Optional[str] = Form(None),
    pan: Optional[str] = Form(None),
    dob: Optional[str] = Form(None),
    name: Optional[str] = Form(None),
    age: Optional[str] = Form(None),
) -> AnalysisResult:
    raw = await file.read()
    ocr_fields = {
        k: v for k, v in {
            "aadhaar": aadhaar, "pan": pan, "dob": dob, "name": name, "age": age,
        }.items() if v
    }
    return analyze(
        raw,
        ocr_fields=ocr_fields,
        doc_type=doc_type if doc_type not in (None, "auto") else None,
        persist=True,
    )
