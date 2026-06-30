"""Streamlit demo — upload a KYC document, see the tamper analysis.

Run:  streamlit run app/streamlit_app.py

OCR fields can be typed in manually (the production system feeds them from your
existing OCR). An optional pytesseract auto-extract is offered if installed.
"""
from __future__ import annotations

import base64
import hashlib
import sys
from io import BytesIO
from pathlib import Path

import streamlit as st
from PIL import Image

# Make the package importable when run via `streamlit run`.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tamper.models import Decision  # noqa: E402
from tamper.pipeline import analyze  # noqa: E402

_DECISION_STYLE = {
    Decision.CLEAR: ("✅ GENUINE / CLEAR", "#1a7f37"),
    Decision.REVIEW: ("⚠️ SUSPICIOUS / REVIEW", "#9a6700"),
    Decision.HOLD: ("⛔ TAMPERED / HOLD", "#cf222e"),
    Decision.UNSUPPORTED: ("🚫 NOT A KYC DOCUMENT", "#6e7781"),
}


def _b64_to_image(b64: str) -> Image.Image:
    return Image.open(BytesIO(base64.b64decode(b64)))


st.set_page_config(page_title="KYC Tamper Detection", layout="wide")
st.title("🛡️ KYC Document Tamper Detection")
st.caption(
    "Forensic flagger — assists human reviewers. Indicative scores only; "
    "not a certified automated decision system. Runs fully locally."
)

with st.sidebar:
    st.header("Input")
    sample_choice = st.radio(
        "Document source",
        ["Upload my own", "Built-in genuine sample", "Built-in tampered sample"],
        help="Built-in samples are synthetic demo cards — no real personal data.",
    )
    st.divider()
    st.caption(
        "Upload a KYC document — Aadhaar, PAN, Driving Licence, Passport or "
        "Voter ID. The document type and ID number are detected automatically."
    )

raw = None
if sample_choice == "Upload my own":
    uploaded = st.file_uploader(
        "Upload a KYC document image", type=["jpg", "jpeg", "png", "webp", "bmp"]
    )
    if uploaded is not None:
        raw = uploaded.getvalue()
else:
    sample_file = "genuine.png" if "genuine" in sample_choice else "tampered.png"
    sample_path = Path(__file__).resolve().parent.parent / "samples" / sample_file
    raw = sample_path.read_bytes() if sample_path.exists() else None
    if raw is None:
        st.error(f"Sample not found: {sample_path}")

if raw is not None:
    # Built-in samples prefill plausible OCR values so the field-level checks
    # (Verhoeff checksum etc.) are demonstrated; for real uploads the pipeline
    # auto-detects the document type and ID number via OCR.
    ocr_fields = None
    if sample_choice != "Upload my own":
        ocr_fields = (
            {"aadhaar": "2345 6789 0124", "dob": "14/03/1990"}
            if "genuine" in sample_choice
            else {"aadhaar": "1234 5678 9012", "dob": "01/01/1980"}
        )

    # Cache the result by image hash so clicking a verdict button (which reruns
    # the script) does NOT re-run the analysis or create a duplicate record.
    img_hash = hashlib.md5(raw).hexdigest()
    if st.session_state.get("img_hash") != img_hash:
        with st.spinner("Running forensic detectors…"):
            st.session_state["result"] = analyze(raw, ocr_fields=ocr_fields, persist=True)
        st.session_state["img_hash"] = img_hash
        st.session_state["verdict_done"] = False
    result = st.session_state["result"]

    label, color = _DECISION_STYLE[result.decision]
    st.markdown(
        f"<h2 style='color:{color}'>{label}</h2>", unsafe_allow_html=True
    )

    if result.decision == Decision.UNSUPPORTED:
        # Not a KYC document — show the original and the reason, then stop.
        st.warning(result.summary)
        st.image(Image.open(BytesIO(raw)), caption="Uploaded image",
                 use_container_width=True)
        st.stop()

    c1, c2 = st.columns(2)
    c1.metric("Indicative tamper score", f"{result.tamper_score} / 100")
    c2.metric("Detected document type", result.doc_type or "unknown")
    st.info(result.summary)

    # Show actionable findings (SOFT/HARD) prominently; keep INFO context muted
    # so neutral notes (e.g. "no camera metadata" on WhatsApp images) don't read
    # as tamper flags.
    actionable = [f for f in result.findings if f.severity.value != "info"]
    info_notes = [f for f in result.findings if f.severity.value == "info"]

    st.subheader("Findings")
    if actionable:
        st.table([
            {
                "Severity": f.severity.value.upper(),
                "Detector": f.detector,
                "Code": f.code,
                "Explanation": f.explanation,
            }
            for f in actionable
        ])
    else:
        st.success("No tamper indicators raised by any detector.")

    if info_notes:
        with st.expander(f"Context notes ({len(info_notes)}) — not tamper flags"):
            for f in info_notes:
                st.caption(f"• {f.explanation}")

    st.subheader("Evidence")
    cols = st.columns(2)
    cols[0].image(Image.open(BytesIO(raw)), caption="Original", use_container_width=True)
    i = 1
    for detector, b64 in result.heatmaps.items():
        cols[i % 2].image(
            _b64_to_image(b64), caption=f"{detector} heatmap",
            use_container_width=True,
        )
        i += 1

    with st.expander("Masked stored record (privacy-preserving)"):
        st.json({
            "decision": result.decision.value,
            "tamper_score": result.tamper_score,
            "doc_type": result.doc_type,
            "ocr_fields": result.ocr_fields,  # masked identifiers
        })

    # --- Verdict capture: turns each test into a labelled training example ---
    st.divider()
    st.subheader("🏷️ Help improve accuracy")
    st.caption(
        "Tell us the ground truth for this document. It's stored (with masked "
        "data) and used to tune the detectors — this is what turns the demo into "
        "a learning system."
    )
    if st.session_state.get("verdict_done"):
        st.success(f"Thanks! Recorded as **{st.session_state.get('verdict_label')}**.")
    elif not result.record_id:
        st.info("Verdict capture unavailable (the record wasn't stored).")
    else:
        vc1, vc2, vc3 = st.columns(3)
        choice = None
        if vc1.button("✅ Genuine", use_container_width=True):
            choice = "genuine"
        if vc2.button("⚠️ Suspicious", use_container_width=True):
            choice = "suspicious"
        if vc3.button("⛔ Tampered", use_container_width=True):
            choice = "tampered"
        if choice:
            from tamper.store import attach_verdict
            if attach_verdict(result.record_id, choice):
                st.session_state["verdict_done"] = True
                st.session_state["verdict_label"] = choice
                st.rerun()
            else:
                st.error("Could not save the verdict.")
else:
    st.write("⬆️ Upload a document, or pick a **built-in sample** in the "
             "sidebar to begin.")
