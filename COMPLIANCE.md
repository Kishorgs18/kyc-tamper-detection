# Compliance & Data-Handling Notes

> Not legal advice. A checklist to take to a qualified legal/compliance
> reviewer before any real-data or production use. Handling Aadhaar/PAN in
> India falls under **UIDAI regulations** and the **DPDP Act, 2023**.

## Current posture (demo)

- Runs **fully locally**; no external network calls in the analysis path.
- **No raw images persisted** by default (`STORE_RAW_IMAGES = False`).
- **No full identifiers persisted** — Aadhaar/PAN are **masked** to the last 4
  characters in all reports and stored records.
- Heatmaps (which embed the document image) are **not** written to the store.
- Ships as a **human-review flagger** — it does not auto-reject anyone.

## Before using real KYC data — checklist

- [ ] **Lawful basis & consent** for processing each document (DPDP).
- [ ] **Data minimisation**: store the least sensitive data needed — prefer
      masked numbers / hashes / detector outputs over raw images.
- [ ] **Retention limits**: define and enforce deletion windows for any raw data.
- [ ] **Encryption** at rest and in transit.
- [ ] **Access control + audit logs**: who viewed/processed which document.
- [ ] **Data residency**: if ever hosted, use an **India region** and confirm
      requirements with legal.
- [ ] **Dataset provenance**: never train on real Aadhaar images of unknown
      origin (e.g. random public dataset dumps). Prefer clearly-synthetic data.
- [ ] **Human-in-the-loop**: do not auto-reject KYC on an unvalidated model —
      both a fairness and a legal risk.

## Validation gate

Accuracy claims require labeled tamper data. Until then:
- Treat all scores as **indicative**, not probabilities.
- Use `tamper/store.py` + `store.attach_verdict()` to accumulate labels.
- Measure precision/recall **per fraud type**, not a single accuracy number.
