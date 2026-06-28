"""Central configuration.

Privacy/isolation defaults are intentionally conservative — see COMPLIANCE.md.
Thresholds are *indicative* and must be tuned once labeled data exists.
"""
from __future__ import annotations

from pathlib import Path

# --- Paths ---------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
STORE_DIR = DATA_DIR / "store"
UPLOAD_DIR = DATA_DIR / "uploads"

# --- Privacy (UIDAI / DPDP-aware defaults) -------------------------------
# Never persist raw KYC images or full identifiers unless a reviewed policy
# explicitly enables it. The flagger does not need the sensitive payload.
STORE_RAW_IMAGES = False
STORE_FULL_NUMBERS = False
MASK_VISIBLE_DIGITS = 4

# --- Metadata detector ---------------------------------------------------
# Software signatures that indicate image editing.
EDITOR_SIGNATURES = [
    "adobe photoshop", "photoshop", "gimp", "paint.net", "pixelmator",
    "snapseed", "picsart", "lightroom", "affinity", "inkscape",
    "coreldraw", "canva", "facetune", "fotor", "photoscape",
]

# --- ELA detector --------------------------------------------------------
ELA_QUALITY = 90              # recompression quality for Error Level Analysis
ELA_SOFT_THRESHOLD = 0.20    # normalized mean bright-residual to raise a soft flag

# --- Noise / field-consistency detector ----------------------------------
FIELD_NOISE_RATIO_SOFT = 1.8  # per-field residual energy vs document baseline

# --- Copy-move detector --------------------------------------------------
COPYMOVE_MIN_MATCHES = 12     # min duplicated keypoint matches to flag
COPYMOVE_MIN_DISTANCE = 40    # px; ignore matches closer than this (same feature)
