"""Copy-move detection — finds regions duplicated *within* the same image.

Catches a digit/field/stamp copied over another part of the document. Uses ORB
keypoints matched against themselves, discarding matches between spatially close
features (which are just the same texture). Surviving long-range duplicate
matches are the signal.
"""
from __future__ import annotations

import cv2
import numpy as np

from ..config import COPYMOVE_MIN_DISTANCE, COPYMOVE_MIN_MATCHES
from ..ingest import Context
from ..models import DetectorResult, Finding, Severity
from ..utils import to_b64_png

NAME = "copymove"


def run(ctx: Context) -> DetectorResult:
    findings: list[Finding] = []
    gray = cv2.cvtColor(ctx.cv_image, cv2.COLOR_BGR2GRAY)

    orb = cv2.ORB_create(nfeatures=2000)
    kps, desc = orb.detectAndCompute(gray, None)

    # Collect candidate duplicate matches, then keep only those that AGREE on a
    # single translation offset. Real copy-move shifts a block by one consistent
    # vector; repeated texture / flat regions vote for random offsets and are
    # rejected. This removes the flat-background false positives.
    BIN = 8  # px quantisation for offset voting
    pairs: list[tuple] = []
    if desc is not None and len(kps) > 2:
        bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=False)
        # k=2 so we can skip the trivial self-match (descriptor matches itself).
        matches = bf.knnMatch(desc, desc, k=2)
        for m_set in matches:
            for m in m_set:
                if m.queryIdx == m.trainIdx:
                    continue
                p1 = np.array(kps[m.queryIdx].pt)
                p2 = np.array(kps[m.trainIdx].pt)
                if np.linalg.norm(p1 - p2) < COPYMOVE_MIN_DISTANCE:
                    continue
                if m.distance < 24:  # strict: near-identical descriptor
                    pairs.append((p1, p2))
                break

    # Vote on canonical offsets (v and -v are the same translation).
    votes: dict[tuple, list] = {}
    for p1, p2 in pairs:
        dx, dy = (p2 - p1)
        if dx < 0 or (dx == 0 and dy < 0):
            dx, dy = -dx, -dy
        key = (int(round(dx / BIN)), int(round(dy / BIN)))
        votes.setdefault(key, []).append((p1, p2))

    dominant = max(votes.values(), key=len) if votes else []
    n = len(dominant)

    overlay = ctx.cv_image.copy()
    for p1, p2 in dominant:
        a = tuple(np.round(p1).astype(int))
        b = tuple(np.round(p2).astype(int))
        cv2.line(overlay, a, b, (0, 0, 255), 1)
        cv2.circle(overlay, a, 3, (0, 255, 0), -1)
        cv2.circle(overlay, b, 3, (0, 255, 0), -1)

    if n >= COPYMOVE_MIN_MATCHES:
        findings.append(Finding(
            detector=NAME, code="COPY_MOVE_DETECTED", severity=Severity.SOFT,
            explanation=f"{n} duplicated regions share a consistent offset — "
                        "content may have been copied to cover an edit.",
            score=min(1.0, n / (COPYMOVE_MIN_MATCHES * 3)),
        ))

    return DetectorResult(
        detector=NAME, findings=findings,
        heatmap_b64=to_b64_png(overlay) if n else None,
        meta={"duplicate_pairs": n},
    )
