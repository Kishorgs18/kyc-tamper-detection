"""Forensic detectors.

Each detector exposes `run(ctx: Context) -> DetectorResult` and is fully
independent — add, remove, or swap one (e.g. drop in a deep-learning detector
later) without touching the others. The router is the only place a decision
is made from their combined findings.
"""
from . import copymove, ela, metadata, noise_jpeg, semantic

# Order is presentation-only; all detectors run regardless.
ALL_DETECTORS = [semantic, metadata, ela, copymove, noise_jpeg]

__all__ = ["ALL_DETECTORS", "semantic", "metadata", "ela", "copymove", "noise_jpeg"]
