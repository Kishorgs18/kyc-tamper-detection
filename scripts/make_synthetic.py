"""Synthetic demo-data generator.

Two uses:
  1. Build a clean "genuine-looking" mock KYC card from scratch (no real PII).
  2. Take any genuine-looking image and produce TAMPERED variants, so you have
     labeled genuine/tampered PAIRS to demo and to measure detectors with —
     without ever touching a real person's Aadhaar.

Usage:
  python scripts/make_synthetic.py mock   --out data/uploads/genuine.png
  python scripts/make_synthetic.py tamper --in  data/uploads/genuine.png \
                                          --out data/uploads/tampered.png
"""
from __future__ import annotations

import argparse
import random
from pathlib import Path

import cv2
import numpy as np
from PIL import Image, ImageDraw, ImageFont


def _font(size: int):
    try:
        return ImageFont.truetype("DejaVuSans.ttf", size)
    except Exception:
        return ImageFont.load_default()


def make_mock_card(out: Path) -> None:
    """A clearly-FAKE sample card with non-real numbers (Verhoeff-valid demo)."""
    img = Image.new("RGB", (640, 400), (245, 245, 240))
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, 640, 70], fill=(220, 120, 40))
    d.text((20, 22), "GOVERNMENT OF SAMPLE  (DEMO ONLY)", font=_font(22), fill="white")
    d.rectangle([30, 110, 170, 290], outline=(120, 120, 120), width=2)
    d.text((55, 190), "PHOTO", font=_font(20), fill=(120, 120, 120))
    d.text((200, 120), "Name: ASHA SAMPLE", font=_font(24), fill="black")
    d.text((200, 160), "DOB: 14/03/1990", font=_font(24), fill="black")
    d.text((200, 200), "Gender: Female", font=_font(24), fill="black")
    # A demo 12-digit number that passes Verhoeff (generated, not a real Aadhaar).
    d.text((200, 250), "2345 6789 0124", font=_font(30), fill=(20, 20, 80))

    # Add faint sensor-like noise so the card resembles a real photograph:
    # this makes every region unique (no pixel-perfect duplicate glyphs), which
    # is what a genuine camera capture looks like.
    arr = np.asarray(img).astype(np.int16)
    noise = np.random.normal(0, 4, arr.shape).astype(np.int16)
    arr = np.clip(arr + noise, 0, 255).astype(np.uint8)
    img = Image.fromarray(arr)

    out.parent.mkdir(parents=True, exist_ok=True)
    img.save(out, "JPEG", quality=95)
    print(f"wrote mock card -> {out}")


def tamper(in_path: Path, out: Path) -> None:
    """Apply a random tamper: copy-move a patch + splice over a text region."""
    img = cv2.imread(str(in_path))
    if img is None:
        raise SystemExit(f"could not read {in_path}")
    h, w = img.shape[:2]

    # 1) Copy-move: duplicate a TEXT-RICH patch (guaranteed keypoints) onto
    #    another location so the offset-voting detector reliably catches it.
    src = img[245:285, 200:380].copy()          # the number/text band
    ph, pw = src.shape[:2]
    dy, dx = 300, 200
    if dy + ph <= h and dx + pw <= w:
        img[dy:dy + ph, dx:dx + pw] = src

    # 2) Splice: paint over the DOB area and write a different value (different
    #    noise floor -> the noise detector should react).
    cv2.rectangle(img, (200, 158), (430, 188), (245, 245, 240), -1)
    cv2.putText(img, "DOB: 01/01/1980", (202, 182),
                cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 0), 2)

    out.parent.mkdir(parents=True, exist_ok=True)
    # Re-save at a different quality to perturb the JPEG history.
    cv2.imwrite(str(out), img, [cv2.IMWRITE_JPEG_QUALITY, 75])
    print(f"wrote tampered variant -> {out}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    m = sub.add_parser("mock", help="generate a clean fake sample card")
    m.add_argument("--out", type=Path, default=Path("data/uploads/genuine.png"))

    t = sub.add_parser("tamper", help="produce a tampered variant of an image")
    t.add_argument("--in", dest="inp", type=Path, required=True)
    t.add_argument("--out", type=Path, default=Path("data/uploads/tampered.png"))

    args = p.parse_args()
    if args.cmd == "mock":
        make_mock_card(args.out)
    else:
        tamper(args.inp, args.out)


if __name__ == "__main__":
    main()
