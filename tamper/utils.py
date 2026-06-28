"""Image conversion + small shared helpers."""
from __future__ import annotations

import base64
from io import BytesIO

import cv2
import numpy as np
from PIL import Image

from .config import MASK_VISIBLE_DIGITS


def pil_to_cv(img: Image.Image) -> np.ndarray:
    """PIL RGB(A) -> OpenCV BGR ndarray."""
    arr = np.array(img.convert("RGB"))
    return cv2.cvtColor(arr, cv2.COLOR_RGB2BGR)


def cv_to_pil(arr: np.ndarray) -> Image.Image:
    """OpenCV BGR ndarray -> PIL RGB image."""
    rgb = cv2.cvtColor(arr, cv2.COLOR_BGR2RGB)
    return Image.fromarray(rgb)


def to_b64_png(arr: np.ndarray) -> str:
    """Encode a BGR/gray ndarray as a base64 PNG string."""
    if arr.ndim == 2:
        ok, buf = cv2.imencode(".png", arr)
    else:
        ok, buf = cv2.imencode(".png", arr)
    if not ok:
        raise ValueError("PNG encoding failed")
    return base64.b64encode(buf.tobytes()).decode("ascii")


def heatmap_overlay(base_bgr: np.ndarray, intensity: np.ndarray,
                    alpha: float = 0.45) -> np.ndarray:
    """Overlay a single-channel intensity map onto the image as a colour heatmap."""
    inten = intensity.astype(np.float32)
    if inten.max() > 0:
        inten = inten / inten.max()
    inten_u8 = (inten * 255).astype(np.uint8)
    inten_u8 = cv2.resize(inten_u8, (base_bgr.shape[1], base_bgr.shape[0]))
    colored = cv2.applyColorMap(inten_u8, cv2.COLORMAP_JET)
    return cv2.addWeighted(colored, alpha, base_bgr, 1 - alpha, 0)


def mask_identifier(value: str, visible: int = MASK_VISIBLE_DIGITS) -> str:
    """Mask all but the last `visible` characters. 'XXXXXXXX1234' style.

    Used so logs/stores never retain a full Aadhaar/PAN number by default.
    """
    if not value:
        return ""
    cleaned = value.strip()
    if len(cleaned) <= visible:
        return "X" * len(cleaned)
    return "X" * (len(cleaned) - visible) + cleaned[-visible:]
