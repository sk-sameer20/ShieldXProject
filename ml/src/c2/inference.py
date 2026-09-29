"""
src/c2/inference.py — Thin inference wrapper for the C2 detector.

Person 4 calls run_c2_detection(window) and gets an Alert back.
The internal model loading and caching is handled here — Person 4
does not need to know about IsolationForest or feature extraction.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Optional

from src.c2.detector import C2Detector
from src.c2.features import extract_c2_features
from src.common.alert import Alert

# ── Default model path ────────────────────────────────────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_DEFAULT_MODEL_PATH = _PROJECT_ROOT / "models" / "c2" / "c2_model.joblib"

# ── Module-level singleton (lazy-loaded on first call) ────────────────────────
_detector: Optional[C2Detector] = None


def _get_detector() -> C2Detector:
    """Load the detector on first use (lazy singleton)."""
    global _detector
    if _detector is None:
        model_path = os.environ.get("C2_MODEL_PATH", str(_DEFAULT_MODEL_PATH))
        if Path(model_path).exists():
            _detector = C2Detector.load(model_path)
        else:
            # No trained model yet — create an unfitted detector.
            # predict() will return benign alerts until fit() is called.
            _detector = C2Detector()
    return _detector


def run_c2_detection(
    window: List[Dict],
    src_ip: Optional[str] = None,
    window_start: Optional[float] = None,
    window_end: Optional[float] = None,
) -> Alert:
    """
    Detect C2 beaconing from a window of connection records.

    This is the integration contract for Person 4.

    Args:
        window:       List of connection record dicts for ONE source host.
                      Expected keys: timestamp, dst_ip, duration,
                      orig_bytes, resp_bytes. Extra keys are ignored.
        src_ip:       Source IP for the alert (informational).
        window_start: Window start timestamp (epoch float).
        window_end:   Window end timestamp (epoch float).

    Returns:
        Alert instance. Check alert.detected for True/False.

    Example:
        from src.c2.inference import run_c2_detection
        alert = run_c2_detection(window, src_ip="10.0.0.25")
        print(alert.detected, alert.confidence, alert.evidence)
    """
    detector = _get_detector()
    return detector.predict_from_records(
        records=window,
        src_ip=src_ip,
        window_start=window_start,
        window_end=window_end,
    )


def reload_detector(model_path: Optional[str] = None) -> None:
    """
    Force reload the detector from disk (e.g., after a model update).

    Args:
        model_path: Optional override path. If None, uses default path.
    """
    global _detector
    path = model_path or str(_DEFAULT_MODEL_PATH)
    if Path(path).exists():
        _detector = C2Detector.load(path)
    else:
        _detector = C2Detector()
