"""
src/c2/features.py — C2 Beaconing Feature Extractor

Consumes a list of connection records for a single (src_ip, dst_ip) pair
within a time window and produces a feature dictionary.

Design rules:
- Pure functions only — no model calls, no alerts, no side effects.
- Division-by-zero handled explicitly everywhere.
- All numeric outputs documented with their scale/units.
- Window must be pre-filtered to one (src_ip, dst_ip) pair by the caller.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Dict, List, Optional

import numpy as np

from src.common.entropy import sequence_entropy


# ── Type alias ────────────────────────────────────────────────────────────────
ConnRecord = Dict  # keys: timestamp, src_ip, dst_ip, duration, orig_bytes, resp_bytes, ...


def extract_c2_features(
    records: List[ConnRecord],
    src_ip: Optional[str] = None,
) -> Dict[str, float]:
    """
    Extract C2 behavioral features from a list of connection records.

    The records should represent connections from ONE source host within
    one time window. They may go to multiple destinations; features like
    `dominant_destination_ratio` capture destination concentration.

    Args:
        records: List of connection dicts. Each must contain at minimum:
                 {timestamp: float, dst_ip: str, duration: float,
                  orig_bytes: int, resp_bytes: int}
        src_ip:  Source IP (informational only, not used for computation).

    Returns:
        Feature dict with float values. Returns all-zero features for
        empty or single-record windows (not enough data for IAT/periodicity).
    """
    n = len(records)

    if n == 0:
        return _zero_features()

    # Sort by timestamp ascending
    sorted_records = sorted(records, key=lambda r: r["timestamp"])

    # ── Inter-Arrival Times ────────────────────────────────────────────────
    timestamps = [r["timestamp"] for r in sorted_records]
    iats = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]

    iat_mean = float(np.mean(iats)) if iats else 0.0
    iat_std = float(np.std(iats)) if iats else 0.0

    # Coefficient of Variation — std/mean; safe for mean == 0
    if iat_mean > 0:
        iat_cv = iat_std / iat_mean
    else:
        iat_cv = 0.0

    # ── Periodicity Score via Autocorrelation ──────────────────────────────
    periodicity_score = _compute_periodicity_score(iats)

    # ── Destination Analysis ───────────────────────────────────────────────
    dst_ips = [r.get("dst_ip", "") for r in sorted_records]
    dst_counts = Counter(dst_ips)
    unique_destinations = len(dst_counts)
    top_dst_count = max(dst_counts.values()) if dst_counts else 0
    dominant_destination_ratio = top_dst_count / n if n > 0 else 0.0

    # ── Flow Characteristics ───────────────────────────────────────────────
    durations = [r.get("duration", 0.0) for r in sorted_records]
    orig_bytes_list = [r.get("orig_bytes", 0) for r in sorted_records]
    resp_bytes_list = [r.get("resp_bytes", 0) for r in sorted_records]

    mean_duration = float(np.mean(durations)) if durations else 0.0
    mean_orig_bytes = float(np.mean(orig_bytes_list)) if orig_bytes_list else 0.0
    mean_resp_bytes = float(np.mean(resp_bytes_list)) if resp_bytes_list else 0.0

    total_orig = sum(orig_bytes_list)
    total_resp = sum(resp_bytes_list)
    total_bytes = total_orig + total_resp
    byte_ratio = total_orig / total_bytes if total_bytes > 0 else 0.5

    # Variance of orig_bytes — very consistent sizes hint at templated beacons
    orig_bytes_std = float(np.std(orig_bytes_list)) if orig_bytes_list else 0.0

    # ── IAT entropy — low entropy = very regular timing ───────────────────
    iat_entropy = sequence_entropy(iats) if len(iats) >= 2 else 0.0

    # ── Protocol & Packet Characteristics ──────────────────────────────────
    udp_count = sum(1 for r in sorted_records if r.get("proto", "") == "udp")
    udp_ratio = udp_count / n if n > 0 else 0.0

    pkts_list = [r.get("pkts", 0) for r in sorted_records]
    mean_packets = float(np.mean(pkts_list)) if pkts_list else 0.0

    tcp_records = [r for r in sorted_records if r.get("proto", "") == "tcp"]
    if tcp_records:
        tcp_success_count = sum(r.get("tcp_success", 0) for r in tcp_records)
        tcp_success_ratio = tcp_success_count / len(tcp_records)
    else:
        tcp_success_ratio = 0.0

    return {
        # IAT features
        "iat_mean": iat_mean,
        "iat_std": iat_std,
        "iat_cv": iat_cv,
        "iat_entropy": iat_entropy,
        # Periodicity
        "periodicity_score": periodicity_score,
        # Volume / flow count
        "connection_count": float(n),
        # Destination concentration
        "unique_destinations": float(unique_destinations),
        "dominant_destination_ratio": dominant_destination_ratio,
        # Payload characteristics
        "mean_duration": mean_duration,
        "mean_orig_bytes": mean_orig_bytes,
        "mean_resp_bytes": mean_resp_bytes,
        "orig_bytes_std": orig_bytes_std,
        "byte_ratio": byte_ratio,
        # Protocol & Packet characteristics
        "udp_ratio": udp_ratio,
        "mean_packets": mean_packets,
        "tcp_success_ratio": tcp_success_ratio,
    }


def _compute_periodicity_score(iats: List[float]) -> float:
    """
    Compute a periodicity score in [0.0, 1.0] using autocorrelation of IATs.

    A score close to 1.0 means the IAT sequence is highly periodic.
    A score close to 0.0 means irregular timing.

    Returns 0.0 if fewer than 4 IAT samples exist (not enough for autocorrelation).

    The score is the maximum normalized autocorrelation value at any lag
    from 1 to min(len(iats)-1, max_lag), where max_lag defaults to 20.
    """
    if len(iats) < 4:
        return 0.0

    arr = np.array(iats, dtype=float)
    arr_centered = arr - arr.mean()
    norm = np.dot(arr_centered, arr_centered)

    if norm == 0:
        # Constant IAT — perfectly periodic
        return 1.0

    max_lag = min(len(iats) - 1, 20)
    max_corr = 0.0

    for lag in range(1, max_lag + 1):
        corr = np.dot(arr_centered[:-lag], arr_centered[lag:]) / norm
        if corr > max_corr:
            max_corr = float(corr)

    # Clamp to [0, 1] — negative autocorrelation is not a periodicity signal
    return max(0.0, min(1.0, max_corr))


def _zero_features() -> Dict[str, float]:
    """Return a zero-valued feature dict for empty windows."""
    return {
        "iat_mean": 0.0,
        "iat_std": 0.0,
        "iat_cv": 0.0,
        "iat_entropy": 0.0,
        "periodicity_score": 0.0,
        "connection_count": 0.0,
        "unique_destinations": 0.0,
        "dominant_destination_ratio": 0.0,
        "mean_duration": 0.0,
        "mean_orig_bytes": 0.0,
        "mean_resp_bytes": 0.0,
        "orig_bytes_std": 0.0,
        "byte_ratio": 0.5,
        "udp_ratio": 0.0,
        "mean_packets": 0.0,
        "tcp_success_ratio": 0.0,
    }


# ── Convenience: feature names in fixed order for ML ─────────────────────────
C2_FEATURE_NAMES: List[str] = list(_zero_features().keys())
