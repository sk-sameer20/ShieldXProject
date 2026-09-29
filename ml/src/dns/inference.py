"""
src/dns/inference.py — Thin inference wrapper for DNS Tunnel detector.

Person 4's integration contract:
    from src.dns.inference import run_dns_tunnel_detection
    tunnel_alert = run_dns_tunnel_detection(window, src_ip="10.0.0.40")
"""

from __future__ import annotations

from typing import Dict, List, Optional

from src.dns.tunnel import DNSTunnelDetector
from src.common.schema import Alert

# ── Module-level singleton (lazy-loaded) ──────────────────────────────────────
_tunnel_detector: Optional[DNSTunnelDetector] = None

def _get_tunnel_detector() -> DNSTunnelDetector:
    global _tunnel_detector
    if _tunnel_detector is None:
        _tunnel_detector = DNSTunnelDetector()
    return _tunnel_detector

def run_dns_tunnel_detection(
    window: List[Dict],
    src_ip: Optional[str] = None,
    window_start: Optional[float] = None,
    window_end: Optional[float] = None,
) -> Alert:
    """
    Detect DNS tunnelling from a window of DNS records for one host.

    Args:
        window:       List of DNS record dicts. Required keys: timestamp, query.
                      Optional: qtype, rcode, query_length.
        src_ip:       Source host IP (informational).
        window_start: Window start timestamp (epoch float).
        window_end:   Window end timestamp (epoch float).

    Returns:
        Alert instance. alert.threat_class == "DNS_TUNNEL" when detected.
    """
    return _get_tunnel_detector().predict_from_records(
        records=window,
        src_ip=src_ip,
        window_start=window_start,
        window_end=window_end,
    )
