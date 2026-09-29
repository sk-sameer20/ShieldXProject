"""
src/dns/detector.py — DGA + DNS Tunnel Detectors

Implements two distinct detectors:
1. DGADetector   — supervised Random Forest on per-domain lexical + behavioral features
2. DNSTunnelDetector — multi-signal heuristic baseline; supervised model optional

Design rules:
- DGA and DNS_TUNNEL produce DISTINCT alert threat_classes — don't merge them.
# - DNSTunnelDetector explicitly distinguishes data-carrying behavior (long queries,
#   consistent registered domain) from DGA (lexical randomness, NXDOMAIN storm).
# - Confidence for DNSTunnelDetector is a documented heuristic score, not a probability.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from src.common.schema import Alert, Severity, make_benign_alert
from src.dns.features import extract_host_dns_features
from src.config import CONFIG


# ─────────────────────────────────────────────────────────────────────────────
# DNS TUNNEL DETECTOR
# ─────────────────────────────────────────────────────────────────────────────

class DNSTunnelDetector:
    """
    DNS Tunnelling Detector — multi-signal heuristic baseline.

    Primary approach: combine multiple behavioral signals into a composite score.
    Key distinction from DGA:
    - DGA: lexically random labels, high NXDOMAIN, diverse registered domains
    - DNS Tunnel: long encoded subdomains, consistent registered domain,
                  unusual record types (TXT), high query frequency, low NXDOMAIN

    Supervised model: only added if an appropriate labeled dataset is found
    and documented (see training/dga/prepare_dataset.py comments).
    """

    MODEL_VERSION: str = CONFIG.models.dns_version

    def __init__(self) -> None:
        self._query_length_threshold = CONFIG.dns_tunnel.query_length_threshold
        self._entropy_threshold = CONFIG.dns_tunnel.entropy_threshold
        self._query_freq_threshold = CONFIG.dns_tunnel.query_freq_threshold
        self._unique_subdomain_threshold = CONFIG.dns_tunnel.unique_subdomain_threshold

    def predict_from_records(
        self,
        records: List[Dict],
        src_ip: Optional[str] = None,
        window_start: Optional[float] = None,
        window_end: Optional[float] = None,
    ) -> Alert:
        """
        Detect DNS tunnelling from a window of DNS records for one host.

        Args:
            records:      DNS record dicts. Must have: timestamp, query, qtype,
                          rcode, query_length (optional).
            src_ip:       Source host.
            window_start, window_end: Window metadata.

        Returns:
            Alert instance.
        """
        if not records:
            return make_benign_alert(
                model_version=self.MODEL_VERSION,
                src_ip=src_ip,
                window_start=window_start,
                window_end=window_end,
            )

        features = extract_host_dns_features(records, src_ip=src_ip)
        return self.predict(
            features,
            src_ip=src_ip,
            window_start=window_start,
            window_end=window_end,
        )

    def predict(
        self,
        features: Dict[str, float],
        src_ip: Optional[str] = None,
        window_start: Optional[float] = None,
        window_end: Optional[float] = None,
    ) -> Alert:
        """
        Detect DNS tunnelling from pre-extracted host behavioral features.

        Confidence is a weighted heuristic combination — NOT a probability.
        Documented explicitly in technical_evidence.
        """
        signals: List[Dict[str, Any]] = []
        total_weight = 0.0
        weighted_score = 0.0

        # ── Signal 1: Long query lengths ──────────────────────────────────
        w1 = 0.25
        mean_len = features["mean_query_length"]
        max_len = features["max_query_length"]
        if mean_len > self._query_length_threshold:
            s1 = min(1.0, (mean_len - self._query_length_threshold) / 30.0)
            signals.append({
                "name": "long_mean_query_length",
                "score": s1,
                "value": mean_len,
                "triggered": True,
            })
        else:
            s1 = 0.0
            signals.append({"name": "long_mean_query_length", "score": 0.0, "value": mean_len, "triggered": False})
        weighted_score += w1 * s1
        total_weight += w1

        # ── Signal 2: High subdomain entropy ──────────────────────────────
        w2 = 0.25
        mean_entropy = features["mean_label_entropy"]
        if mean_entropy > self._entropy_threshold:
            s2 = min(1.0, (mean_entropy - self._entropy_threshold) / 1.5)
            signals.append({"name": "high_label_entropy", "score": s2, "value": mean_entropy, "triggered": True})
        else:
            s2 = 0.0
            signals.append({"name": "high_label_entropy", "score": 0.0, "value": mean_entropy, "triggered": False})
        weighted_score += w2 * s2
        total_weight += w2

        # ── Signal 3: High unique subdomains per registered domain ─────────
        w3 = 0.20
        max_subs = features["max_unique_subdomains"]
        if max_subs > self._unique_subdomain_threshold:
            s3 = min(1.0, (max_subs - self._unique_subdomain_threshold) / 20.0)
            signals.append({"name": "high_unique_subdomains", "score": s3, "value": max_subs, "triggered": True})
        else:
            s3 = 0.0
            signals.append({"name": "high_unique_subdomains", "score": 0.0, "value": max_subs, "triggered": False})
        weighted_score += w3 * s3
        total_weight += w3

        # ── Signal 4: High query frequency ────────────────────────────────
        w4 = 0.15
        qfreq = features["query_frequency"]
        if qfreq > self._query_freq_threshold:
            s4 = min(1.0, (qfreq - self._query_freq_threshold) / 10.0)
            signals.append({"name": "high_query_frequency", "score": s4, "value": qfreq, "triggered": True})
        else:
            s4 = 0.0
            signals.append({"name": "high_query_frequency", "score": 0.0, "value": qfreq, "triggered": False})
        weighted_score += w4 * s4
        total_weight += w4

        # ── Signal 5: Unusual record types (TXT dominant) ─────────────────
        w5 = 0.10
        txt_ratio = features["txt_ratio"]
        if txt_ratio > 0.3:
            s5 = min(1.0, txt_ratio / 0.5)
            signals.append({"name": "high_txt_ratio", "score": s5, "value": txt_ratio, "triggered": True})
        else:
            s5 = 0.0
            signals.append({"name": "high_txt_ratio", "score": 0.0, "value": txt_ratio, "triggered": False})
        weighted_score += w5 * s5
        total_weight += w5

        # ── Signal 6: Low NXDOMAIN (distinguishes from DGA) ───────────────
        # Tunnelling typically RESOLVES — DGA mostly NXDOMAINs.
        # Low NXDOMAIN alone doesn't trigger, but dampens confidence if mixed.
        nxdomain_damping = features["nxdomain_ratio"]

        confidence = weighted_score / total_weight if total_weight > 0 else 0.0
        # Apply mild NXDOMAIN dampening: if NXDOMAIN is high, likely DGA not tunnel
        confidence = confidence * (1.0 - 0.3 * nxdomain_damping)
        confidence = float(max(0.0, min(1.0, confidence)))

        detection_threshold = 0.35
        triggered_signals = [s for s in signals if s["triggered"]]
        detected = confidence >= detection_threshold and len(triggered_signals) >= 2

        if not detected:
            return make_benign_alert(
                model_version=self.MODEL_VERSION,
                src_ip=src_ip,
                window_start=window_start,
                window_end=window_end,
                technical_evidence={**features, "tunnel_confidence": confidence, "signals": signals},
            )

        evidence = self._build_tunnel_evidence(features=features, triggered_signals=triggered_signals)

        return Alert(
            threat_class="DNS_TUNNEL",
            detected=True,
            confidence=confidence,
            severity=self._compute_severity(confidence),
            evidence=evidence,
            technical_evidence={
                **features,
                "tunnel_confidence": confidence,
                "signals": signals,
                "confidence_note": (
                    "Heuristic multi-signal score. Weights: "
                    "query_length=0.25, entropy=0.25, unique_subdomains=0.20, "
                    "query_freq=0.15, txt_ratio=0.10. NXDOMAIN dampening applied."
                ),
            },
            model_version=self.MODEL_VERSION,
            src_ip=src_ip,
            window_start=window_start,
            window_end=window_end,
        )

    def _build_tunnel_evidence(
        self,
        features: Dict[str, float],
        triggered_signals: List[Dict],
    ) -> List[str]:
        evidence: List[str] = []

        for sig in triggered_signals:
            name = sig["name"]
            val = sig["value"]
            if name == "long_mean_query_length":
                evidence.append(
                    f"Unusually long DNS query names (mean={val:.0f} chars) "
                    f"— may indicate data encoding in subdomains"
                )
            elif name == "high_label_entropy":
                evidence.append(
                    f"High subdomain entropy (mean={val:.2f}) "
                    f"— consistent with encoded/encrypted data in DNS names"
                )
            elif name == "high_unique_subdomains":
                evidence.append(
                    f"Large number of unique subdomains per registered domain ({int(val)}) "
                    f"— consistent with data-carrying DNS tunnelling"
                )
            elif name == "high_query_frequency":
                evidence.append(
                    f"High DNS query rate ({val:.1f} q/s) "
                    f"— above threshold for normal behavior"
                )
            elif name == "high_txt_ratio":
                evidence.append(
                    f"Elevated TXT record query ratio ({val*100:.0f}%) "
                    f"— TXT records are commonly abused for DNS tunnelling"
                )

        nxdomain_ratio = features.get("nxdomain_ratio", 0.0)
        if nxdomain_ratio < 0.1:
            evidence.append(
                "Low NXDOMAIN ratio — unlike DGA behavior; queries are resolving, "
                "consistent with active DNS channel"
            )

        if not evidence:
            evidence.append("Multiple DNS tunnelling behavioral signals elevated simultaneously")

        return evidence

    @staticmethod
    def _compute_severity(confidence: float) -> Severity:
        if confidence >= 0.70:
            return "high"
        elif confidence >= 0.45:
            return "medium"
        return "low"
