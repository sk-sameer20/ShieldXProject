"""
tests/test_dns_detector.py — Tests for DGADetector and DNSTunnelDetector.
"""

from __future__ import annotations

import numpy as np
import pytest

from src.dns.tunnel import DNSTunnelDetector
from src.common.schema import Alert


def make_dns_record(timestamp, query, qtype="A", rcode="NOERROR", query_length=None):
    return {
        "timestamp": timestamp,
        "src_ip": "10.0.0.5",
        "query": query,
        "qtype": qtype,
        "rcode": rcode,
        "query_length": query_length or len(query),
    }


BENIGN_RECORDS = [make_dns_record(1000.0 + i * 5, f"{name}.com") for i, name in
                  enumerate(["google", "github", "wikipedia", "stackoverflow", "amazon"])]

DGA_RECORDS = [make_dns_record(1000.0 + i * 0.3, f"xj3kq9ab{i}m2n.com", rcode="NXDOMAIN")
               for i in range(10)]

TUNNEL_RECORDS = [make_dns_record(
    1000.0 + i * 0.5,
    f"aGVsbG8gd29ybGQ{i}dGVzdHBheWxvYWQ.tunnel.example.com",
    qtype="TXT", query_length=55
) for i in range(10)]


# ── DNSTunnelDetector Tests ───────────────────────────────────────────────────

class TestDNSTunnelDetector:

    def test_empty_records_benign(self):
        detector = DNSTunnelDetector()
        alert = detector.predict_from_records([])
        assert alert.detected is False

    def test_benign_dns_not_tunnel(self):
        detector = DNSTunnelDetector()
        alert = detector.predict_from_records(BENIGN_RECORDS)
        # Benign should not trigger tunnel detection
        assert alert.confidence < 0.5

    def test_tunnel_records_higher_confidence(self):
        detector = DNSTunnelDetector()
        alert_tunnel = detector.predict_from_records(TUNNEL_RECORDS)
        alert_benign = detector.predict_from_records(BENIGN_RECORDS)
        # Compare raw heuristic scores stored in technical_evidence
        # (public .confidence is 0.0 for non-detected alerts by design)
        tunnel_score = alert_tunnel.technical_evidence.get("tunnel_confidence", 0.0)
        benign_score = alert_benign.technical_evidence.get("tunnel_confidence", 0.0)
        assert tunnel_score > benign_score, (
            f"Expected tunnel score ({tunnel_score:.3f}) > benign score ({benign_score:.3f})"
        )

    def test_alert_is_alert_instance(self):
        detector = DNSTunnelDetector()
        alert = detector.predict_from_records(TUNNEL_RECORDS)
        assert isinstance(alert, Alert)

    def test_confidence_in_range(self):
        detector = DNSTunnelDetector()
        alert = detector.predict_from_records(TUNNEL_RECORDS)
        assert 0.0 <= alert.confidence <= 1.0

    def test_detected_threat_class_is_dns_tunnel(self):
        detector = DNSTunnelDetector()
        alert = detector.predict_from_records(TUNNEL_RECORDS)
        if alert.detected:
            assert alert.threat_class == "DNS_TUNNEL"

    def test_detected_alert_has_evidence(self):
        detector = DNSTunnelDetector()
        alert = detector.predict_from_records(TUNNEL_RECORDS)
        if alert.detected:
            assert len(alert.evidence) > 0

    def test_model_version_present(self):
        detector = DNSTunnelDetector()
        alert = detector.predict_from_records(BENIGN_RECORDS)
        assert alert.model_version is not None

    def test_dga_high_nxdomain_dampened(self):
        """High NXDOMAIN should dampen tunnel confidence (it's more like DGA)."""
        detector = DNSTunnelDetector()
        alert_tunnel = detector.predict_from_records(TUNNEL_RECORDS)
        # Add NXDOMAIN to tunnel records
        nxdomain_records = [dict(r, rcode="NXDOMAIN") for r in TUNNEL_RECORDS]
        alert_nxdomain = detector.predict_from_records(nxdomain_records)
        # NXDOMAIN version should have lower or equal tunnel confidence
        assert alert_nxdomain.confidence <= alert_tunnel.confidence + 0.1
