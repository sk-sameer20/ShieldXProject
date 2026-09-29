"""
tests/test_alert.py — Tests for the shared Alert Pydantic schema.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.common.alert import Alert, make_benign_alert


class TestAlertSchema:

    def test_valid_alert_construction(self):
        alert = Alert(
            threat_class="C2",
            detected=True,
            confidence=0.87,
            severity="high",
            evidence=["periodic connections", "repeated destination"],
            model_version="c2-v1",
        )
        assert alert.threat_class == "C2"
        assert alert.detected is True
        assert alert.confidence == pytest.approx(0.87)

    def test_alert_id_is_generated(self):
        alert = Alert(
            threat_class="DGA",
            detected=True,
            confidence=0.91,
            severity="high",
            evidence=["high entropy"],
            model_version="dga-v1",
        )
        assert alert.alert_id is not None
        assert len(alert.alert_id) > 0

    def test_timestamp_is_generated(self):
        alert = Alert(
            threat_class="DNS_TUNNEL",
            detected=True,
            confidence=0.75,
            severity="high",
            evidence=["long query"],
            model_version="dns-v1",
        )
        assert alert.timestamp > 0

    def test_confidence_below_zero_rejected(self):
        with pytest.raises(ValidationError):
            Alert(
                threat_class="C2",
                detected=True,
                confidence=-0.1,
                severity="medium",
                evidence=["something"],
                model_version="c2-v1",
            )

    def test_confidence_above_one_rejected(self):
        with pytest.raises(ValidationError):
            Alert(
                threat_class="DGA",
                detected=True,
                confidence=1.1,
                severity="high",
                evidence=["something"],
                model_version="dga-v1",
            )

    def test_invalid_threat_class_rejected(self):
        with pytest.raises(ValidationError):
            Alert(
                threat_class="UNKNOWN_THREAT",
                detected=True,
                confidence=0.5,
                severity="medium",
                evidence=["something"],
                model_version="v1",
            )

    def test_invalid_severity_rejected(self):
        with pytest.raises(ValidationError):
            Alert(
                threat_class="C2",
                detected=True,
                confidence=0.5,
                severity="SUPER_HIGH",
                evidence=["something"],
                model_version="c2-v1",
            )

    def test_detected_true_requires_evidence(self):
        """Alert with detected=True and no evidence must fail validation."""
        with pytest.raises(ValidationError):
            Alert(
                threat_class="C2",
                detected=True,
                confidence=0.9,
                severity="high",
                evidence=[],     # empty!
                model_version="c2-v1",
            )

    def test_detected_false_allows_empty_evidence(self):
        alert = Alert(
            threat_class="benign",
            detected=False,
            confidence=0.1,
            severity="low",
            evidence=[],
            model_version="c2-v1",
        )
        assert alert.detected is False

    def test_to_dict_contains_all_fields(self):
        alert = Alert(
            threat_class="DGA",
            detected=True,
            confidence=0.82,
            severity="high",
            evidence=["high entropy domain"],
            model_version="dga-v1",
        )
        d = alert.to_dict()
        assert "alert_id" in d
        assert "timestamp" in d
        assert "threat_class" in d
        assert "detected" in d
        assert "confidence" in d
        assert "severity" in d
        assert "evidence" in d
        assert "model_version" in d

    def test_optional_ip_fields(self):
        alert = Alert(
            threat_class="C2",
            detected=True,
            confidence=0.75,
            severity="medium",
            evidence=["repeated destination"],
            model_version="c2-v1",
            src_ip="10.0.0.25",
            dst_ip="185.220.101.45",
        )
        assert alert.src_ip == "10.0.0.25"
        assert alert.dst_ip == "185.220.101.45"


class TestMakeBenignAlert:

    def test_benign_alert_not_detected(self):
        alert = make_benign_alert(model_version="c2-v1")
        assert alert.detected is False
        assert alert.threat_class == "benign"
        assert alert.severity == "low"

    def test_benign_alert_empty_evidence(self):
        alert = make_benign_alert(model_version="dga-v1")
        assert alert.evidence == []

    def test_benign_alert_with_optional_fields(self):
        alert = make_benign_alert(
            model_version="c2-v1",
            src_ip="10.0.0.1",
            window_start=1000.0,
            window_end=1060.0,
        )
        assert alert.src_ip == "10.0.0.1"
        assert alert.window_start == pytest.approx(1000.0)
        assert alert.window_end == pytest.approx(1060.0)
