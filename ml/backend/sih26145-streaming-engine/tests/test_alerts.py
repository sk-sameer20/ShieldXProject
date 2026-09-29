import pytest
from src.alerts.builder import AlertBuilder
from src.alerts.validator import AlertValidator
from src.alerts.deduplication import AlertDeduplicator


def test_alert_builder_and_validator():
    builder = AlertBuilder()
    validator = AlertValidator()

    alert = builder.build_alert(
        threat_type="DDoS",
        src_ip="10.0.0.50",
        confidence=0.92,
        severity="high",
        evidence=["High PPS"],
        timestamp=100.0
    )

    assert alert.threat_type == "DDoS"
    assert alert.confidence == 0.92
    assert validator.validate(alert) is True


def test_alert_validator_invalid_bounds():
    builder = AlertBuilder()
    validator = AlertValidator()

    alert = builder.build_alert(
        threat_type="DDoS",
        src_ip="10.0.0.50",
        confidence=1.5, # invalid confidence > 1.0
        severity="high",
        evidence=[]
    )

    with pytest.raises(ValueError, match="out of range"):
        validator.validate(alert)


def test_alert_deduplicator():
    dedup = AlertDeduplicator(suppression_window_seconds=30.0)
    builder = AlertBuilder()

    a1 = builder.build_alert("DDoS", "10.0.0.50", 0.9, "high", ["High PPS"], timestamp=10.0)
    a2 = builder.build_alert("DDoS", "10.0.0.50", 0.9, "high", ["High PPS"], timestamp=20.0) # within 30s window
    a3 = builder.build_alert("DDoS", "10.0.0.50", 0.9, "high", ["High PPS"], timestamp=50.0) # after 30s window

    # 1st alert -> emit
    emit1, res1 = dedup.process_alert(a1)
    assert emit1 is True

    # 2nd alert -> suppress emission, increment count
    emit2, res2 = dedup.process_alert(a2)
    assert emit2 is False
    assert res2.suppressed_count == 1

    # 3rd alert -> window expired, emit new alert
    emit3, res3 = dedup.process_alert(a3)
    assert emit3 is True
