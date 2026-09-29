"""
Comprehensive Pydantic v2 Schema Validation Tests for ShieldX SOC
Tests confidence bounds, IP address validation, enums, and data integrity.
"""
from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from app.models.schemas import (
    AlertSeverity,
    TriageStatus,
    AlertStatus,
    ThreatClass,
    AlertEvidence,
    AlertCreate,
    AlertResponse,
    AlertListResponse,
    DetectorStatus,
    Statistics,
    ThreatCategoryItem,
    ThreatDistribution,
    TimelinePoint,
    TrafficPoint,
    GaugeItem,
    DataSourceItem,
    SensorNetworkItem,
    DiodeIntegrityItem,
    HealthResponse,
    WebSocketAlertEvent,
)


# ═══════════════════════════════════════════════════════════════
# 1. ALERT CREATE TESTS (CONFIDENCE, IP, ENUMS)
# ═══════════════════════════════════════════════════════════════

def test_alert_create_valid():
    """Test creating an AlertCreate with full valid parameters."""
    payload = {
        "alert_id": "alt-ddos-8901",
        "timestamp": datetime.now(timezone.utc),
        "threat_class": ThreatClass.DDOS,
        "attack_classification": "DDOS",
        "severity": AlertSeverity.CRITICAL,
        "confidence": 0.98,
        "source_ip": "198.51.100.44",
        "destination_ip": "10.240.0.12",
        "source_port": 54112,
        "destination_port": 443,
        "transport_protocol": "TCP : 443",
        "status": AlertStatus.MITIGATED,
        "triage_status": TriageStatus.NEW,
        "model_version": "v3.2.0",
        "detector_model": "Ensemble-Volumetric-SYN-Burst",
        "mitre_technique": "T1498.001",
        "reason": "Abnormal volumetric SYN burst exceeding baseline by 840%.",
        "evidence": {
            "rule_or_model": "Ensemble-Volumetric-SYN-Burst",
            "why_flagged": "SYN spike detected",
            "trigger_features": {"syn_pps": 28400},
        },
        "trigger_features": {"syn_arrival_rate_pps": 28400},
    }
    alert = AlertCreate(**payload)
    assert alert.alert_id == "alt-ddos-8901"
    assert alert.confidence == 0.98
    assert alert.source_ip == "198.51.100.44"
    assert alert.destination_ip == "10.240.0.12"
    assert alert.severity == AlertSeverity.CRITICAL
    assert alert.triage_status == TriageStatus.NEW


@pytest.mark.parametrize("invalid_confidence", [-0.01, -1.0, 1.01, 2.5, 98.0])
def test_alert_create_confidence_out_of_bounds(invalid_confidence):
    """Test that confidence strictly outside [0, 1] raises a ValidationError."""
    payload = {
        "alert_id": "alt-ddos-8901",
        "threat_class": "DDOS",
        "attack_classification": "DDOS",
        "severity": "CRITICAL",
        "confidence": invalid_confidence,
        "source_ip": "198.51.100.44",
        "destination_ip": "10.240.0.12",
        "transport_protocol": "TCP",
        "detector_model": "XGBoost",
        "reason": "Testing confidence bounds",
    }
    with pytest.raises(ValidationError) as exc_info:
        AlertCreate(**payload)
    errors = str(exc_info.value)
    assert "confidence" in errors


@pytest.mark.parametrize("valid_confidence", [0.0, 0.0001, 0.5, 0.98, 1.0])
def test_alert_create_confidence_valid_boundary(valid_confidence):
    """Test that boundary values 0.0, 1.0, and standard floats pass validation."""
    payload = {
        "alert_id": "alt-test-01",
        "threat_class": "DDOS",
        "attack_classification": "DDOS",
        "severity": "CRITICAL",
        "confidence": valid_confidence,
        "source_ip": "198.51.100.44",
        "destination_ip": "10.240.0.12",
        "transport_protocol": "TCP",
        "detector_model": "XGBoost",
        "reason": "Testing boundary",
    }
    alert = AlertCreate(**payload)
    assert alert.confidence == valid_confidence


@pytest.mark.parametrize("invalid_ip", ["not-an-ip", "999.999.999.999", "10.240.0.999", "256.0.0.1", ""])
def test_alert_create_invalid_source_ip(invalid_ip):
    """Test that invalid IP formats raise ValidationError."""
    payload = {
        "alert_id": "alt-test-02",
        "threat_class": "DDOS",
        "attack_classification": "DDOS",
        "severity": "CRITICAL",
        "confidence": 0.85,
        "source_ip": invalid_ip,
        "destination_ip": "10.240.0.12",
        "transport_protocol": "TCP",
        "detector_model": "XGBoost",
        "reason": "Testing IP format",
    }
    with pytest.raises(ValidationError) as exc_info:
        AlertCreate(**payload)
    assert "source_ip" in str(exc_info.value)


def test_alert_create_ipv6_support():
    """Test that standard IPv6 addresses are accepted and validated."""
    payload = {
        "alert_id": "alt-test-ipv6",
        "threat_class": "C2_BEACONING",
        "attack_classification": "C2",
        "severity": "HIGH",
        "confidence": 0.91,
        "source_ip": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "destination_ip": "::1",
        "transport_protocol": "TCP",
        "detector_model": "LSTM",
        "reason": "IPv6 test",
    }
    alert = AlertCreate(**payload)
    assert alert.source_ip == "2001:db8:85a3::8a2e:370:7334"
    assert alert.destination_ip == "::1"


def test_alert_create_invalid_enums():
    """Test that unapproved severity or triage status strings are rejected."""
    base_payload = {
        "alert_id": "alt-test-enum",
        "threat_class": "DDOS",
        "attack_classification": "DDOS",
        "confidence": 0.85,
        "source_ip": "198.51.100.44",
        "destination_ip": "10.240.0.12",
        "transport_protocol": "TCP",
        "detector_model": "XGBoost",
        "reason": "Testing enums",
    }

    # Invalid severity
    with pytest.raises(ValidationError):
        AlertCreate(**{**base_payload, "severity": "EXTREME"})

    # Invalid triage status
    with pytest.raises(ValidationError):
        AlertCreate(**{**base_payload, "severity": "HIGH", "triage_status": "PENDING_APPROVAL"})

    # Invalid operational status
    with pytest.raises(ValidationError):
        AlertCreate(**{**base_payload, "severity": "HIGH", "status": "DESTROYED"})


# ═══════════════════════════════════════════════════════════════
# 2. ALERT EVIDENCE TESTS
# ═══════════════════════════════════════════════════════════════

def test_alert_evidence_schema():
    """Test structured evidence fusion model."""
    evidence = AlertEvidence(
        rule_or_model="Entropy-DGA-Classifier-v2",
        trigger_features={"domain_entropy": 4.62, "txt_ratio": 0.78},
        why_flagged="Anomalous domain entropy",
        mitre_technique_id="T1071.004",
        mitre_tactic="Exfiltration",
    )
    assert evidence.rule_or_model == "Entropy-DGA-Classifier-v2"
    assert evidence.mitre_technique_id == "T1071.004"


def test_alert_evidence_invalid_mitre():
    """Test invalid MITRE format raises regex validation error."""
    with pytest.raises(ValidationError):
        AlertEvidence(
            rule_or_model="Model",
            why_flagged="Reason",
            mitre_technique_id="INVALID-MITRE",
        )


# ═══════════════════════════════════════════════════════════════
# 3. ALERT RESPONSE & LIST RESPONSE TESTS
# ═══════════════════════════════════════════════════════════════

def test_alert_response_mapping():
    """Test AlertResponse contract formatting."""
    resp = AlertResponse(
        id="alt-ddos-8901",
        alert_id="alt-ddos-8901",
        timestamp=datetime(2026, 9, 24, 5, 11, 12, tzinfo=timezone.utc),
        time="05:11:12",
        dateLabel="Today",
        severity=AlertSeverity.CRITICAL,
        classification="DDOS",
        threat_class="DDOS",
        srcIp="198.51.100.44",
        destIp="10.240.0.12",
        source_ip="198.51.100.44",
        destination_ip="10.240.0.12",
        protocol="TCP : 443",
        confidence=0.98,
        confidence_pct=98.0,
        confidenceFormatted="98.0%",
        triage="NEW",
        triage_status=TriageStatus.NEW,
        triageType="danger",
        status=AlertStatus.MITIGATED,
        accentColor="#ef4444",
        whyFlagged="Abnormal volumetric SYN burst",
        reason="Abnormal volumetric SYN burst",
        detectorModel="Ensemble-Volumetric-SYN-Burst",
        detector_model="Ensemble-Volumetric-SYN-Burst",
        mitre="T1498.001",
        triggerFeatures={"syn_arrival_rate_pps": 28400},
        trigger_features={"syn_arrival_rate_pps": 28400},
    )
    assert resp.id == "alt-ddos-8901"
    assert resp.confidenceFormatted == "98.0%"
    assert resp.severity == AlertSeverity.CRITICAL


def test_alert_list_response():
    """Test AlertListResponse structure."""
    list_resp = AlertListResponse(
        total=1,
        counts={"all": 1, "critical": 1, "high": 0, "medium": 0, "low": 0},
        items=[],
        page=1,
        page_size=10,
        total_pages=1,
    )
    assert list_resp.total == 1
    assert list_resp.counts["critical"] == 1


# ═══════════════════════════════════════════════════════════════
# 4. DETECTOR STATUS TESTS
# ═══════════════════════════════════════════════════════════════

def test_detector_status_schema():
    """Test DetectorStatus schema."""
    detector = DetectorStatus(
        engine_type="DDOS",
        status="ACTIVE THREAT",
        rule_name="Ensemble-Volumetric-SYN-Burst",
        target_host="10.240.0.12:443",
        attack_vector="TCP SYN Flood (Unidirectional)",
        cadence_or_duration="45.2 seconds",
        recommended_action="Rate-limit boundary ingress",
        metrics={"syn_pps": 28400, "confidence": 98.4},
    )
    assert detector.engine_type == "DDOS"
    assert detector.metrics["syn_pps"] == 28400


# ═══════════════════════════════════════════════════════════════
# 5. STATISTICS & UNIDIRECTIONAL CONSTRAINTS TESTS
# ═══════════════════════════════════════════════════════════════

def test_statistics_valid():
    """Test Statistics schema calculation metrics."""
    stats = Statistics(
        total_alerts=14,
        critical_count=3,
        high_count=5,
        medium_count=4,
        low_count=2,
        active_flows=4821,
        packets_per_sec=18400.0,
        bytes_per_sec=92700000.0,
        mbps=92.7,
        detection_latency_ms=740.0,
        actual_egress_packets=0,
        actual_egress_bytes=0,
    )
    assert stats.total_alerts == 14
    assert stats.actual_egress_packets == 0
    assert stats.actual_egress_bytes == 0


def test_statistics_egress_must_be_zero():
    """Test that actual_egress_packets > 0 is rejected (hardware diode guarantee)."""
    with pytest.raises(ValidationError):
        Statistics(
            total_alerts=14,
            critical_count=3,
            high_count=5,
            medium_count=4,
            low_count=2,
            active_flows=4821,
            packets_per_sec=18400.0,
            bytes_per_sec=92700000.0,
            mbps=92.7,
            detection_latency_ms=740.0,
            actual_egress_packets=10,  # Invalid: Hardware diode cannot leak packets
            actual_egress_bytes=0,
        )


# ═══════════════════════════════════════════════════════════════
# 6. THREAT DISTRIBUTION TESTS
# ═══════════════════════════════════════════════════════════════

def test_threat_distribution_schema():
    """Test ThreatDistribution schema."""
    dist = ThreatDistribution(
        filter_mode="Observed (Inbound)",
        total_threats=14,
        categories=[
            ThreatCategoryItem(label="DDoS", pct=34.0, pct_formatted="34%", count=5, color="#ef4444"),
            ThreatCategoryItem(label="C2", pct=18.0, pct_formatted="18%", count=3, color="#f97316"),
        ],
    )
    assert dist.total_threats == 14
    assert len(dist.categories) == 2
    assert dist.categories[0].label == "DDoS"


# ═══════════════════════════════════════════════════════════════
# 7. TIMELINE POINT & TRAFFIC POINT TESTS
# ═══════════════════════════════════════════════════════════════

def test_timeline_point():
    """Test TimelinePoint schema."""
    point = TimelinePoint(
        timestamp=datetime.now(timezone.utc),
        time_label="14:24:17",
        event_type="DDoS Volumetric Burst",
        severity=AlertSeverity.CRITICAL,
        description="SYN flood surge",
        source_ip="198.51.100.44",
    )
    assert point.severity == AlertSeverity.CRITICAL


def test_traffic_point():
    """Test TrafficPoint telemetry chart point."""
    point = TrafficPoint(
        timestamp=datetime.now(timezone.utc),
        time_label="14:24",
        packets_per_sec=21400.0,
        bytes_per_sec=109100000.0,
        mbps=109.1,
        is_anomaly=True,
        anomaly_val="21.4K pps",
    )
    assert point.is_anomaly is True
    assert point.anomaly_val == "21.4K pps"


# ═══════════════════════════════════════════════════════════════
# 8. HEALTH RESPONSE & HARDWARE DIODE TESTS
# ═══════════════════════════════════════════════════════════════

def test_health_response_schema():
    """Test HealthResponse with full gauges, sources, and diode integrity."""
    health = HealthResponse(
        status="Healthy",
        gauges=[
            GaugeItem(label="CPU", val=98.0, detail="32 Cores · 48°C", color="#10b981"),
            GaugeItem(label="Memory", val=76.0, detail="24.3 / 32 GB", color="#00d2ff"),
        ],
        sources=[
            DataSourceItem(name="Firewall Telemetry", status="Online", latency="1.2ms"),
        ],
        sensor_network=SensorNetworkItem(
            online_sensors=12,
            total_sensors=12,
            regions_count=3,
            uptime_pct=99.98,
            avg_latency="0.8ms",
        ),
        diode_integrity=DiodeIntegrityItem(
            physical_link_rx=True,
            physical_link_tx=False,
            optical_power_dbm=-13.8,
            ring_buffer_utilization_pct=18.4,
            dropped_frames=0,
            diode_state="NOMINAL",
            tamper_evident_chain_valid=True,
            last_audit_hash="8f43a9b1c78e3290deaf1455bb39c011e4f9b8c2d1109a8734e5f901a1829bc3",
        ),
    )
    assert health.status == "Healthy"
    assert health.diode_integrity.physical_link_tx is False


# ═══════════════════════════════════════════════════════════════
# 9. WEBSOCKET ALERT EVENT TESTS
# ═══════════════════════════════════════════════════════════════

def test_websocket_alert_event():
    """Test encapsulation of AlertResponse inside WebSocketAlertEvent."""
    alert_resp = AlertResponse(
        id="alt-ddos-8901",
        alert_id="alt-ddos-8901",
        timestamp=datetime.now(timezone.utc),
        time="05:11:12",
        dateLabel="Today",
        severity=AlertSeverity.CRITICAL,
        classification="DDOS",
        threat_class="DDOS",
        srcIp="198.51.100.44",
        destIp="10.240.0.12",
        source_ip="198.51.100.44",
        destination_ip="10.240.0.12",
        protocol="TCP : 443",
        confidence=0.98,
        confidence_pct=98.0,
        confidenceFormatted="98.0%",
        triage="NEW",
        triage_status=TriageStatus.NEW,
        triageType="danger",
        status=AlertStatus.MITIGATED,
        accentColor="#ef4444",
        whyFlagged="Abnormal volumetric SYN burst",
        reason="Abnormal volumetric SYN burst",
        detectorModel="Ensemble-Volumetric-SYN-Burst",
        detector_model="Ensemble-Volumetric-SYN-Burst",
        mitre="T1498.001",
    )
    event = WebSocketAlertEvent(event="NEW_ALERT", data=alert_resp)
    assert event.event == "NEW_ALERT"
    assert event.data.id == "alt-ddos-8901"
    assert event.data.confidence == 0.98
