"""
Comprehensive API Endpoint Tests for ShieldX SOC
Tests all REST endpoints, status codes, query filtering, validation errors, and CORS headers.
"""
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.deps import get_db
from app.main import app
from app.models.base import Base
from app.models.alert import Alert
from app.models.detection import DetectionAttribution
from app.models.health import DiodeIntegrity, SystemHealth
from app.models.telemetry import TelemetrySnapshot


@pytest.fixture(scope="module")
def test_client():
    """Create a TestClient with an isolated in-memory test database using StaticPool."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    # Seed baseline health, detectors, alerts, and telemetry in test db
    with TestingSession() as session:
        # Seed an alert
        alert = Alert(
            alert_id="alt-api-test-01",
            timestamp=datetime(2026, 9, 24, 14, 0, 0, tzinfo=timezone.utc),
            threat_class="DDOS",
            attack_classification="SYN Flood",
            severity="CRITICAL",
            confidence=0.98,
            source_ip="198.51.100.44",
            destination_ip="10.240.0.12",
            source_port=54112,
            destination_port=443,
            transport_protocol="TCP : 443",
            status="Mitigated",
            triage_status="NEW",
            detector_model="Ensemble-v1",
            reason="SYN surge detected",
            trigger_features={"rate": 28400},
        )
        session.add(alert)

        # Seed telemetry snapshot
        snapshot = TelemetrySnapshot(
            timestamp=datetime.now(timezone.utc),
            packets_per_sec=18400.0,
            bytes_per_sec=92700000.0,
            active_flows_count=4821,
            threat_alerts_count=1,
            threat_alerts_critical=1,
            detection_latency_ms=740.0,
            actual_egress_packets=0,
            actual_egress_bytes=0,
        )
        session.add(snapshot)

        # Seed system health
        health = SystemHealth(
            status="Healthy",
            cpu_pct=98.0,
            cpu_detail="32 Cores · 48°C",
            memory_pct=76.0,
            memory_detail="24.3 / 32 GB",
            storage_pct=92.0,
            storage_detail="3.8 / 4.0 TB NVMe",
            sensors_pct=100.0,
            sensors_detail="12 / 12 Online",
            sources_json=[
                {"name": "Firewall Telemetry", "status": "Online", "latency": "1.2ms"},
            ],
            sensor_network_json={
                "online_sensors": 12,
                "total_sensors": 12,
                "regions_count": 3,
                "uptime_pct": 99.98,
                "avg_latency_ms": 0.8,
            },
        )
        session.add(health)

        # Seed diode integrity
        diode = DiodeIntegrity(
            physical_link_rx=True,
            physical_link_tx=False,
            optical_power_dbm=-13.8,
            ring_buffer_utilization_pct=18.4,
            dropped_frames=0,
            diode_state="NOMINAL",
            tamper_evident_chain_valid=True,
            last_audit_hash="8f43a9b1c78e3290deaf1455bb39c011e4f9b8c2d1109a8734e5f901a1829bc3",
        )
        session.add(diode)

        # Seed detection attribution
        detector = DetectionAttribution(
            engine_type="DDOS",
            status_badge="ACTIVE THREAT",
            rule_name="Ensemble-Volumetric-SYN-Burst",
            target_host="10.240.0.12:443",
            attack_vector="TCP SYN Flood (Unidirectional)",
            cadence_or_duration="45.2 seconds",
            recommended_action="Rate-limit boundary ingress",
            metrics_json={"syn_pps": 28400},
        )
        session.add(detector)
        session.commit()

    def override_get_db():
        session = TestingSession()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()



# ═══════════════════════════════════════════════════════════════
# 1. ROOT & DOCS ENDPOINTS
# ═══════════════════════════════════════════════════════════════

def test_root_and_openapi_docs(test_client):
    """Test that / and /docs and /openapi.json are accessible."""
    res = test_client.get("/")
    assert res.status_code == 200
    assert res.json()["status"] == "OPERATIONAL"

    docs_res = test_client.get("/docs")
    assert docs_res.status_code == 200

    openapi_res = test_client.get("/openapi.json")
    assert openapi_res.status_code == 200
    assert "paths" in openapi_res.json()


# ═══════════════════════════════════════════════════════════════
# 2. CORS HEADER VERIFICATION
# ═══════════════════════════════════════════════════════════════

def test_cors_headers_allowed_origin(test_client):
    """Test that CORS returns Access-Control-Allow-Origin for http://localhost:5173."""
    res = test_client.options(
        "/api/alerts",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert res.status_code == 200
    assert res.headers.get("access-control-allow-origin") == "http://localhost:5173"


def test_cors_headers_disallowed_origin(test_client):
    """Test that unauthorized origins do not receive allow headers."""
    res = test_client.options(
        "/api/alerts",
        headers={
            "Origin": "http://malicious-site.example.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert res.headers.get("access-control-allow-origin") != "http://malicious-site.example.com"


# ═══════════════════════════════════════════════════════════════
# 3. GET /api/health
# ═══════════════════════════════════════════════════════════════

def test_get_health(test_client):
    """Test GET /api/health returns 200 and proper HealthResponse."""
    res = test_client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] in ["Healthy", "Nominal"]
    assert "gauges" in data
    assert "sources" in data
    assert "sensor_network" in data
    assert "diode_integrity" in data
    assert data["diode_integrity"]["physical_link_tx"] is False  # Data diode zero-return guarantee


# ═══════════════════════════════════════════════════════════════
# 4. GET /api/alerts
# ═══════════════════════════════════════════════════════════════

def test_get_alerts_pagination_and_filter(test_client):
    """Test GET /api/alerts returns paginated results and counts."""
    res = test_client.get("/api/alerts?page=1&page_size=10")
    assert res.status_code == 200
    data = res.json()
    assert "total" in data
    assert "counts" in data
    assert "items" in data
    assert data["page"] == 1
    assert data["page_size"] == 10

    # Severity filtering
    res_crit = test_client.get("/api/alerts?severity=CRITICAL")
    assert res_crit.status_code == 200
    crit_data = res_crit.json()
    assert all(item["severity"] == "CRITICAL" for item in crit_data["items"])


# ═══════════════════════════════════════════════════════════════
# 5. GET /api/alerts/{alert_id}
# ═══════════════════════════════════════════════════════════════

def test_get_alert_by_id_success(test_client):
    """Test retrieving existing alert by alert_id."""
    res = test_client.get("/api/alerts/alt-api-test-01")
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == "alt-api-test-01"
    assert data["confidence"] == 0.98
    assert data["confidenceFormatted"] == "98.0%"
    assert data["srcIp"] == "198.51.100.44"


def test_get_alert_by_id_not_found(test_client):
    """Test retrieving non-existent alert returns 404."""
    res = test_client.get("/api/alerts/alt-non-existent-9999")
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


# ═══════════════════════════════════════════════════════════════
# 6. GET /api/stats
# ═══════════════════════════════════════════════════════════════

def test_get_stats(test_client):
    """Test GET /api/stats returns dynamically calculated Statistics."""
    res = test_client.get("/api/stats")
    assert res.status_code == 200
    data = res.json()
    assert data["total_alerts"] >= 1
    assert data["actual_egress_packets"] == 0
    assert data["actual_egress_bytes"] == 0
    assert data["packets_per_sec"] > 0


# ═══════════════════════════════════════════════════════════════
# 7. GET /api/stats/threat-distribution
# ═══════════════════════════════════════════════════════════════

def test_get_threat_distribution(test_client):
    """Test GET /api/stats/threat-distribution returns donut categories."""
    res = test_client.get("/api/stats/threat-distribution")
    assert res.status_code == 200
    data = res.json()
    assert "total_threats" in data
    assert "categories" in data
    assert isinstance(data["categories"], list)


# ═══════════════════════════════════════════════════════════════
# 8. GET /api/stats/timeline
# ═══════════════════════════════════════════════════════════════

def test_get_timeline(test_client):
    """Test GET /api/stats/timeline returns chronological events."""
    res = test_client.get("/api/stats/timeline?limit=10")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    if data:
        assert "timestamp" in data[0]
        assert "time_label" in data[0]


# ═══════════════════════════════════════════════════════════════
# 9. GET /api/traffic
# ═══════════════════════════════════════════════════════════════

def test_get_traffic(test_client):
    """Test GET /api/traffic returns sliding window rate samples."""
    res = test_client.get("/api/traffic?limit=10")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    assert "packets_per_sec" in data[0]
    assert "bytes_per_sec" in data[0]


# ═══════════════════════════════════════════════════════════════
# 10. GET /api/detectors/status
# ═══════════════════════════════════════════════════════════════

def test_get_detectors_status(test_client):
    """Test GET /api/detectors/status returns detector attributions."""
    res = test_client.get("/api/detectors/status")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)


# ═══════════════════════════════════════════════════════════════
# 11. POST /api/internal/alerts (INGESTION HOOK)
# ═══════════════════════════════════════════════════════════════

def test_post_internal_alert_success(test_client):
    """Test creating a valid alert via POST /api/internal/alerts."""
    payload = {
        "alert_id": "alt-ingest-test-01",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "threat_class": "C2_BEACONING",
        "attack_classification": "C2 Beacon",
        "severity": "HIGH",
        "confidence": 0.94,
        "source_ip": "10.240.4.88",
        "destination_ip": "203.0.113.195",
        "source_port": 49822,
        "destination_port": 8443,
        "transport_protocol": "HTTPS : 8443",
        "status": "Blocked",
        "triage_status": "INVESTIGATING",
        "detector_model": "LSTM-Interval-Detector",
        "reason": "Outbound periodic handshake",
        "trigger_features": {"jitter": 0.08},
    }
    res = test_client.post("/api/internal/alerts", json=payload)
    assert res.status_code == 201
    data = res.json()
    assert data["id"] == "alt-ingest-test-01"
    assert data["severity"] == "HIGH"
    assert data["confidenceFormatted"] == "94.0%"


def test_post_internal_alert_duplicate_conflict(test_client):
    """Test that posting duplicate alert_id returns 409 Conflict."""
    payload = {
        "alert_id": "alt-api-test-01",  # already exists
        "threat_class": "DDOS",
        "attack_classification": "SYN Flood",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "source_ip": "198.51.100.44",
        "destination_ip": "10.240.0.12",
        "transport_protocol": "TCP",
        "detector_model": "XGBoost",
        "reason": "Duplicate test",
    }
    res = test_client.post("/api/internal/alerts", json=payload)
    assert res.status_code == 409
    assert "already exists" in res.json()["detail"].lower()


def test_post_internal_alert_invalid_confidence(test_client):
    """Test that confidence > 1 returns 422 Unprocessable Entity."""
    payload = {
        "alert_id": "alt-invalid-conf",
        "threat_class": "DDOS",
        "attack_classification": "SYN Flood",
        "severity": "CRITICAL",
        "confidence": 98.0,  # Invalid: must be <= 1.0
        "source_ip": "198.51.100.44",
        "destination_ip": "10.240.0.12",
        "transport_protocol": "TCP",
        "detector_model": "XGBoost",
        "reason": "Invalid confidence test",
    }
    res = test_client.post("/api/internal/alerts", json=payload)
    assert res.status_code == 422


def test_post_internal_alert_invalid_ip_rejected(test_client):
    """Test that invalid IP address format returns 422 Unprocessable Entity."""
    payload = {
        "alert_id": "alt-invalid-ip",
        "threat_class": "DDOS",
        "attack_classification": "SYN Flood",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "source_ip": "999.999.999.999",  # Invalid IPv4
        "destination_ip": "10.240.0.12",
        "transport_protocol": "TCP",
        "detector_model": "XGBoost",
        "reason": "Invalid IP test",
    }
    res = test_client.post("/api/internal/alerts", json=payload)
    assert res.status_code == 422


def test_post_internal_alert_invalid_severity_rejected(test_client):
    """Test that unapproved severity enum returns 422 Unprocessable Entity."""
    payload = {
        "alert_id": "alt-invalid-sev",
        "threat_class": "DDOS",
        "attack_classification": "SYN Flood",
        "severity": "FATAL_ERROR",  # Invalid enum
        "confidence": 0.95,
        "source_ip": "198.51.100.44",
        "destination_ip": "10.240.0.12",
        "transport_protocol": "TCP",
        "detector_model": "XGBoost",
        "reason": "Invalid severity test",
    }
    res = test_client.post("/api/internal/alerts", json=payload)
    assert res.status_code == 422


def test_post_internal_alert_extra_fields_forbidden(test_client):
    """Test that extra unmapped fields are rejected by extra='forbid'."""
    payload = {
        "alert_id": "alt-extra-field",
        "threat_class": "DDOS",
        "attack_classification": "SYN Flood",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "source_ip": "198.51.100.44",
        "destination_ip": "10.240.0.12",
        "transport_protocol": "TCP",
        "detector_model": "XGBoost",
        "reason": "Extra field test",
        "malicious_injection": "DROP TABLE alerts;",
    }
    res = test_client.post("/api/internal/alerts", json=payload)
    assert res.status_code == 422


def test_get_alerts_arbitrary_sort_by_safe_fallback(test_client):
    """Test that arbitrary/malicious sort_by strings fall back safely without SQL errors."""
    res = test_client.get("/api/alerts?sort_by=non_existent_column_or_sqli;--")
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert isinstance(data["items"], list)

