"""
Unit Tests for ShieldX AlertService
Tests creation, retrieval, filtering, pagination, date ranges, and dynamic statistics.
"""
from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models.base import Base
from app.models.alert import Alert
from app.models.schemas import (
    AlertCreate,
    AlertSeverity,
    AlertStatus,
    ThreatClass,
    TriageStatus,
)
from app.services.alert_service import AlertService, alert_to_response


@pytest.fixture(scope="function")
def db_session():
    """Create a fresh in-memory SQLite database session for each test function."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    session = TestingSession()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def populated_db(db_session):
    """Seed test database with 5 distinct alerts across various severities and dates."""
    base_time = datetime(2026, 9, 24, 12, 0, 0, tzinfo=timezone.utc)
    sample_alerts = [
        Alert(
            alert_id="alt-001",
            timestamp=base_time - timedelta(minutes=10),
            threat_class="DDOS",
            attack_classification="SYN Flood",
            severity="CRITICAL",
            confidence=0.98,
            source_ip="198.51.100.1",
            destination_ip="10.0.0.1",
            source_port=44100,
            destination_port=443,
            transport_protocol="TCP : 443",
            status="Mitigated",
            triage_status="NEW",
            detector_model="XGBoost-v1",
            reason="SYN surge detected",
            trigger_features={"pps": 25000},
        ),
        Alert(
            alert_id="alt-002",
            timestamp=base_time - timedelta(minutes=5),
            threat_class="C2_BEACONING",
            attack_classification="Cobalt Strike",
            severity="HIGH",
            confidence=0.92,
            source_ip="198.51.100.2",
            destination_ip="10.0.0.2",
            source_port=50000,
            destination_port=8443,
            transport_protocol="HTTPS : 8443",
            status="Blocked",
            triage_status="INVESTIGATING",
            detector_model="LSTM-v1",
            reason="Periodic beaconing cadence",
            trigger_features={"interval": 45.0},
        ),
        Alert(
            alert_id="alt-003",
            timestamp=base_time - timedelta(minutes=2),
            threat_class="DGA_DNS_TUNNEL",
            attack_classification="DNS Exfiltration",
            severity="MEDIUM",
            confidence=0.85,
            source_ip="198.51.100.3",
            destination_ip="10.0.0.3",
            source_port=53,
            destination_port=53,
            transport_protocol="DNS",
            status="Alerted",
            triage_status="NEW",
            detector_model="Entropy-v1",
            reason="High Shannon entropy on domain",
            trigger_features={"entropy": 4.8},
        ),
        Alert(
            alert_id="alt-004",
            timestamp=base_time - timedelta(minutes=1),
            threat_class="ANOMALY",
            attack_classification="SSH Anomaly",
            severity="LOW",
            confidence=0.70,
            source_ip="198.51.100.4",
            destination_ip="10.0.0.4",
            source_port=22,
            destination_port=22,
            transport_protocol="TCP : 22",
            status="Monitored",
            triage_status="RESOLVED",
            detector_model="IsolationForest-v1",
            reason="Unusual SSH duration",
            trigger_features={"duration": 120},
        ),
        Alert(
            alert_id="alt-005",
            timestamp=base_time,
            threat_class="DDOS",
            attack_classification="UDP Flood",
            severity="CRITICAL",
            confidence=0.95,
            source_ip="198.51.100.5",
            destination_ip="10.0.0.1",
            source_port=11211,
            destination_port=443,
            transport_protocol="UDP : 443",
            status="Mitigated",
            triage_status="ESCALATED",
            detector_model="UDP-Flood-v1",
            reason="Amplified reflection attack",
            trigger_features={"pps": 30000},
        ),
    ]
    for a in sample_alerts:
        db_session.add(a)
    db_session.commit()
    return db_session


# ═══════════════════════════════════════════════════════════════
# 1. CREATING ALERT TESTS
# ═══════════════════════════════════════════════════════════════

def test_create_alert_success(db_session):
    """Test successful creation and persistence of an alert."""
    alert_in = AlertCreate(
        alert_id="alt-test-create",
        timestamp=datetime.now(timezone.utc),
        threat_class=ThreatClass.DDOS,
        attack_classification="Volumetric SYN Burst",
        severity=AlertSeverity.CRITICAL,
        confidence=0.97,
        source_ip="192.0.2.1",
        destination_ip="10.240.0.50",
        source_port=49152,
        destination_port=443,
        transport_protocol="TCP : 443",
        status=AlertStatus.MITIGATED,
        triage_status=TriageStatus.NEW,
        detector_model="Ensemble-v1",
        reason="Exceeded baseline rate",
        trigger_features={"rate": 20000},
    )

    created = AlertService.create_alert(db_session, alert_in)
    assert created.alert_id == "alt-test-create"
    assert created.confidence == 0.97
    assert created.severity == "CRITICAL"

    # Verify retrieval from DB
    retrieved = db_session.get(Alert, "alt-test-create")
    assert retrieved is not None
    assert retrieved.source_ip == "192.0.2.1"


# ═══════════════════════════════════════════════════════════════
# 2. RETRIEVING ALERT & MISSING ALERT TESTS
# ═══════════════════════════════════════════════════════════════

def test_get_alert_found(populated_db):
    """Test retrieving an existing alert by ID."""
    alert = AlertService.get_alert(populated_db, "alt-001")
    assert alert is not None
    assert alert.alert_id == "alt-001"
    assert alert.severity == "CRITICAL"
    assert alert.threat_class == "DDOS"


def test_get_alert_missing(populated_db):
    """Test retrieving a non-existent alert returns None."""
    alert = AlertService.get_alert(populated_db, "alt-does-not-exist-9999")
    assert alert is None


# ═══════════════════════════════════════════════════════════════
# 3. FILTERING TESTS
# ═══════════════════════════════════════════════════════════════

def test_filtering_by_severity(populated_db):
    """Test filtering alerts strictly by severity level."""
    # Critical should return 2 items (alt-001, alt-005)
    crit_items, crit_count = AlertService.get_alerts(populated_db, severity="CRITICAL")
    assert crit_count == 2
    assert len(crit_items) == 2
    assert all(a.severity == "CRITICAL" for a in crit_items)

    # High should return 1 item (alt-002)
    high_items, high_count = AlertService.get_alerts(populated_db, severity=AlertSeverity.HIGH)
    assert high_count == 1
    assert high_items[0].alert_id == "alt-002"


def test_filtering_by_threat_class(populated_db):
    """Test filtering alerts by threat class."""
    ddos_items, count = AlertService.get_alerts(populated_db, threat_class="DDOS")
    assert count == 2
    assert all(a.threat_class == "DDOS" for a in ddos_items)

    c2_items, c2_count = AlertService.get_alerts(populated_db, threat_class=ThreatClass.C2_BEACONING)
    assert c2_count == 1
    assert c2_items[0].alert_id == "alt-002"


def test_filtering_by_ip(populated_db):
    """Test filtering alerts by source and destination IP."""
    items, count = AlertService.get_alerts(populated_db, source_ip="198.51.100.1")
    assert count == 1
    assert items[0].source_ip == "198.51.100.1"

    dest_items, dest_count = AlertService.get_alerts(populated_db, destination_ip="10.0.0.1")
    assert dest_count == 2  # alt-001 and alt-005 target 10.0.0.1


def test_filtering_by_search(populated_db):
    """Test universal search query across multiple columns."""
    # Search by IP
    items, count = AlertService.get_alerts(populated_db, search="198.51.100.3")
    assert count == 1
    assert items[0].alert_id == "alt-003"

    # Search by reason keyword
    items, count = AlertService.get_alerts(populated_db, search="Shannon entropy")
    assert count == 1
    assert items[0].alert_id == "alt-003"


# ═══════════════════════════════════════════════════════════════
# 4. DATE FILTERING TESTS
# ═══════════════════════════════════════════════════════════════

def test_date_filtering(populated_db):
    """Test filtering by start_time and end_time datetime bounds."""
    base_time = datetime(2026, 9, 24, 12, 0, 0, tzinfo=timezone.utc)
    
    # Range covering only the last 3 minutes (alt-004, alt-005, alt-003)
    start = base_time - timedelta(minutes=3)
    items, count = AlertService.get_alerts(populated_db, start_time=start)
    assert count == 3
    assert {a.alert_id for a in items} == {"alt-003", "alt-004", "alt-005"}

    # Window covering exactly 1 item (alt-002: base_time - 5min)
    win_start = base_time - timedelta(minutes=6)
    win_end = base_time - timedelta(minutes=4)
    win_items, win_count = AlertService.get_alerts(populated_db, start_time=win_start, end_time=win_end)
    assert win_count == 1
    assert win_items[0].alert_id == "alt-002"


# ═══════════════════════════════════════════════════════════════
# 5. PAGINATION TESTS
# ═══════════════════════════════════════════════════════════════

def test_pagination(populated_db):
    """Test limit and offset parameter paging."""
    # Total items in DB = 5
    page1, total = AlertService.get_alerts(populated_db, limit=2, offset=0)
    assert total == 5
    assert len(page1) == 2

    page2, total2 = AlertService.get_alerts(populated_db, limit=2, offset=2)
    assert total2 == 5
    assert len(page2) == 2
    assert page1[0].alert_id != page2[0].alert_id

    page3, total3 = AlertService.get_alerts(populated_db, limit=2, offset=4)
    assert len(page3) == 1


# ═══════════════════════════════════════════════════════════════
# 6. DYNAMIC STATISTICS TESTS (NO HARDCODING)
# ═══════════════════════════════════════════════════════════════

def test_dynamic_statistics_counts(populated_db):
    """
    Test that alert counts are calculated directly via SQL aggregation
    and accurately match database records.
    """
    counts = AlertService.get_alert_counts(populated_db)

    # 5 total alerts seeded
    assert counts["all"] == 5
    assert counts["critical"] == 2
    assert counts["high"] == 1
    assert counts["medium"] == 1
    assert counts["low"] == 1

    # Triage counts
    assert counts["new"] == 2           # alt-001, alt-003
    assert counts["investigating"] == 1  # alt-002
    assert counts["resolved"] == 1       # alt-004
    assert counts["escalated"] == 1      # alt-005


def test_threat_distribution_dynamic(populated_db):
    """Test dynamic calculation of threat taxonomy donut distribution."""
    distribution = AlertService.get_threat_distribution(populated_db)
    assert distribution.total_threats == 5

    # Categories should be sorted descending by count
    # DDOS has 2 items -> 40.0%
    ddos_cat = next(c for c in distribution.categories if c.label == "DDoS")
    assert ddos_cat.count == 2
    assert ddos_cat.pct == 40.0
    assert ddos_cat.pct_formatted == "40%"

    # Sum of category counts must equal total
    assert sum(c.count for c in distribution.categories) == 5


# ═══════════════════════════════════════════════════════════════
# 7. TIMELINE & MUTATION TESTS
# ═══════════════════════════════════════════════════════════════

def test_get_timeline(populated_db):
    """Test generating chronological timeline audit points."""
    timeline = AlertService.get_timeline(populated_db, limit=3)
    assert len(timeline) == 3
    # Check that points are ordered descending by time
    assert timeline[0].timestamp >= timeline[1].timestamp


def test_update_triage(populated_db):
    """Test mutating triage status and action status of an alert."""
    updated = AlertService.update_triage(
        populated_db,
        alert_id="alt-001",
        triage_status=TriageStatus.ESCALATED,
        action_status=AlertStatus.BLOCKED,
    )
    assert updated is not None
    assert updated.triage_status == "ESCALATED"
    assert updated.status == "Blocked"


def test_alert_to_response_mapper(populated_db):
    """Test conversion of Alert model to AlertResponse DTO."""
    alert = populated_db.get(Alert, "alt-001")
    resp = alert_to_response(alert)
    assert resp.id == "alt-001"
    assert resp.confidenceFormatted == "98.0%"
    assert resp.triageType == "danger"
    assert resp.srcIp == "198.51.100.1"
