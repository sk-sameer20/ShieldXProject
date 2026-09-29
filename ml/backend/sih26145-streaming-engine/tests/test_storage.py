import os
import pytest
from src.alerts.builder import AlertBuilder
from src.storage.sqlite_store import SQLiteStore


def test_sqlite_store(tmp_path):
    db_file = str(tmp_path / "test_sih26145.db")
    store = SQLiteStore(db_path=db_file)
    builder = AlertBuilder()

    alert1 = builder.build_alert(
        threat_type="DDoS",
        src_ip="10.0.0.50",
        confidence=0.91,
        severity="critical",
        evidence=["Packet burst"],
        timestamp=100.0
    )
    alert2 = builder.build_alert(
        threat_type="C2",
        src_ip="10.0.0.22",
        confidence=0.85,
        severity="high",
        evidence=["Periodic beaconing"],
        timestamp=105.0
    )

    assert store.save_alert(alert1) is True
    assert store.save_alert(alert2) is True

    recent = store.get_recent_alerts(limit=10)
    assert len(recent) == 2
    assert recent[0]["threat_type"] == "C2" # Ordered timestamp desc

    ddos_alerts = store.get_alerts_by_threat("DDoS")
    assert len(ddos_alerts) == 1
    assert ddos_alerts[0]["src_ip"] == "10.0.0.50"

    stats = store.get_stats()
    assert stats["total_alerts"] == 2
    assert stats["by_threat_type"]["DDoS"] == 1
    assert stats["by_threat_type"]["C2"] == 1

    store.clear_alerts()
    assert store.get_stats()["total_alerts"] == 0
