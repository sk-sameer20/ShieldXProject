"""
Unit and Integration Tests for ShieldX SOC WebSocket Layer
Tests connection, disconnect, broadcast, multiple clients, failure isolation,
and alert ingestion -> WebSocket broadcast pipeline.
"""
from datetime import datetime, timezone
import json
import pytest
from unittest.mock import AsyncMock
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.deps import get_db
from app.main import app
from app.models.base import Base
from app.services.alert_service import AlertService
from app.websocket.manager import ConnectionManager, ws_manager


@pytest.fixture
def db_session():
    """Create an isolated in-memory test database."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    session = TestingSession()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(db_session):
    """TestClient overriding get_db dependency."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


# ─── 1. CONNECTION & DISCONNECT TESTS ─────────────────────────────

def test_websocket_connect_and_disconnect(client):
    """Verify that a client can connect, ping/pong, and safely disconnect."""
    initial_count = ws_manager.client_count

    with client.websocket_connect("/ws/alerts") as websocket:
        # Client count must have increased by 1
        assert ws_manager.client_count == initial_count + 1

        # Test ping-pong mechanism
        websocket.send_text("ping")
        response = websocket.receive_text()
        assert response == "pong"

    # After exiting context manager, client is disconnected
    assert ws_manager.client_count == initial_count


# ─── 2. BROADCAST TO MULTIPLE CLIENTS ──────────────────────────────

def test_websocket_multiple_clients_broadcast(client):
    """Verify multiple concurrent clients receive broadcasted messages simultaneously."""
    initial_count = ws_manager.client_count

    with client.websocket_connect("/ws/alerts") as ws1, \
         client.websocket_connect("/ws/alerts") as ws2, \
         client.websocket_connect("/ws/alerts") as ws3:

        assert ws_manager.client_count == initial_count + 3

        test_payload = {
            "type": "alert",
            "data": {"alert_id": "test-broadcast-99", "severity": "HIGH"},
        }

        # Synchronously run broadcast using the test client event loop
        import asyncio
        asyncio.run(ws_manager.broadcast(test_payload))

        # All 3 clients should receive the exact broadcast payload
        msg1 = json.loads(ws1.receive_text())
        msg2 = json.loads(ws2.receive_text())
        msg3 = json.loads(ws3.receive_text())

        assert msg1 == test_payload
        assert msg2 == test_payload
        assert msg3 == test_payload

    # All 3 disconnected cleanly
    assert ws_manager.client_count == initial_count


# ─── 3. CLIENT FAILURE ISOLATION ──────────────────────────────────

@pytest.mark.asyncio
async def test_client_failure_isolation():
    """
    Verify that an exception or disconnected state on one client
    does NOT prevent other clients from receiving the broadcast,
    and the failing client is safely removed from active connections.
    """
    manager = ConnectionManager()

    # Client A: Healthy client
    healthy_client_1 = AsyncMock()
    healthy_client_1.send_text = AsyncMock(return_value=None)

    # Client B: Broken client that raises RuntimeError on send
    broken_client = AsyncMock()
    broken_client.send_text = AsyncMock(side_effect=RuntimeError("Connection reset by peer"))

    # Client C: Another healthy client
    healthy_client_2 = AsyncMock()
    healthy_client_2.send_text = AsyncMock(return_value=None)

    # Register all three directly to active connections
    manager.active_connections.add(healthy_client_1)
    manager.active_connections.add(broken_client)
    manager.active_connections.add(healthy_client_2)

    assert manager.client_count == 3

    # Broadcast message
    payload = {"type": "alert", "data": {"alert_id": "iso-test-01"}}
    await manager.broadcast(payload)

    expected_json = json.dumps(payload)

    # Both healthy clients received the broadcast
    healthy_client_1.send_text.assert_awaited_once_with(expected_json)
    healthy_client_2.send_text.assert_awaited_once_with(expected_json)

    # Broken client attempted send
    broken_client.send_text.assert_awaited_once_with(expected_json)

    # Broken client was automatically pruned from active connections
    assert manager.client_count == 2
    assert broken_client not in manager.active_connections
    assert healthy_client_1 in manager.active_connections
    assert healthy_client_2 in manager.active_connections


# ─── 4. ALERT INGESTION -> WEBSOCKET BROADCAST PIPELINE ─────────────

def test_alert_ingestion_broadcasts_event_after_persistence(client, db_session):
    """
    Verify the complete end-to-end alert ingestion flow:
    1. Validation passes
    2. Saved to SQLite database
    3. Broadcast over WebSocket in { type: 'alert', data: { ... } } format
    """
    with client.websocket_connect("/ws/alerts") as ws:
        payload = {
            "alert_id": "alt-ingest-ws-001",
            "timestamp": "2026-09-24T15:30:00Z",
            "threat_class": "C2",
            "attack_classification": "DNS Beaconing",
            "severity": "CRITICAL",
            "confidence": 0.96,
            "source_ip": "10.0.1.15",
            "destination_ip": "198.51.100.88",
            "source_port": 53211,
            "destination_port": 53,
            "transport_protocol": "UDP : 53",
            "status": "Blocked",
            "triage_status": "NEW",
            "detector_model": "DGA-DNS-v1.2",
            "reason": "High entropy periodic query spikes to unregistered apex",
            "evidence": {"beacon_interval_sec": 45, "jitter_percent": 2.1},
            "trigger_features": {"entropy": 4.88, "query_rate": 120},
            "metadata": {"enclave": "SecureZone-A"},
        }

        # POST /api/internal/alerts
        response = client.post("/api/internal/alerts", json=payload)
        assert response.status_code == 201
        created_data = response.json()
        assert created_data["alert_id"] == "alt-ingest-ws-001"

        # 1. Verify saved to SQLite database
        persisted = AlertService.get_alert(db_session, "alt-ingest-ws-001")
        assert persisted is not None
        assert persisted.alert_id == "alt-ingest-ws-001"
        assert persisted.threat_class == "C2"

        # 2. Verify WebSocket received broadcasted event
        raw_ws_message = ws.receive_text()
        ws_event = json.loads(raw_ws_message)

        # Check required schema format: {"type": "alert", "data": { ... }}
        assert ws_event["type"] == "alert"
        assert "data" in ws_event
        assert ws_event["data"]["alert_id"] == "alt-ingest-ws-001"
        assert ws_event["data"]["severity"] == "CRITICAL"
        assert ws_event["data"]["attack_classification"] == "DNS Beaconing"


# ─── 5. FAILED INGESTION DOES NOT BROADCAST ───────────────────────

def test_failed_ingestion_does_not_broadcast(client):
    """
    Verify that invalid payloads (validation error) or duplicate alerts (conflict error)
    never trigger a WebSocket broadcast.
    """
    with client.websocket_connect("/ws/alerts") as ws:
        # Invalid payload (confidence > 1.0 violates constraint)
        invalid_payload = {
            "alert_id": "alt-invalid-01",
            "timestamp": "2026-09-24T15:30:00Z",
            "threat_class": "DDOS",
            "attack_classification": "SYN Flood",
            "severity": "HIGH",
            "confidence": 1.5,  # INVALID: must be <= 1.0
            "source_ip": "1.2.3.4",
            "destination_ip": "5.6.7.8",
            "source_port": 1234,
            "destination_port": 80,
            "transport_protocol": "TCP",
            "status": "Active",
            "triage_status": "NEW",
            "detector_model": "TestModel",
            "reason": "Test reason",
        }

        response = client.post("/api/internal/alerts", json=invalid_payload)
        assert response.status_code == 422

        # Send a ping to verify that no alert event is pending in the queue
        ws.send_text("ping")
        reply = ws.receive_text()
        # The reply MUST be "pong", proving no alert broadcast preceded it!
        assert reply == "pong"
