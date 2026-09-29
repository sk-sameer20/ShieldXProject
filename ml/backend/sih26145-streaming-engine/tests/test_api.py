import pytest
import asyncio
from fastapi.testclient import TestClient
from main import app, ConnectionManager
from src.alerts.schema import AlertSchema

def test_health():
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

def test_get_alerts():
    with TestClient(app) as client:
        response = client.get("/alerts?limit=5")
        assert response.status_code == 200
        assert "alerts" in response.json()
        assert isinstance(response.json()["alerts"], list)

def test_get_stats():
    with TestClient(app) as client:
        response = client.get("/stats")
        assert response.status_code == 200
        data = response.json()
        assert "total_alerts" in data
        assert "by_threat_type" in data
        assert "by_severity" in data

def test_get_traffic():
    with TestClient(app) as client:
        response = client.get("/traffic")
        assert response.status_code == 200
        data = response.json()
        assert "events_processed" in data
        assert "events_dropped" in data

def test_websocket_connection():
    with TestClient(app) as client:
        with client.websocket_connect("/ws/alerts") as websocket:
            pass # just checking it can connect

@pytest.mark.asyncio
async def test_manager_broadcast():
    manager = ConnectionManager()
    
    class MockWS:
        def __init__(self):
            self.messages = []
        async def send_json(self, data):
            self.messages.append(data)
            
    ws1 = MockWS()
    ws2 = MockWS()
    manager.active_connections.extend([ws1, ws2])
    
    alert = AlertSchema(
        id="test-id",
        timestamp=100.0,
        threat_type="DDoS",
        severity="high",
        confidence=0.8,
        src_ip="10.0.0.1",
        model_version="v1"
    )
    
    await manager.broadcast_alert(alert)
    
    assert len(ws1.messages) == 1
    assert ws1.messages[0]["id"] == "test-id"
    assert len(ws2.messages) == 1
    assert ws2.messages[0]["id"] == "test-id"
    
@pytest.mark.asyncio
async def test_manager_disconnected_client():
    manager = ConnectionManager()
    
    class BrokenWS:
        async def send_json(self, data):
            raise Exception("Broken pipe")
            
    ws1 = BrokenWS()
    manager.active_connections.append(ws1)
    
    alert = AlertSchema(
        id="test-id", timestamp=100.0, threat_type="DDoS",
        severity="high", confidence=0.8, src_ip="10.0.0.1", model_version="v1"
    )
    
    # Broadcast should catch the exception and remove the client
    await manager.broadcast_alert(alert)
    assert len(manager.active_connections) == 0
