import pytest
from src.ingestion.parser import NetworkEvent
from src.detectors.ddos_adapter import RealDDoSAdapter
from src.detectors.c2_adapter import RealC2Adapter
from src.detectors.dga_adapter import RealDGAAdapter
from src.detectors.dns_tunnel_adapter import RealDNSTunnelAdapter

@pytest.fixture
def mock_events():
    return [
        NetworkEvent(
            timestamp=1.0,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=50000,
            dst_port=80,
            duration=None,
            conn_state=None,
            query="test-dga-domain.com",
            qtype="A",
            rcode="NOERROR"
        ),
        NetworkEvent(
            timestamp=2.0,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=50001,
            dst_port=80,
            duration=0.5,
            conn_state="SF",
            query="test-tunneling-domain.com",
            qtype="TXT",
            rcode="NOERROR"
        )
    ]

def test_ddos_adapter(mock_events):
    adapter = RealDDoSAdapter()
    result = adapter.predict(mock_events)
    assert "detected" in result
    assert "score" in result
    assert "evidence" in result
    assert result["model_version"] == "ddos_person2"

def test_c2_adapter(mock_events):
    adapter = RealC2Adapter()
    result = adapter.predict(mock_events)
    assert "detected" in result
    assert "score" in result
    assert "evidence" in result

def test_dga_adapter(mock_events):
    adapter = RealDGAAdapter()
    result = adapter.predict(mock_events)
    assert "detected" in result
    assert "score" in result
    assert "evidence" in result

def test_dns_tunnel_adapter(mock_events):
    adapter = RealDNSTunnelAdapter()
    result = adapter.predict(mock_events)
    assert "detected" in result
    assert "score" in result
    assert "evidence" in result
