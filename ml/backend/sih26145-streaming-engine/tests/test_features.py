from src.ingestion.parser import NetworkEvent
from src.features.ddos_adapter import DDoSFeatureAdapter
from src.features.c2_adapter import C2FeatureAdapter
from src.features.dns_adapter import DNSFeatureAdapter


def test_ddos_feature_adapter():
    adapter = DDoSFeatureAdapter()

    # Empty window
    empty_feat = adapter.extract_features([], window_seconds=5.0)
    assert empty_feat["pps"] == 0.0
    assert empty_feat["syn_ratio"] == 0.0

    # Populated window
    events = [
        NetworkEvent(timestamp=10.0, src_ip="10.0.0.1", dst_ip="192.168.1.1", src_port=1, dst_port=80, orig_pkts=5, conn_state="S0"),
        NetworkEvent(timestamp=11.0, src_ip="10.0.0.1", dst_ip="192.168.1.2", src_port=2, dst_port=80, orig_pkts=5, conn_state="SF"),
    ]
    feat = adapter.extract_features(events, window_seconds=5.0)
    assert feat["total_pkts"] == 10
    assert feat["pps"] == 2.0
    assert feat["syn_ratio"] == 0.5
    assert feat["unique_dst_ips"] == 2


def test_c2_feature_adapter_beaconing():
    adapter = C2FeatureAdapter()
    
    # Perfectly periodic events at t=1.0, 2.0, 3.0, 4.0
    events = [
        NetworkEvent(timestamp=float(i), src_ip="10.0.0.1", dst_ip="1.1.1.1", src_port=100, dst_port=443, orig_bytes=100)
        for i in range(1, 5)
    ]
    feat = adapter.extract_features(events, window_seconds=60.0)
    assert feat["beacon_regularity_stddev"] == 0.0
    assert feat["beacon_regularity_score"] == 1.0


def test_dns_feature_adapter_entropy():
    adapter = DNSFeatureAdapter()
    events = [
        NetworkEvent(timestamp=1.0, src_ip="10.0.0.1", dst_ip="8.8.8.8", src_port=53, dst_port=53, query="x93kf81lza0492.com"),
    ]
    feat = adapter.extract_features(events, window_seconds=60.0)
    assert feat["unique_domains_count"] == 1
    assert feat["avg_shannon_entropy"] > 3.0
