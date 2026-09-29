import pytest
from src.ingestion.parser import NetworkEvent
from src.streaming.window_manager import WindowManager


def test_window_manager_sliding_window():
    wm = WindowManager(window_config={"ddos_seconds": 5.0, "c2_seconds": 60.0, "dns_seconds": 60.0})

    # Add events at t=10.0, t=12.0, t=16.0
    wm.add_event(NetworkEvent(timestamp=10.0, src_ip="10.0.0.1", dst_ip="8.8.8.8", src_port=1, dst_port=80))
    wm.add_event(NetworkEvent(timestamp=12.0, src_ip="10.0.0.1", dst_ip="8.8.8.8", src_port=2, dst_port=80))
    wm.add_event(NetworkEvent(timestamp=16.0, src_ip="10.0.0.1", dst_ip="8.8.8.8", src_port=3, dst_port=80))

    # At latest_ts=16.0, 5s DDoS window cutoff is [11.0, 16.0]
    ddos_events = wm.get_ddos_window("10.0.0.1")
    assert len(ddos_events) == 2
    assert ddos_events[0].timestamp == 12.0
    assert ddos_events[1].timestamp == 16.0

    # 60s C2 window includes all 3 events
    c2_events = wm.get_c2_window("10.0.0.1")
    assert len(c2_events) == 3


def test_window_manager_out_of_order():
    wm = WindowManager(window_config={"ddos_seconds": 5.0, "c2_seconds": 60.0, "dns_seconds": 60.0})

    wm.add_event(NetworkEvent(timestamp=10.0, src_ip="10.0.0.1", dst_ip="8.8.8.8", src_port=1, dst_port=80))
    wm.add_event(NetworkEvent(timestamp=14.0, src_ip="10.0.0.1", dst_ip="8.8.8.8", src_port=2, dst_port=80))
    # Out of order event at t=12.0
    wm.add_event(NetworkEvent(timestamp=12.0, src_ip="10.0.0.1", dst_ip="8.8.8.8", src_port=3, dst_port=80))

    events = wm.get_ddos_window("10.0.0.1")
    timestamps = [e.timestamp for e in events]
    assert timestamps == [10.0, 12.0, 14.0]
