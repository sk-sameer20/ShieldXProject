import pytest
import asyncio
from src.ingestion.parser import NetworkEvent
from src.streaming.event_queue import EventQueue


@pytest.mark.asyncio
async def test_queue_normal_operation():
    q = EventQueue(max_size=10)
    event = NetworkEvent(timestamp=1.0, src_ip="10.0.0.1", dst_ip="8.8.8.8", src_port=123, dst_port=80)

    success = await q.put(event)
    assert success is True
    assert q.size() == 1

    retrieved = await q.get()
    assert retrieved.src_ip == "10.0.0.1"
    
    stats = q.get_stats()
    assert stats["events_received"] == 1
    assert stats["events_processed"] == 1
    assert stats["events_dropped"] == 0


@pytest.mark.asyncio
async def test_queue_overflow_drop():
    q = EventQueue(max_size=2, drop_on_overflow=True)
    e1 = NetworkEvent(timestamp=1.0, src_ip="10.0.0.1", dst_ip="8.8.8.8", src_port=1, dst_port=80)
    e2 = NetworkEvent(timestamp=2.0, src_ip="10.0.0.2", dst_ip="8.8.8.8", src_port=2, dst_port=80)
    e3 = NetworkEvent(timestamp=3.0, src_ip="10.0.0.3", dst_ip="8.8.8.8", src_port=3, dst_port=80)

    assert q.put_nowait(e1) is True
    assert q.put_nowait(e2) is True
    # 3rd event should be dropped due to max_size 2
    assert q.put_nowait(e3) is False

    stats = q.get_stats()
    assert stats["events_received"] == 3
    assert stats["events_dropped"] == 1
    assert q.size() == 2
