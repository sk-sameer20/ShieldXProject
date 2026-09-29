from src.ingestion.parser import parse_jsonl

import os

def test_parser():
    base_dir = os.path.dirname(os.path.dirname(__file__))
    events = list(
        parse_jsonl(os.path.join(base_dir, "data/sample/sample_events.jsonl"))
    )

    assert len(events) > 0
    assert events[0].src_ip is not None
    assert events[0].dst_ip is not None