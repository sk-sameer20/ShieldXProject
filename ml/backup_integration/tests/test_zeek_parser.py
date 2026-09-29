import json
import tempfile
import os

from src.parser.zeek_parser import normalize_event, parse_zeek_log


def test_normalize_event():
    record = {
        "ts": 1730284025.152965,
        "id.orig_h": "10.0.0.1",
        "id.resp_h": "10.0.0.2",
        "id.orig_p": 12345,
        "id.resp_p": 443,
        "proto": "tcp",
        "duration": 2.5,
        "orig_bytes": 100,
        "resp_bytes": 200,
        "orig_pkts": 5,
        "resp_pkts": 4,
    }

    event = normalize_event(record)

    assert event["src_ip"] == "10.0.0.1"
    assert event["dst_ip"] == "10.0.0.2"
    assert event["src_port"] == 12345
    assert event["dst_port"] == 443
    assert event["protocol"] == "tcp"
    assert event["orig_bytes"] == 100
    assert event["resp_bytes"] == 200


def test_parse_zeek_log():
    zeek_record = {
        "ts": 1730284025.152965,
        "id.orig_h": "10.0.0.1",
        "id.resp_h": "10.0.0.2",
        "id.orig_p": 12345,
        "id.resp_p": 443,
        "proto": "tcp",
        "duration": 2.5,
        "orig_bytes": 100,
        "resp_bytes": 200,
    }

    with tempfile.TemporaryDirectory() as tmp:
        input_file = os.path.join(tmp, "conn.log")
        output_file = os.path.join(tmp, "normalized.json")

        with open(input_file, "w") as f:
            f.write("# Zeek log\n")
            f.write(json.dumps(zeek_record) + "\n")

        parse_zeek_log(input_file, output_file)

        with open(output_file) as f:
            result = json.loads(f.readline())

        assert result["src_ip"] == "10.0.0.1"
        assert result["dst_port"] == 443


if __name__ == "__main__":
    test_normalize_event()
    test_parse_zeek_log()
    print("All parser tests passed.")
