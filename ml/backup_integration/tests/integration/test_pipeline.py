import json
import pytest
import os
import tempfile
from typing import List, Dict

from src.parser.zeek_parser import normalize_event, parse_zeek_log
from src.ddos.ddos_detector import detect_ddos
from src.c2.inference import run_c2_detection
from src.dns.inference import run_dns_tunnel_detection
from src.dga.inference import run_dga_detection

def test_conn_pipeline():
    # Zeek conn.log style records
    zeek_records = [
        {
            "ts": 1730284025.0,
            "id.orig_h": "10.0.0.1",
            "id.resp_h": "10.0.0.2",
            "id.orig_p": 12345,
            "id.resp_p": 443,
            "proto": "tcp",
            "duration": 2.5,
            "orig_bytes": 1000,
            "resp_bytes": 2000,
            "orig_pkts": 50,
            "resp_pkts": 40,
            "conn_state": "S1"
        },
        {
            "ts": 1730284030.0,
            "id.orig_h": "10.0.0.1",
            "id.resp_h": "10.0.0.2",
            "id.orig_p": 12346,
            "id.resp_p": 443,
            "proto": "tcp",
            "duration": 0.5,
            "orig_bytes": 50,
            "resp_bytes": 0,
            "orig_pkts": 1,
            "resp_pkts": 0,
            "conn_state": "S0" # SYN only
        }
    ]

    # 1. Parse/Normalize (Person 1)
    normalized = [normalize_event(r) for r in zeek_records]

    # Ensure required fields survived
    assert normalized[0]["conn_state"] == "S1"
    assert normalized[1]["conn_state"] == "S0"
    assert normalized[0]["src_ip"] == "10.0.0.1"

    # 2. Run DDoS (Person 2)
    ddos_alert = detect_ddos(normalized)
    assert ddos_alert is not None
    assert ddos_alert["threat"] == "DDoS"

    # 3. Run C2 (Person 3)
    c2_alert = run_c2_detection(normalized, src_ip="10.0.0.1")
    assert c2_alert.threat_class in ["C2", "benign"]


def test_dns_pipeline():
    # Zeek dns.log style records
    zeek_records = [
        {
            "ts": 1730284025.0,
            "id.orig_h": "10.0.0.1",
            "id.resp_h": "10.0.0.53",
            "proto": "udp",
            "query": "banjori123.com",
            "qtype_name": "A",
            "rcode_name": "NOERROR"
        },
        {
            "ts": 1730284026.0,
            "id.orig_h": "10.0.0.1",
            "id.resp_h": "10.0.0.53",
            "proto": "udp",
            "query": "long-dns-tunnel-payload-string-xyz.com",
            "qtype_name": "TXT",
            "rcode_name": "NOERROR"
        }
    ]

    # 1. Parse/Normalize
    normalized = [normalize_event(r) for r in zeek_records]
    assert normalized[0]["query"] == "banjori123.com"
    assert normalized[0]["qtype"] == "A"

    # 2. Run DGA (Person 3)
    # The DGA detector expects domain strings
    dga_alerts = []
    for record in normalized:
        if record.get("query"):
            alert = run_dga_detection(record["query"])
            dga_alerts.append(alert)
    
    assert len(dga_alerts) == 2
    # The first one should be detected by the frozen DGA models
    
    # 3. Run DNS Tunnel (Person 3)
    tunnel_alert = run_dns_tunnel_detection(normalized, src_ip="10.0.0.1")
    assert tunnel_alert.threat_class in ["DNS_TUNNEL", "benign"]

if __name__ == "__main__":
    pytest.main([__file__])
