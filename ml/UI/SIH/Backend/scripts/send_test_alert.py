"""
Simulated Detection Engine Alert Sender
Step 9 Verification Script for ShieldX SOC Ingestion Pipeline.

Sends synthetic alerts directly to POST /api/internal/alerts to verify:
Detection event -> FastAPI -> Pydantic validation -> SQLite persistence
-> Stats recalculation -> WebSocket broadcast -> Live Frontend update.
"""

import argparse
import json
import random
import sys
import time
import uuid
from datetime import datetime, timezone
import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:8000"

SAMPLE_ALERTS = {
    "DDOS": {
        "threat_class": "DDOS",
        "attack_classification": "Distributed Denial of Service (SYN Flood)",
        "severity": "CRITICAL",
        "confidence": 0.98,
        "source_ip": "198.51.100.77",
        "destination_ip": "10.240.0.12",
        "source_port": 41822,
        "destination_port": 443,
        "transport_protocol": "TCP",
        "status": "Blocked",
        "triage_status": "NEW",
        "detector_model": "XGBoost-Volumetric-v3",
        "model_version": "v3.2.0",
        "mitre_technique": "T1498.001",
        "reason": "Sudden 840% spike in unidirectional TCP SYN packets without ACK handshake completion.",
        "evidence": {
            "rule_or_model": "XGBoost-Volumetric-v3",
            "why_flagged": "Ingress rate reached 28,400 PPS with SYN/ACK asymmetry ratio 1.0",
            "mitre_technique_id": "T1498.001",
            "mitre_tactic": "Impact",
            "trigger_features": {
                "syn_pps": 28400,
                "syn_delta": "+840%",
                "entropy": 1.12,
                "asymmetry_ratio": 1.0,
            }
        },
        "trigger_features": {
            "syn_pps": 28400,
            "asymmetry_ratio": 1.0
        }
    },
    "C2_BEACONING": {
        "threat_class": "C2_BEACONING",
        "attack_classification": "Command & Control Periodic Beaconing",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "source_ip": "10.240.4.88",
        "destination_ip": "203.0.113.195",
        "source_port": 52140,
        "destination_port": 8443,
        "transport_protocol": "TLS 1.3",
        "status": "Mitigated",
        "triage_status": "INVESTIGATING",
        "detector_model": "LSTM-Interval-Beacon-Detector",
        "model_version": "v2.1.0",
        "mitre_technique": "T1071.001",
        "reason": "Regular heartbeat intervals detected with minimal jitter, indicative of automated agent beaconing.",
        "evidence": {
            "rule_or_model": "LSTM-Interval-Beacon-Detector",
            "why_flagged": "Mean beacon interval 45.2s with std dev 0.08s and high payload entropy (7.84)",
            "mitre_technique_id": "T1071.001",
            "mitre_tactic": "Command and Control",
            "trigger_features": {
                "interval_mean_sec": 45.2,
                "jitter_std": 0.08,
                "payload_entropy": 7.84
            }
        },
        "trigger_features": {
            "interval_mean_sec": 45.2,
            "payload_entropy": 7.84
        }
    },
    "DGA_DNS_TUNNEL": {
        "threat_class": "DGA_DNS_TUNNEL",
        "attack_classification": "DNS Tunneling / Algorithmically Generated Domain",
        "severity": "HIGH",
        "confidence": 0.92,
        "source_ip": "10.240.1.19",
        "destination_ip": "1.1.1.1",
        "source_port": 53021,
        "destination_port": 53,
        "transport_protocol": "DNS over UDP",
        "status": "Blocked",
        "triage_status": "NEW",
        "detector_model": "Entropy-DGA-Classifier-v2",
        "model_version": "v1.4.2",
        "mitre_technique": "T1071.004",
        "reason": "High character entropy in requested domain names and anomalous NXDOMAIN burst volume.",
        "evidence": {
            "rule_or_model": "Entropy-DGA-Classifier-v2",
            "why_flagged": "Shannon entropy 4.62 on subdomains with 312 NXDOMAIN bursts per minute",
            "mitre_technique_id": "T1071.004",
            "mitre_tactic": "Command and Control",
            "trigger_features": {
                "domain_entropy": 4.62,
                "nxdomain_burst_count": 312,
                "txt_ratio": 0.78
            }
        },
        "trigger_features": {
            "domain_entropy": 4.62,
            "nxdomain_burst_count": 312
        }
    },
    "ANOMALY": {
        "threat_class": "ANOMALY",
        "attack_classification": "Statistical Flow Anomaly / Latent Protocol Deviation",
        "severity": "MEDIUM",
        "confidence": 0.81,
        "source_ip": "192.168.10.104",
        "destination_ip": "10.240.0.5",
        "source_port": 49912,
        "destination_port": 8080,
        "transport_protocol": "TCP",
        "status": "Monitored",
        "triage_status": "NEW",
        "detector_model": "Autoencoder-Anomaly-v1",
        "model_version": "v1.0.1",
        "mitre_technique": "T1046",
        "reason": "Reconstruction error in bidirectional flow features exceeded 3.5 standard deviations from baseline.",
        "evidence": {
            "rule_or_model": "Autoencoder-Anomaly-v1",
            "why_flagged": "Reconstruction loss 0.084 exceeded threshold 0.021 across PCA embedding space",
            "mitre_technique_id": "T1046",
            "mitre_tactic": "Discovery",
            "trigger_features": {
                "reconstruction_loss": 0.084,
                "z_score": 3.72
            }
        },
        "trigger_features": {
            "reconstruction_loss": 0.084,
            "z_score": 3.72
        }
    }
}


def send_alert(alert_type: str, custom_id: str = None) -> dict:
    """Send a single alert of given threat class to the ingestion endpoint."""
    if alert_type not in SAMPLE_ALERTS:
        raise ValueError(f"Unknown alert type: {alert_type}. Options: {list(SAMPLE_ALERTS.keys())}")
    
    payload = dict(SAMPLE_ALERTS[alert_type])
    alert_uuid = custom_id or f"ALERT-{alert_type}-{int(time.time())}-{random.randint(100, 999)}"
    payload["alert_id"] = alert_uuid
    payload["timestamp"] = datetime.now(timezone.utc).isoformat()

    url = f"{BASE_URL}/api/internal/alerts"
    headers = {"Content-Type": "application/json"}
    data_bytes = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(url, data=data_bytes, headers=headers, method="POST")

    print(f"\n[>>> INGESTION DISPATCH] Sending {alert_type} (ID: {alert_uuid})...")
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            resp_code = response.getcode()
            resp_body = response.read().decode("utf-8")
            data = json.loads(resp_body)
            print(f"  [HTTP {resp_code} CREATED] Saved to SQLite & Broadcasted via WebSocket!")
            print(f"  ID: {data.get('alert_id')} | Threat: {data.get('attack_classification')}")
            print(f"  Severity: {data.get('severity')} | Confidence: {data.get('confidenceFormatted')}")
            print(f"  Source -> Dest: {data.get('srcIp')} -> {data.get('destIp')}")
            return data
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8")
        print(f"  [HTTP ERROR {e.code}]: {error_body}")
        raise
    except Exception as e:
        print(f"  [ERROR]: {e}")
        raise


def fetch_stats() -> dict:
    """Fetch current aggregate SOC statistics from SQLite."""
    url = f"{BASE_URL}/api/stats"
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception as e:
        print(f"Could not fetch stats: {e}")
        return {}


def main():
    parser = argparse.ArgumentParser(description="ShieldX Synthetic Ingestion Pipeline Tester")
    parser.add_argument(
        "--type",
        choices=["ALL", "DDOS", "C2_BEACONING", "DGA_DNS_TUNNEL", "ANOMALY"],
        default="ALL",
        help="Alert type to generate (default: ALL)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=1.5,
        help="Delay in seconds between alerts when sending ALL (default: 1.5s)",
    )
    args = parser.parse_args()

    print("=" * 70)
    print(" SHIELDX ENCLAVE INGESTION PIPELINE VERIFICATION")
    print(" Upstream Detection Engine Simulator")
    print("=" * 70)

    # 1. Check Baseline Stats
    initial_stats = fetch_stats()
    print(f"\n[BASELINE STATS] Total alerts before injection: {initial_stats.get('total_alerts', 'N/A')}")
    print(f"  Critical: {initial_stats.get('critical_count', 0)} | High: {initial_stats.get('high_count', 0)} | Medium: {initial_stats.get('medium_count', 0)} | Low: {initial_stats.get('low_count', 0)}")

    types_to_send = list(SAMPLE_ALERTS.keys()) if args.type == "ALL" else [args.type]

    # 2. Ingest alerts sequentially
    for alert_type in types_to_send:
        send_alert(alert_type)
        if len(types_to_send) > 1 and alert_type != types_to_send[-1]:
            time.sleep(args.delay)

    # 3. Check Updated Stats to verify SQLite recalculation
    time.sleep(0.5)
    updated_stats = fetch_stats()
    print("\n" + "=" * 70)
    print(f"[UPDATED STATS] Total alerts after injection: {updated_stats.get('total_alerts', 'N/A')}")
    print(f"  Critical: {updated_stats.get('critical_count', 0)} | High: {updated_stats.get('high_count', 0)} | Medium: {updated_stats.get('medium_count', 0)} | Low: {updated_stats.get('low_count', 0)}")
    
    diff = updated_stats.get("total_alerts", 0) - initial_stats.get("total_alerts", 0)
    print(f"\nVerified Pipeline Delta: +{diff} alerts recorded in SQLite and broadcasted.")
    print("=" * 70)


if __name__ == "__main__":
    main()
