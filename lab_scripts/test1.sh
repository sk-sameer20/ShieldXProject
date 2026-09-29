#!/bin/bash
echo "[*] Transmitting Telemetry Alert from Kali (192.168.81.10) to ShieldX Enclave..."

curl -s -X POST http://192.168.81.1:8000/api/internal/alerts \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "TEST-LAB-CONNECTIVITY-001",
    "threat_class": "RECONNAISSANCE",
    "attack_classification": "Host-Only Lab Sensor Handshake",
    "severity": "LOW",
    "confidence": 0.99,
    "source_ip": "192.168.81.10",
    "destination_ip": "192.168.81.20",
    "source_port": 54120,
    "destination_port": 445,
    "transport_protocol": "TCP",
    "status": "Monitored",
    "triage_status": "NEW",
    "detector_model": "Enclave-Lab-Telemetry-Sensor",
    "model_version": "v1.0",
    "mitre_technique": "T1595",
    "reason": "Verified bidirectional link between Kali (192.168.81.10) and Windows VM (192.168.81.20).",
    "evidence": {
      "link": "192.168.81.0/24 Host-Only",
      "rtt_ms": 26.5
    }
  }'

echo ""
echo "[+] Telemetry Alert Dispatched! Check your dashboard at http://localhost:8080"
