"""
Live HTTP verification script for all ShieldX REST endpoints.
"""
import urllib.request
import json

BASE = "http://127.0.0.1:8000"

endpoints = [
    ("GET /docs", "/docs"),
    ("GET /openapi.json", "/openapi.json"),
    ("GET /api/health", "/api/health"),
    ("GET /api/alerts?page=1&page_size=3", "/api/alerts?page=1&page_size=3"),
    ("GET /api/alerts/alt-ddos-8901", "/api/alerts/alt-ddos-8901"),
    ("GET /api/stats", "/api/stats"),
    ("GET /api/stats/threat-distribution", "/api/stats/threat-distribution"),
    ("GET /api/stats/timeline?limit=3", "/api/stats/timeline?limit=3"),
    ("GET /api/traffic?limit=2", "/api/traffic?limit=2"),
    ("GET /api/detectors/status", "/api/detectors/status"),
]

print("=" * 70)
print("TESTING ALL REST ENDPOINTS AGAINST RUNNING FASTAPI SERVER")
print("=" * 70)

for label, path in endpoints:
    url = BASE + path
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req) as resp:
            status = resp.status
            content_type = resp.headers.get("content-type", "")
            if "json" in content_type:
                data = json.loads(resp.read().decode("utf-8"))
                preview = json.dumps(data)[:90].replace("\n", " ")
            else:
                preview = resp.read().decode("utf-8")[:90].replace("\n", " ")
            print(f"[PASS] {label:<36} -> HTTP {status} | {preview}...")
    except Exception as e:
        print(f"[FAIL] {label:<36} -> Error: {e}")

# Test POST /api/internal/alerts
print("\n" + "=" * 70)
print("TESTING INGESTION HOOK: POST /api/internal/alerts")
print("=" * 70)
post_url = BASE + "/api/internal/alerts"
payload = {
    "alert_id": "alt-live-curl-01",
    "timestamp": "2026-09-24T12:00:00Z",
    "threat_class": "DDOS",
    "attack_classification": "Volumetric SYN Flood",
    "severity": "CRITICAL",
    "confidence": 0.99,
    "source_ip": "198.51.100.200",
    "destination_ip": "10.240.0.12",
    "transport_protocol": "TCP : 443",
    "status": "Mitigated",
    "triage_status": "NEW",
    "detector_model": "Ensemble-Volumetric-v3",
    "reason": "Real-time test ingestion via live HTTP call",
}
req = urllib.request.Request(
    post_url,
    data=json.dumps(payload).encode("utf-8"),
    headers={"Content-Type": "application/json"},
    method="POST",
)
try:
    with urllib.request.urlopen(req) as resp:
        res_data = json.loads(resp.read().decode("utf-8"))
        print(f"[PASS] POST /api/internal/alerts          -> HTTP {resp.status} | Created alert: {res_data['id']} (confidence={res_data['confidenceFormatted']})")
except Exception as e:
    print(f"[FAIL] POST /api/internal/alerts          -> Error: {e}")

print("=" * 70)
