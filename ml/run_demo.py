"""
run_demo.py — SIH26145 Person 3: C2 + DGA/DNS Detection Demo

Demonstrates all three detectors against synthetic sample data.
Runs completely standalone — no live network, no real dataset required.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# ── Path setup (so module imports work from repo root) ────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.c2.inference import run_c2_detection
from src.dga.inference import run_dga_detection
from src.dns.inference import run_dns_tunnel_detection

SAMPLE_DIR = PROJECT_ROOT / "data" / "sample"
SEP = "=" * 56


def load_jsonl(path: Path) -> list:
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def severity_color(severity: str) -> str:
    return {"high": "[!!!]", "medium": "[!! ]", "low": "[.  ]", "critical": "[!!!]"}.get(severity, "[   ]")


def print_alert(label: str, alert) -> None:
    detected_str = "[DETECTED]" if alert.detected else "[Clean]   "
    sev = severity_color(alert.severity)
    print(f"\n  [{label}]")
    print(f"  Status:     {detected_str}")
    print(f"  Threat:     {alert.threat_class}")
    print(f"  Confidence: {alert.confidence * 100:.1f}%")
    print(f"  Severity:   {sev} {alert.severity.upper()}")
    if alert.evidence:
        print(f"  Evidence:")
        for e in alert.evidence:
            print(f"    • {e}")
    if alert.src_ip:
        print(f"  Host:       {alert.src_ip}")
    print(f"  Model:      {alert.model_version}")


def main() -> None:
    print(SEP)
    print("   SIH26145 — Person 3: C2 + DGA/DNS Detection Demo")
    print(SEP)
    print("  Using: SYNTHETIC sample data (data/sample/*.jsonl)")
    print("  All detectors: standalone, no live network required.\n")

    t0 = time.perf_counter()

    # ── 1. C2 Beaconing ───────────────────────────────────────────────────
    print(SEP)
    print("  SCENARIO 1 — C2 BEACONING")
    print(SEP)

    benign_conn = load_jsonl(SAMPLE_DIR / "benign_conn.jsonl")
    c2_conn = load_jsonl(SAMPLE_DIR / "c2_conn.jsonl")

    # Extract records per src_ip
    c2_src = "10.0.0.25"
    c2_window = [r for r in c2_conn if r.get("src_ip") == c2_src]
    benign_src = "10.0.0.5"
    benign_window_conn = [r for r in benign_conn if r.get("src_ip") == benign_src]

    alert_c2 = run_c2_detection(
        c2_window, src_ip=c2_src,
        window_start=c2_window[0]["timestamp"] if c2_window else None,
        window_end=c2_window[-1]["timestamp"] if c2_window else None,
    )
    alert_benign_c2 = run_c2_detection(
        benign_window_conn, src_ip=benign_src,
        window_start=benign_window_conn[0]["timestamp"] if benign_window_conn else None,
        window_end=benign_window_conn[-1]["timestamp"] if benign_window_conn else None,
    )

    print_alert("C2 — Malicious host (30s beacon interval)", alert_c2)
    print_alert("C2 — Benign host (normal browsing)", alert_benign_c2)

    # ── 2. DGA Detection ──────────────────────────────────────────────────
    print(f"\n{SEP}")
    print("  SCENARIO 2 — DGA DOMAIN ACTIVITY")
    print(SEP)

    benign_dns = load_jsonl(SAMPLE_DIR / "benign_dns.jsonl")
    dga_dns = load_jsonl(SAMPLE_DIR / "dga_dns.jsonl")

    alert_dga = run_dga_detection(
        dga_dns, src_ip="10.0.0.30",
        window_start=dga_dns[0]["timestamp"] if dga_dns else None,
        window_end=dga_dns[-1]["timestamp"] if dga_dns else None,
    )
    alert_benign_dns = run_dga_detection(
        benign_dns, src_ip="10.0.0.5",
        window_start=benign_dns[0]["timestamp"] if benign_dns else None,
        window_end=benign_dns[-1]["timestamp"] if benign_dns else None,
    )

    print_alert("DGA — Malicious host (NXDOMAIN storm, random domains)", alert_dga)
    print_alert("DGA — Benign host (normal DNS)", alert_benign_dns)

    # ── 3. DNS Tunnelling ─────────────────────────────────────────────────
    print(f"\n{SEP}")
    print("  SCENARIO 3 — DNS TUNNELLING")
    print(SEP)

    tunnel_dns = load_jsonl(SAMPLE_DIR / "tunnel_dns.jsonl")

    alert_tunnel = run_dns_tunnel_detection(
        tunnel_dns, src_ip="10.0.0.40",
        window_start=tunnel_dns[0]["timestamp"] if tunnel_dns else None,
        window_end=tunnel_dns[-1]["timestamp"] if tunnel_dns else None,
    )
    alert_benign_tunnel = run_dns_tunnel_detection(
        benign_dns, src_ip="10.0.0.5",
        window_start=benign_dns[0]["timestamp"] if benign_dns else None,
        window_end=benign_dns[-1]["timestamp"] if benign_dns else None,
    )

    print_alert("DNS_TUNNEL — Encoded TXT queries to single domain", alert_tunnel)
    print_alert("DNS_TUNNEL — Benign host (normal DNS)", alert_benign_tunnel)

    # ── Summary ────────────────────────────────────────────────────────────
    elapsed = time.perf_counter() - t0
    print(f"\n{SEP}")
    print("  INTEGRATION CONTRACT (for Person 4)")
    print(SEP)
    print("  from src.c2.inference import run_c2_detection")
    print("  from src.dns.inference import run_dga_detection, run_dns_tunnel_detection")
    print()
    print("  c2_alert     = run_c2_detection(window, src_ip=...)")
    print("  dga_alert    = run_dga_detection(window, src_ip=...)")
    print("  tunnel_alert = run_dns_tunnel_detection(window, src_ip=...)")
    print()
    print("  Each returns: Alert(detected, threat_class, confidence, severity, evidence)")
    print(f"\n  Demo completed in {elapsed * 1000:.1f} ms")
    print(SEP)


if __name__ == "__main__":
    main()
