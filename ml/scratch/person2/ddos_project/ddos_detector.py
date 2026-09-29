import json
import math
import pandas as pd
from collections import Counter

def calculate_entropy(ip_list):
    """Calculates Shannon Entropy for Source IP Diversity."""
    if not ip_list:
        return 0.0
    total_count = len(ip_list)
    counts = Counter(ip_list)
    entropy = 0.0
    for count in counts.values():
        p = count / total_count
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def parse_zeek_conn_log(file_path):
    """Parses Zeek JSON conn.log and extracts DDoS metric features."""
    connections = []
    
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                connections.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if not connections:
        print("No valid connection records found.")
        return

    df = pd.DataFrame(connections)

    # 1. Calculate Packet & Byte Rates
    total_packets = df['orig_pkts'].sum() if 'orig_pkts' in df.columns else len(df)
    total_bytes = df['orig_bytes'].sum() if 'orig_bytes' in df.columns else 0
    duration = df['duration'].sum() if 'duration' in df.columns else 1.0
    duration = max(duration, 1.0) # Avoid division by zero

    pps = round(total_packets / duration, 2)
    bps = round(total_bytes / duration, 2)

    # 2. Calculate SYN Ratio
    syn_count = 0
    if 'conn_state' in df.columns:
        syn_count = df['conn_state'].isin(['S0', 'REJ', 'S1']).sum()
    syn_ratio = round(syn_count / len(df), 2)

    # 3. Calculate Source IP Entropy
    source_ips = df['id.orig_h'].tolist() if 'id.orig_h' in df.columns else []
    entropy = calculate_entropy(source_ips)

    # Print Extracted DDoS Feature Vector
    print("\n--- Extracted DDoS Feature Vector ---")
    print(f"Packets Per Second (PPS): {pps}")
    print(f"Bytes Per Second (BPS)  : {bps}")
    print(f"SYN Flag Ratio          : {syn_ratio}")
    print(f"Source IP Entropy       : {entropy}")
    print(f"Unique Source IPs       : {len(set(source_ips))}")

    # 4. Alert Generation
    baseline_pps = 5.0
    pps_multiplier = round(pps / baseline_pps, 1) if baseline_pps > 0 else 1.0

    alert = {
     "threat": "DDoS",
        "confidence": 94 if syn_ratio > 0.8 or pps_multiplier > 5 else 12,
        "evidence": [
            f"PPS increased {pps_multiplier}x",
            f"SYN ratio = {syn_ratio}",
            "Source entropy calculated"
        ]
    }

    print("\n--- Generated Alert Output ---")
    print(json.dumps(alert, indent=2))

if __name__ == "__main__":
    parse_zeek_conn_log("conn.log")
