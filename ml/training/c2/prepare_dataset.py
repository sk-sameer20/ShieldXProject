"""
training/c2/prepare_dataset.py — Build C2 feature CSV from real CTU-13 data.

Downloads binetflow files for selected scenarios, filters for Normal and CC Botnet
traffic, and extracts features grouped by source IP.

Outputs:
    data/processed/c2_features.csv
"""

from __future__ import annotations

import os
import sys
import urllib.request
import ssl
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.c2.features import extract_c2_features, C2_FEATURE_NAMES

OUTPUT_PATH = PROJECT_ROOT / "data" / "processed" / "c2_features.csv"
RAW_DIR = PROJECT_ROOT / "data" / "raw" / "ctu-13"

# Scenarios to use for C2 (Botnet CC traffic)
SCENARIOS = {
    "2": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-43/capture20110811.binetflow",
    "3": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-44/capture20110812.binetflow",
    "4": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-45/capture20110815.binetflow",
    "9": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-50/capture20110817.binetflow",
}

def download_file(url: str, dest: Path) -> None:
    if dest.exists():
        print(f"  [OK] Already downloaded: {dest.name}")
        return
    print(f"  [DL] Downloading {dest.name}...")
    dest.parent.mkdir(parents=True, exist_ok=True)
    # Disable SSL verification due to certificate issues on Windows
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(url, context=ctx) as response, open(dest, 'wb') as out_file:
            import shutil
            shutil.copyfileobj(response, out_file)
        print(f"  [OK] Download complete.")
    except urllib.error.HTTPError as e:
        print(f"  [!] HTTP Error: {e.code} for {url}")
        print("      Cannot download automatically. Please place file manually.")
        # Remove empty file if created
        if dest.exists() and dest.stat().st_size == 0:
            dest.unlink()

def process_scenario(filepath: Path) -> tuple[pd.DataFrame, dict]:
    print(f"  [*] Processing {filepath.name}...")
    metrics = {
        "raw_rows": 0,
        "filtered_rows": 0,
        "dropped_background": 0,
        "dropped_non_cc": 0,
        "normal_count": 0,
        "c2_count": 0,
        "sub_labels": {},
        "windows_generated": 0,
        "windows_benign": 0,
        "windows_malicious": 0,
        "dropped_small_windows": 0,
        "dropped_c2_small_windows": 0,
        "window_sizes": [],
        "windows_1_flow": 0,
        "windows_2_flows": 0,
        "windows_3plus_flows": 0
    }
    
    # Read CSV. Some rows might be malformed, use error_bad_lines=False if needed, 
    # but for modern pandas we use on_bad_lines='skip'.
    # binetflow has columns: StartTime, Dur, Proto, SrcAddr, Sport, Dir, DstAddr, Dport, State, sTos, dTos, TotPkts, TotBytes, SrcBytes, Label
    try:
        df = pd.read_csv(filepath, on_bad_lines='skip')
        metrics["raw_rows"] = int(len(df))
    except Exception as e:
        print(f"  [!] Error reading CSV: {e}")
        return pd.DataFrame(), metrics

    # Filter to only Normal and Botnet CC traffic. Drop Background.
    # The labels look like: "flow=Background", "flow=From-Normal", "flow=From-Botnet-V1-TCP-CC-108-HTTP-Custom-Port"
    if "Label" not in df.columns:
        print(f"  [!] Missing Label column in {filepath.name}")
        return pd.DataFrame(), metrics

    df = df[df["Label"].notna()]
    
    # Identify Normal
    normal_mask = df["Label"].str.contains("Normal", case=False, na=False)
    
    # Identify C2 (Botnet AND contains CC)
    botnet_mask = df["Label"].str.contains("Botnet", case=False, na=False)
    cc_mask = df["Label"].str.contains("CC", case=False, na=False)
    c2_mask = botnet_mask & cc_mask
    
    metrics["dropped_background"] = int(len(df[~normal_mask & ~botnet_mask]))
    metrics["dropped_non_cc"] = int(len(df[botnet_mask & ~cc_mask]))
    
    # Combine masks
    df_filtered = df[normal_mask | c2_mask].copy()
    metrics["filtered_rows"] = int(len(df_filtered))
    metrics["normal_count"] = int(normal_mask.sum())
    metrics["c2_count"] = int(c2_mask.sum())
    
    if metrics["c2_count"] > 0:
        sub_labels = df[c2_mask]["Label"].value_counts().to_dict()
        metrics["sub_labels"] = {k: int(v) for k, v in sub_labels.items()}

    # Assign our standard binary labels
    df_filtered["is_c2"] = df_filtered["Label"].str.contains("Botnet", case=False, na=False) & df_filtered["Label"].str.contains("CC", case=False, na=False)
    df_filtered["std_label"] = df_filtered["is_c2"].map({True: "c2", False: "benign"})

    # Map columns to what our feature extractor expects
    # extract_c2_features expects dicts with: timestamp, duration, src_ip, dst_ip, orig_bytes, resp_bytes
    # CTU-13 has: StartTime (string), Dur, SrcAddr, DstAddr, SrcBytes, TotBytes
    
    # Convert string StartTime to timezone-aware UTC datetime, then to epoch seconds
    dt = pd.to_datetime(df_filtered["StartTime"], utc=True)
    df_filtered["timestamp"] = (dt - pd.Timestamp("1970-01-01", tz="UTC")).dt.total_seconds()
    
    # 60-second tumbling window
    df_filtered["window_id"] = (df_filtered["timestamp"] // 60) * 60
    
    records = []
    for _, row in df_filtered.iterrows():
        orig_bytes = float(row.get("SrcBytes", 0))
        tot_bytes = float(row.get("TotBytes", 0))
        resp_bytes = max(0.0, tot_bytes - orig_bytes)
        
        state = str(row.get("State", ""))
        tcp_success = 1 if ("PA_" in state or "FA_" in state or "FPA_" in state) else 0
        
        records.append({
            "timestamp": float(row.get("timestamp", 0)),
            "window_id": float(row.get("window_id", 0)),
            "duration": float(row.get("Dur", 0)),
            "src_ip": str(row.get("SrcAddr", "")),
            "dst_ip": str(row.get("DstAddr", "")),
            "orig_bytes": orig_bytes,
            "resp_bytes": resp_bytes,
            "label": row.get("std_label", "benign"),
            "proto": str(row.get("Proto", "")).lower(),
            "pkts": float(row.get("TotPkts", 0) or 0),
            "tcp_success": tcp_success
        })

    # Group by src_ip, window_id, and label to extract features per 60-second chunk
    df_records = pd.DataFrame(records)
    if df_records.empty:
        return pd.DataFrame(), metrics

    feature_rows = []
    grouped = df_records.groupby(["src_ip", "label", "window_id"])
    
    for (src_ip, label, window_id), group in grouped:
        n_flows = len(group)
        
        # New filtering logic
        if label == "c2" and n_flows < 3:
            metrics["dropped_c2_small_windows"] += 1
            metrics["dropped_small_windows"] += 1
            continue
        elif label == "benign" and n_flows < 1:
            # Technically impossible due to groupby, but conceptually
            metrics["dropped_small_windows"] += 1
            continue
            
        if n_flows == 1:
            metrics["windows_1_flow"] += 1
        elif n_flows == 2:
            metrics["windows_2_flows"] += 1
        else:
            metrics["windows_3plus_flows"] += 1
            
        group_records = group.to_dict(orient="records")
        features = extract_c2_features(group_records, src_ip=src_ip)
        features["src_ip"] = src_ip
        features["label"] = label
        features["window_id"] = window_id
        
        window_start = group["timestamp"].min()
        window_end = group["timestamp"].max()
        features["window_start"] = window_start
        features["window_end"] = window_end
        
        feature_rows.append(features)
        
        metrics["windows_generated"] += 1
        metrics["window_sizes"].append(len(group))
        
        if label == "c2":
            metrics["windows_malicious"] += 1
        else:
            metrics["windows_benign"] += 1

    return pd.DataFrame(feature_rows), metrics


def main() -> None:
    print("=" * 60)
    print("  C2 Dataset Preparation (CTU-13)")
    print("=" * 60)

    # Note: Downloading the full binetflow files takes time (hundreds of MBs). 
    # We will process them one by one.
    
    all_features = pd.DataFrame()
    global_metrics = {
        "raw_rows": 0,
        "filtered_rows": 0,
        "dropped_background": 0,
        "dropped_non_cc": 0,
        "normal_count": 0,
        "c2_count": 0,
        "windows_generated": 0,
        "windows_benign": 0,
        "windows_malicious": 0,
        "dropped_small_windows": 0,
        "dropped_c2_small_windows": 0,
        "scenarios": {},
        "c2_hosts": {},
        "benign_hosts": {},
        "sub_labels": {},
        "window_sizes": [],
        "windows_1_flow": 0,
        "windows_2_flows": 0,
        "windows_3plus_flows": 0
    }

    for sc_id, url in SCENARIOS.items():
        filename = url.split("/")[-1]
        dest = RAW_DIR / filename
        download_file(url, dest)
        if not dest.exists() or dest.stat().st_size == 0:
            print(f"  [-] Skipping {filename} due to missing file.")
            continue
            
        df_feat, metrics = process_scenario(dest)
        
        # Accumulate metrics
        for k in ["raw_rows", "filtered_rows", "dropped_background", "dropped_non_cc", 
                  "normal_count", "c2_count", "windows_generated", "windows_benign", 
                  "windows_malicious", "dropped_small_windows", "dropped_c2_small_windows",
                  "windows_1_flow", "windows_2_flows", "windows_3plus_flows"]:
            global_metrics[k] += metrics[k]
            
        global_metrics["window_sizes"].extend(metrics["window_sizes"])
        
        global_metrics["scenarios"][filename] = metrics["windows_generated"]
        for label, count in metrics["sub_labels"].items():
            global_metrics["sub_labels"][label] = global_metrics["sub_labels"].get(label, 0) + count

        if not df_feat.empty:
            df_feat["scenario"] = filename # Add scenario name for tracking
            
            # Count windows per C2 host and Benign host
            c2_windows = df_feat[df_feat["label"] == "c2"]
            for src_ip, count in c2_windows["src_ip"].value_counts().items():
                global_metrics["c2_hosts"][src_ip] = global_metrics["c2_hosts"].get(src_ip, 0) + count
                
            benign_windows = df_feat[df_feat["label"] == "benign"]
            for src_ip, count in benign_windows["src_ip"].value_counts().items():
                global_metrics["benign_hosts"][src_ip] = global_metrics["benign_hosts"].get(src_ip, 0) + count
                
            all_features = pd.concat([all_features, df_feat], ignore_index=True)
            print(f"  [+] Extracted {len(df_feat)} temporal feature rows from Scenario {sc_id}.")

    if all_features.empty:
        print("  [!] Error: No features extracted.")
        sys.exit(1)

    # Save
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    all_features.to_csv(OUTPUT_PATH, index=False)

    print(f"\n  [OK] Saved {len(all_features)} rows -> {OUTPUT_PATH}")
    
    import json
    metrics_path = OUTPUT_PATH.parent / "c2_metrics.json"
    
    # Calculate duplicates and missing before saving metrics
    feature_cols = [c for c in all_features.columns if c not in ['src_ip', 'label', 'scenario', 'window_id', 'window_start', 'window_end']]
    duplicates = int(all_features.duplicated(subset=feature_cols).sum())
    missing = int(all_features.isnull().sum().sum())
    
    global_metrics["duplicates"] = duplicates
    global_metrics["missing_values"] = missing
    global_metrics["final_feature_count"] = len(feature_cols)
    
    # Calculate min/median/max connections per window
    import numpy as np
    sizes = global_metrics["window_sizes"]
    if sizes:
        global_metrics["window_conn_min"] = int(np.min(sizes))
        global_metrics["window_conn_median"] = int(np.median(sizes))
        global_metrics["window_conn_max"] = int(np.max(sizes))
    else:
        global_metrics["window_conn_min"] = 0
        global_metrics["window_conn_median"] = 0
        global_metrics["window_conn_max"] = 0
    
    # Remove large list from JSON to save space
    del global_metrics["window_sizes"]
    
    with open(metrics_path, "w") as f:
        json.dump(global_metrics, f, indent=4)
        
    print("\n  DATASET STATISTICS:")
    print(all_features['label'].value_counts().to_string())
    print(f"  Total features per row: {len(C2_FEATURE_NAMES)}")
    print("=" * 60)

if __name__ == "__main__":
    main()
