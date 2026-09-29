import os
import pandas as pd
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
RAW_DIR = PROJECT_ROOT / "data" / "raw" / "ctu-13"

SCENARIOS = ["capture20110811.binetflow", "capture20110812.binetflow", "capture20110815.binetflow", "capture20110817.binetflow"]

def analyze():
    print("="*60)
    print(" INVESTIGATION: CTU-13 FLOW TO WINDOW REDUCTION")
    print("="*60)

    total_unique_ips_normal = set()
    total_unique_ips_c2 = set()
    
    scenario_stats = {}
    window_details = []

    for filename in SCENARIOS:
        filepath = RAW_DIR / filename
        if not filepath.exists():
            continue
        
        df = pd.read_csv(filepath, on_bad_lines='skip')
        df = df[df["Label"].notna()]
        
        normal_mask = df["Label"].str.contains("Normal", case=False, na=False)
        botnet_mask = df["Label"].str.contains("Botnet", case=False, na=False)
        cc_mask = df["Label"].str.contains("CC", case=False, na=False)
        c2_mask = botnet_mask & cc_mask
        
        df_filtered = df[normal_mask | c2_mask].copy()
        df_filtered["is_c2"] = c2_mask
        df_filtered["std_label"] = df_filtered["is_c2"].map({True: "c2", False: "benign"})
        
        normal_flows = df_filtered[~df_filtered["is_c2"]]
        c2_flows = df_filtered[df_filtered["is_c2"]]
        
        normal_ips = set(normal_flows["SrcAddr"].unique())
        c2_ips = set(c2_flows["SrcAddr"].unique())
        
        total_unique_ips_normal.update(normal_ips)
        total_unique_ips_c2.update(c2_ips)
        
        df_filtered["timestamp"] = pd.to_datetime(df_filtered["StartTime"]).astype("int64") / 1e9
        # Sort chronologically
        df_filtered = df_filtered.sort_values(by=["SrcAddr", "timestamp"])
        
        grouped = df_filtered.groupby(["SrcAddr", "std_label"])
        
        benign_windows = 0
        malicious_windows = 0
        
        # Simulators
        t30_windows_c2 = 0
        t30_windows_benign = 0
        t60_windows_c2 = 0
        t60_windows_benign = 0
        
        for (src_ip, label), group in grouped:
            # Simulate 30s tumbling windows
            # group is sorted by timestamp
            group["time_floor_30"] = (group["timestamp"] // 30) * 30
            win_30 = group.groupby("time_floor_30")
            for _, w in win_30:
                if len(w) >= 3:
                    if label == "c2": t30_windows_c2 += 1
                    else: t30_windows_benign += 1
                    
            # Simulate 60s tumbling windows
            group["time_floor_60"] = (group["timestamp"] // 60) * 60
            win_60 = group.groupby("time_floor_60")
            for _, w in win_60:
                if len(w) >= 3:
                    if label == "c2": t60_windows_c2 += 1
                    else: t60_windows_benign += 1

            if len(group) >= 3:
                if label == "c2":
                    malicious_windows += 1
                else:
                    benign_windows += 1
                
                start_ts = pd.to_datetime(group["timestamp"].min(), unit="s")
                end_ts = pd.to_datetime(group["timestamp"].max(), unit="s")
                duration = group["timestamp"].max() - group["timestamp"].min()
                
                window_details.append({
                    "src_ip": src_ip,
                    "scenario": filename,
                    "start_timestamp": str(start_ts),
                    "end_timestamp": str(end_ts),
                    "duration": duration,
                    "flows": len(group),
                    "label": label
                })
        
        scenario_stats[filename] = {
            "retained_normal": len(normal_flows),
            "retained_c2": len(c2_flows),
            "unique_ips_normal": len(normal_ips),
            "unique_ips_c2": len(c2_ips),
            "generated_windows": benign_windows + malicious_windows,
            "benign_windows": benign_windows,
            "malicious_windows": malicious_windows,
            "t30_c2": t30_windows_c2,
            "t30_benign": t30_windows_benign,
            "t60_c2": t60_windows_c2,
            "t60_benign": t60_windows_benign
        }

    print("\n1. Total unique src_ip values after filtering:", len(total_unique_ips_normal | total_unique_ips_c2))
    print("\n2. Unique src_ip values for:")
    print(f"   - Normal: {len(total_unique_ips_normal)}")
    print(f"   - C2/CC: {len(total_unique_ips_c2)}")
    
    print("\n3. Per-scenario statistics:")
    total_t30_c2 = 0
    total_t30_benign = 0
    total_t60_c2 = 0
    total_t60_benign = 0
    for sc, stats in scenario_stats.items():
        print(f"\n   [{sc}]")
        print(f"     - Retained Normal flows: {stats['retained_normal']:,}")
        print(f"     - Retained C2 flows: {stats['retained_c2']:,}")
        print(f"     - Unique Source IPs (Normal): {stats['unique_ips_normal']:,}")
        print(f"     - Unique Source IPs (C2): {stats['unique_ips_c2']:,}")
        print(f"     - Current Generated windows: {stats['generated_windows']}")
        print(f"       (Benign: {stats['benign_windows']}, Malicious: {stats['malicious_windows']})")
        print(f"     - SIMULATED 30s Windows (>=3 flows): Benign: {stats['t30_benign']}, Malicious: {stats['t30_c2']}")
        print(f"     - SIMULATED 60s Windows (>=3 flows): Benign: {stats['t60_benign']}, Malicious: {stats['t60_c2']}")
        
        total_t30_c2 += stats['t30_c2']
        total_t30_benign += stats['t30_benign']
        total_t60_c2 += stats['t60_c2']
        total_t60_benign += stats['t60_benign']

    print("\n4. Window details (C2 windows):")
    c2_win = [w for w in window_details if w["label"] == "c2"]
    for w in c2_win:
        print(f"   [C2] IP: {w['src_ip']:<15} | Scen: {w['scenario']} | Flows: {w['flows']:<6} | Dur(s): {w['duration']:<6.1f} | Start: {w['start_timestamp']} | End: {w['end_timestamp']}")
    
    print("\n[SUMMARY TOTALS FOR PROPOSAL]")
    print(f"Tumbling 30s (>=3 flows): Benign {total_t30_benign}, C2 {total_t30_c2}")
    print(f"Tumbling 60s (>=3 flows): Benign {total_t60_benign}, C2 {total_t60_c2}")

if __name__ == "__main__":
    analyze()
