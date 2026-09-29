import pandas as pd
import numpy as np
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent

SCENARIOS = {
    "capture20110811.binetflow": "2",
    "capture20110812.binetflow": "3",
    "capture20110815.binetflow": "4",
    "capture20110817.binetflow": "9",
}

def analyze_lengths(df_records):
    # Sort globally by timestamp
    df_records = df_records.sort_values(by=["src_ip", "timestamp"])
    
    lengths = [60, 120, 180, 240, 300, 360]
    
    for L in lengths:
        print(f"\n=====================================")
        print(f"=== HISTORY LENGTH: {L} SECONDS ===")
        print(f"=====================================")
        
        # Bin by L seconds
        df_records["window_id"] = (df_records["timestamp"] // L).astype(int)
        
        # Group by host and window
        groups = df_records.groupby(["src_ip", "window_id", "label"])
        
        results = []
        for (src_ip, win_id, label), group in groups:
            count = len(group)
            if count < 3: # Need at least 3 connections for 2 IATs (to get std dev)
                continue
            
            ts = group["timestamp"].values
            iats = np.diff(ts)
            
            span = ts[-1] - ts[0]
            mean = np.mean(iats)
            median = np.median(iats)
            std = np.std(iats)
            cv = std / mean if mean > 0 else 0
            
            results.append({
                "src_ip": src_ip,
                "label": label,
                "count": count,
                "span": span,
                "mean": mean,
                "median": median,
                "std": std,
                "cv": cv
            })
            
        if not results:
            continue
            
        df_res = pd.DataFrame(results)
        
        benign = df_res[df_res["label"] == "benign"]
        c2 = df_res[df_res["label"] == "c2"]
        
        def print_stats(name, df_s):
            if len(df_s) == 0:
                print(f"{name}: No valid windows (>=3 conns).")
                return
                
            print(f"\n{name} (Valid Windows: {len(df_s)}):")
            print(f"  Count: Median {df_s['count'].median():.1f}, 90th {df_s['count'].quantile(0.90):.1f}")
            print(f"  Span:  Median {df_s['span'].median():.1f}s")
            print(f"  IAT Mean:   Median {df_s['mean'].median():.3f}s")
            print(f"  IAT Median: Median {df_s['median'].median():.3f}s")
            print(f"  IAT CV:     Median {df_s['cv'].median():.3f}, 90th {df_s['cv'].quantile(0.90):.3f}")
            
        print_stats("Benign Overall", benign)
        print_stats("C2 Overall", c2)
        
        print("\n  Per C2 Host:")
        for src_ip, group in c2.groupby("src_ip"):
            print(f"    {src_ip}: {len(group)} valid windows | Med Count: {group['count'].median():.1f} | Med CV: {group['cv'].median():.3f}")


def main():
    raw_dir = PROJECT_ROOT / "data" / "raw" / "ctu-13"
    
    all_records = []
    
    for filename in SCENARIOS.keys():
        filepath = raw_dir / filename
        if not filepath.exists():
            continue
            
        print(f"Processing {filename}...")
        df = pd.read_csv(filepath, on_bad_lines='skip')
        
        if "Label" not in df.columns:
            continue
            
        df = df[df["Label"].notna()]
        normal_mask = df["Label"].str.contains("Normal", case=False, na=False)
        botnet_mask = df["Label"].str.contains("Botnet", case=False, na=False)
        cc_mask = df["Label"].str.contains("CC", case=False, na=False)
        c2_mask = botnet_mask & cc_mask
        
        df_filtered = df[normal_mask | c2_mask].copy()
        
        dt = pd.to_datetime(df_filtered["StartTime"], utc=True)
        df_filtered["timestamp"] = (dt - pd.Timestamp("1970-01-01", tz="UTC")).dt.total_seconds()
        
        df_filtered["src_ip"] = df_filtered["SrcAddr"].astype(str)
        df_filtered["label"] = np.where(c2_mask[normal_mask | c2_mask], "c2", "benign")
        
        all_records.append(df_filtered[["timestamp", "src_ip", "label"]])
        
    if not all_records:
        return
        
    full_df = pd.concat(all_records, ignore_index=True)
    analyze_lengths(full_df)

if __name__ == "__main__":
    main()
