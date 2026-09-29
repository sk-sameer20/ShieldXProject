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

def analyze_iats(df_records):
    # Sort globally by timestamp
    df_records = df_records.sort_values(by=["src_ip", "timestamp"])
    
    # Calculate IAT within each host
    df_records["iat"] = df_records.groupby("src_ip")["timestamp"].diff()
    
    # We only care about valid IATs (ignore the first connection which has NaN)
    valid_iats = df_records.dropna(subset=["iat"])
    
    benign = valid_iats[valid_iats["label"] == "benign"]
    c2 = valid_iats[valid_iats["label"] == "c2"]
    
    print("=== GLOBAL TEMPORAL STATISTICS ===")
    
    def print_stats(name, s):
        if len(s) == 0:
            return
        median = s.median()
        mean = s.mean()
        std = s.std()
        cv = std / mean if mean > 0 else 0
        q25 = s.quantile(0.25)
        q75 = s.quantile(0.75)
        q90 = s.quantile(0.90)
        q99 = s.quantile(0.99)
        print(f"\n{name} (N={len(s)} IATs):")
        print(f"  Mean:   {mean:.4f}s")
        print(f"  Median: {median:.4f}s")
        print(f"  Std:    {std:.4f}s")
        print(f"  CV:     {cv:.4f}")
        print(f"  IQR:    {q25:.4f}s - {q75:.4f}s")
        print(f"  90th:   {q90:.4f}s")
        print(f"  99th:   {q99:.4f}s")

    print_stats("Benign Overall", benign["iat"])
    print_stats("C2 Overall", c2["iat"])
    
    print("\n=== PER C2 HOST TEMPORAL STATISTICS ===")
    for src_ip, group in c2.groupby("src_ip"):
        print_stats(f"Host {src_ip}", group["iat"])
        
    print("\n=== TOP 5 BENIGN HOSTS TEMPORAL STATISTICS ===")
    top_benign = benign["src_ip"].value_counts().head(5)
    for src_ip in top_benign.index:
        group = benign[benign["src_ip"] == src_ip]
        print_stats(f"Benign Host {src_ip}", group["iat"])


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
        
        # Keep only necessary columns to save memory
        all_records.append(df_filtered[["timestamp", "src_ip", "label"]])
        
    if not all_records:
        return
        
    full_df = pd.concat(all_records, ignore_index=True)
    analyze_iats(full_df)

if __name__ == "__main__":
    main()
