import pandas as pd
import numpy as np
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

SCENARIOS = {
    "capture20110811.binetflow": "2",
    "capture20110812.binetflow": "3",
    "capture20110815.binetflow": "4",
    "capture20110817.binetflow": "9",
}

TEST_HOSTS = [
    "147.32.84.165", # C2
    "147.32.84.191", # C2
    "147.32.84.192", # C2
]

def main():
    # 1. Temporal Timelines
    raw_dir = PROJECT_ROOT / "data" / "raw" / "ctu-13"
    all_records = []
    
    for filename, scenario_id in SCENARIOS.items():
        filepath = raw_dir / filename
        if not filepath.exists():
            continue
            
        df = pd.read_csv(filepath, on_bad_lines='skip')
        if "Label" not in df.columns:
            continue
            
        df = df[df["Label"].notna()]
        botnet_mask = df["Label"].str.contains("Botnet", case=False, na=False)
        cc_mask = df["Label"].str.contains("CC", case=False, na=False)
        c2_mask = botnet_mask & cc_mask
        
        df_filtered = df[c2_mask].copy()
        if df_filtered.empty:
            continue
            
        dt = pd.to_datetime(df_filtered["StartTime"], utc=True)
        df_filtered["timestamp"] = (dt - pd.Timestamp("1970-01-01", tz="UTC")).dt.total_seconds()
        df_filtered["src_ip"] = df_filtered["SrcAddr"].astype(str)
        df_filtered = df_filtered[df_filtered["src_ip"].isin(TEST_HOSTS)]
        
        df_filtered["scenario"] = scenario_id
        
        all_records.append(df_filtered[["timestamp", "src_ip", "scenario"]])
        
    full_timeline = pd.concat(all_records, ignore_index=True)
    full_timeline.sort_values(by=["src_ip", "timestamp"], inplace=True)
    
    host_timelines = {}
    host_start_times = {}
    for src_ip, group in full_timeline.groupby("src_ip"):
        host_timelines[src_ip] = group["timestamp"].values
        host_start_times[src_ip] = group["timestamp"].min()

    # 2. Evaluation dataset
    csv_path = PROJECT_ROOT / "data" / "processed" / "c2_features.csv"
    df_eval = pd.read_csv(csv_path)
    df_test = df_eval[(df_eval["src_ip"].isin(TEST_HOSTS)) & (df_eval["label"] == "c2")].copy()
    
    fn_list = []
    
    tp_count = 0
    fn_count = 0
    host_stats = {h: {"tp": 0, "fn": 0} for h in TEST_HOSTS}

    # 3. Analyze each C2 window
    for _, row in df_test.iterrows():
        src_ip = row["src_ip"]
        window_end = row["window_end"]
        scenario = row["scenario"]
        
        if src_ip not in host_timelines:
            continue
            
        ts_array = host_timelines[src_ip]
        mask = (ts_array > window_end - 300) & (ts_array <= window_end)
        conns = ts_array[mask]
        
        count = len(conns)
        
        mean_iat = 0.0
        med_iat = 0.0
        std_iat = 0.0
        cv = 100.0
        span = 0.0
        max_iat = 0.0
        
        if count >= 3:
            iats = np.diff(conns)
            mean_iat = np.mean(iats)
            med_iat = np.median(iats)
            std_iat = np.std(iats)
            max_iat = np.max(iats)
            if mean_iat > 0:
                cv = std_iat / mean_iat
            span = conns[-1] - conns[0]
            
        is_tp = (count >= 7) and (cv <= 1.0)
        
        if is_tp:
            tp_count += 1
            host_stats[src_ip]["tp"] += 1
        else:
            fn_count += 1
            host_stats[src_ip]["fn"] += 1
            
            # Determine reason
            reason = "other"
            time_since_first = window_end - host_start_times[src_ip]
            
            if time_since_first < 300:
                reason = "4. boundary/history issue"
            elif count < 7:
                if max_iat > 60.0:
                    reason = "3. dormant-period effect"
                else:
                    reason = "1. insufficient connections"
            elif cv > 1.0:
                if max_iat > 60.0:
                    reason = "3. dormant-period effect"
                else:
                    reason = "2. CV > 1.0"
                    
            fn_list.append({
                "src_ip": src_ip,
                "scenario": scenario,
                "count": count,
                "iat_mean": mean_iat,
                "iat_median": med_iat,
                "iat_std": std_iat,
                "iat_cv": cv,
                "span": span,
                "max_iat": max_iat,
                "time_since_start": time_since_first,
                "reason": reason
            })
            
    print("=== PER-C2-HOST RECALL ===")
    for h in TEST_HOSTS:
        t = host_stats[h]["tp"]
        f = host_stats[h]["fn"]
        tot = t + f
        rec = (t / tot * 100) if tot > 0 else 0
        print(f"{h}: {t} TP / {tot} total (Recall: {rec:.1f}%)")
        
    print("\n=== FALSE NEGATIVE REASONS ===")
    df_fn = pd.DataFrame(fn_list)
    if df_fn.empty:
        print("No false negatives found!")
        return
        
    reason_counts = df_fn["reason"].value_counts()
    for r, c in reason_counts.items():
        pct = (c / len(df_fn)) * 100
        print(f"{r}: {c} ({pct:.1f}%)")
        
    print("\n=== FALSE NEGATIVE DETAILS ===")
    for _, row in df_fn.iterrows():
        print(f"[{row['reason']}] Host {row['src_ip']} (Scen {row['scenario']}):")
        print(f"  Count: {row['count']} | Span: {row['span']:.1f}s | time_since_start: {row['time_since_start']:.1f}s")
        print(f"  IAT Mean: {row['iat_mean']:.2f} | Med: {row['iat_median']:.2f} | Std: {row['iat_std']:.2f} | Max: {row['max_iat']:.2f}")
        print(f"  CV: {row['iat_cv']:.2f}")
        print("-" * 40)

if __name__ == "__main__":
    main()
