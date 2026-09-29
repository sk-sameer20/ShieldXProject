import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent

SCENARIOS = {
    "capture20110811.binetflow": "2",
    "capture20110812.binetflow": "3",
    "capture20110815.binetflow": "4",
    "capture20110817.binetflow": "9",
}

TEST_HOSTS = [
    "147.32.84.164", # Benign
    "147.32.84.170", # Benign
    "147.32.84.134", # Benign
    "147.32.84.165", # C2
    "147.32.84.191", # C2
    "147.32.84.192", # C2
]

def main():
    raw_dir = PROJECT_ROOT / "data" / "raw" / "ctu-13"
    
    # 1. Load Raw Connections to build timelines
    all_records = []
    
    for filename in SCENARIOS.keys():
        filepath = raw_dir / filename
        if not filepath.exists():
            continue
            
        print(f"Loading {filename}...")
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
        
        # Only keep test hosts to save time and memory
        df_filtered = df_filtered[df_filtered["src_ip"].isin(TEST_HOSTS)]
        
        all_records.append(df_filtered[["timestamp", "src_ip"]])
        
    if not all_records:
        return
        
    full_timeline = pd.concat(all_records, ignore_index=True)
    full_timeline.sort_values(by=["src_ip", "timestamp"], inplace=True)
    
    # Pre-group timelines for fast lookup
    host_timelines = {}
    for src_ip, group in full_timeline.groupby("src_ip"):
        host_timelines[src_ip] = group["timestamp"].values

    # 2. Load the evaluation dataset
    csv_path = PROJECT_ROOT / "data" / "processed" / "c2_features.csv"
    df_eval = pd.read_csv(csv_path)
    df_test = df_eval[df_eval["src_ip"].isin(TEST_HOSTS)].copy()
    
    print(f"\nEvaluating on {len(df_test)} test windows...")
    
    # 3. Calculate 300s rolling history for each window
    rolling_counts = []
    rolling_cvs = []
    
    for _, row in df_test.iterrows():
        src_ip = row["src_ip"]
        window_end = row["window_end"]
        
        if src_ip not in host_timelines:
            rolling_counts.append(0)
            rolling_cvs.append(100.0) # High CV means not periodic
            continue
            
        ts_array = host_timelines[src_ip]
        
        # Extract connections in [window_end - 300, window_end]
        mask = (ts_array > window_end - 300) & (ts_array <= window_end)
        conns = ts_array[mask]
        
        count = len(conns)
        rolling_counts.append(count)
        
        if count >= 3:
            iats = np.diff(conns)
            mean = np.mean(iats)
            std = np.std(iats)
            cv = std / mean if mean > 0 else 100.0
            rolling_cvs.append(cv)
        else:
            rolling_cvs.append(100.0)
            
    df_test["rolling_count"] = rolling_counts
    df_test["rolling_cv"] = rolling_cvs
    
    y_true = (df_test["label"] == "c2").astype(int)
    
    counts_to_test = [3, 5, 7, 10]
    cvs_to_test = [0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 1.1]
    
    results = []
    
    for min_c in counts_to_test:
        for max_cv in cvs_to_test:
            y_pred = ((df_test["rolling_count"] >= min_c) & (df_test["rolling_cv"] <= max_cv)).astype(int)
            
            tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
            precision = precision_score(y_true, y_pred, zero_division=0)
            recall = recall_score(y_true, y_pred, zero_division=0)
            f1 = f1_score(y_true, y_pred, zero_division=0)
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
            
            results.append({
                "min_count": min_c,
                "max_cv": max_cv,
                "TP": tp, "TN": tn, "FP": fp, "FN": fn,
                "Precision": precision,
                "Recall": recall,
                "F1": f1,
                "FPR": fpr
            })
            
    res_df = pd.DataFrame(results)
    
    print("\n=== TEMPORAL RULE EVALUATION ===")
    print(res_df.to_string(index=False))
    
    # 4. Detailed output for the best rule (e.g. min_c=5, max_cv=1.0)
    best_c = 5
    best_cv = 1.0
    print(f"\n=== DETAILED ANALYSIS (Count >= {best_c}, CV <= {best_cv}) ===")
    
    y_pred = ((df_test["rolling_count"] >= best_c) & (df_test["rolling_cv"] <= best_cv)).astype(int)
    df_test["pred"] = y_pred
    
    for src_ip, group in df_test.groupby("src_ip"):
        is_c2 = group["label"].iloc[0] == "c2"
        label_str = "C2" if is_c2 else "Benign"
        
        if is_c2:
            tp = group["pred"].sum()
            fn = len(group) - tp
            print(f"Host {src_ip} ({label_str}): {tp} TP / {fn} FN (Detection Rate: {tp/len(group)*100:.1f}%)")
        else:
            fp = group["pred"].sum()
            print(f"Host {src_ip} ({label_str}): {fp} FP out of {len(group)} windows (FPR: {fp/len(group)*100:.1f}%)")
            

if __name__ == "__main__":
    main()
