import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

from src.c2.detector import C2Detector
from src.c2.features import C2_FEATURE_NAMES

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

def print_metrics(name, y_true, y_pred, df_test):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    
    print(f"\n=====================================")
    print(f"=== {name} ===")
    print(f"=====================================")
    print(f"TP: {tp} | TN: {tn} | FP: {fp} | FN: {fn}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1 Score:  {f1:.4f}")
    print(f"FPR:       {fpr:.4f}")
    print(f"Total FP:  {fp}")
    
    df_test["pred"] = y_pred
    host_164_fp = df_test[(df_test["src_ip"] == "147.32.84.164") & (df_test["pred"] == 1)].shape[0]
    print(f"Host 164 FPs: {host_164_fp}")
    
    print("\nPer-Host Breakdown:")
    for src_ip, group in df_test.groupby("src_ip"):
        is_c2 = group["label"].iloc[0] == "c2"
        if is_c2:
            htp = group["pred"].sum()
            print(f"  [C2] {src_ip}: {htp} TP / {len(group)} (Detection Rate: {htp/len(group)*100:.1f}%)")
        else:
            hfp = group["pred"].sum()
            print(f"  [Benign] {src_ip}: {hfp} FP / {len(group)} (FPR: {hfp/len(group)*100:.1f}%)")


def main():
    # 1. Temporal Timelines
    raw_dir = PROJECT_ROOT / "data" / "raw" / "ctu-13"
    all_records = []
    
    for filename in SCENARIOS.keys():
        filepath = raw_dir / filename
        if not filepath.exists():
            continue
            
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
        df_filtered = df_filtered[df_filtered["src_ip"].isin(TEST_HOSTS)]
        all_records.append(df_filtered[["timestamp", "src_ip"]])
        
    full_timeline = pd.concat(all_records, ignore_index=True)
    full_timeline.sort_values(by=["src_ip", "timestamp"], inplace=True)
    
    host_timelines = {}
    for src_ip, group in full_timeline.groupby("src_ip"):
        host_timelines[src_ip] = group["timestamp"].values

    # 2. Evaluation dataset
    csv_path = PROJECT_ROOT / "data" / "processed" / "c2_features.csv"
    df_eval = pd.read_csv(csv_path)
    df_test = df_eval[df_eval["src_ip"].isin(TEST_HOSTS)].copy()
    
    # 3. Temporal predictions
    rolling_counts = []
    rolling_cvs = []
    
    for _, row in df_test.iterrows():
        src_ip = row["src_ip"]
        window_end = row["window_end"]
        
        if src_ip not in host_timelines:
            rolling_counts.append(0)
            rolling_cvs.append(100.0)
            continue
            
        ts_array = host_timelines[src_ip]
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
    temporal_pred = ((df_test["rolling_count"] >= 7) & (df_test["rolling_cv"] <= 1.0)).astype(int)
    
    # 4. Isolation Forest predictions
    detector = C2Detector.load(str(PROJECT_ROOT / "models" / "c2" / "c2_model.joblib"))
    detector._weight_anomaly = 0.70
    detector._weight_periodicity = 0.10
    detector._weight_repetition = 0.10
    detector._weight_iat = 0.10
    
    if_preds = []
    for _, row in df_test.iterrows():
        features = {k: row[k] for k in C2_FEATURE_NAMES if k in row}
        alert = detector.predict(features, src_ip=row["src_ip"])
        if_preds.append(1 if alert.detected else 0)
        
    if_pred = np.array(if_preds)
    
    y_true = (df_test["label"] == "c2").astype(int)
    
    # 5. Evaluate combinations
    and_pred = (temporal_pred & if_pred).astype(int)
    or_pred = (temporal_pred | if_pred).astype(int)
    
    print_metrics("Isolation Forest AND Temporal", y_true, and_pred, df_test.copy())
    print_metrics("Isolation Forest OR Temporal", y_true, or_pred, df_test.copy())
    print_metrics("Temporal alone (baseline)", y_true, temporal_pred, df_test.copy())
    print_metrics("Isolation Forest alone (baseline)", y_true, if_pred, df_test.copy())
    
if __name__ == "__main__":
    main()
