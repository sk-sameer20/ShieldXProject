import pandas as pd
import numpy as np
from pathlib import Path
import sys
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score
from sklearn.model_selection import GroupShuffleSplit

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
from src.c2.detector import C2Detector
from src.c2.features import C2_FEATURE_NAMES

def main():
    df = pd.read_csv(PROJECT_ROOT / "data" / "processed" / "c2_features.csv")
    df_benign = df[df["label"] == "benign"]
    df_c2 = df[df["label"] == "c2"]

    # Recreate the exact train/test split for Benign
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_idx, test_idx = next(gss.split(df_benign, groups=df_benign['src_ip']))
    train_benign = df_benign.iloc[train_idx]
    test_benign = df_benign.iloc[test_idx]

    # The UNTOUCHED final test set
    df_test_final = pd.concat([test_benign, df_c2])

    # Validation split
    gss_c2 = GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=99)
    val_c2_idx, _ = next(gss_c2.split(df_c2, groups=df_c2['src_ip']))
    val_c2 = df_c2.iloc[val_c2_idx]

    gss_val = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=99)
    _, val_benign_idx = next(gss_val.split(train_benign, groups=train_benign['src_ip']))
    val_benign = train_benign.iloc[val_benign_idx]

    df_val = pd.concat([val_benign, val_c2])
    
    detector = C2Detector.load(str(PROJECT_ROOT / "models" / "c2" / "c2_model.joblib"))

    # Weights for Candidate 1
    wa, wp, wr, wi = 0.70, 0.10, 0.10, 0.10
    
    def process_dataset(dataset):
        records = []
        for _, row in dataset.iterrows():
            feat = {k: row[k] if pd.notnull(row[k]) else 0.0 for k in C2_FEATURE_NAMES}
            label = 1 if row["label"] == "c2" else 0
            conn = feat.get("connection_count", 0)
            
            if conn < 3:
                conf = 0.0
                anom = 0.0
            else:
                vec = np.array([[feat.get(k, 0.0) for k in C2_FEATURE_NAMES]])
                anom = -float(detector._model.score_samples(vec)[0])
                per = feat.get("periodicity_score", 0.0)
                rep = detector._compute_repetition_score(feat)
                iat_cv = feat.get("iat_cv", 1.0)
                iat_reg = max(0.0, 1.0 - min(iat_cv, 2.0) / 2.0)
                conf = wa * anom + wp * per + wr * rep + wi * iat_reg
                
            records.append({
                "src_ip": row["src_ip"],
                "scenario": row["scenario"],
                "label": label,
                "conn": conn,
                "anom": anom,
                "conf": conf
            })
        return pd.DataFrame(records)

    print("Processing Validation Set...")
    val_df = process_dataset(df_val)
    
    print("Processing Test Set...")
    test_df = process_dataset(df_test_final)
    
    thresholds = [0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60, 0.65, 0.70]
    
    def print_sweep(df_records, name):
        print(f"\n================ {name} SET SWEEP ================")
        print(f"{'Thresh':<8} | {'TP':<4} | {'TN':<4} | {'FP':<4} | {'FN':<4} | {'Prec':<7} | {'Recall':<7} | {'F1':<7} | {'FPR':<7}")
        print("-" * 75)
        for t in thresholds:
            preds = (df_records["conf"] >= t).astype(int)
            cm = confusion_matrix(df_records["label"], preds, labels=[0, 1])
            tn, fp, fn, tp = cm.ravel()
            prec = precision_score(df_records["label"], preds, zero_division=0)
            rec = recall_score(df_records["label"], preds, zero_division=0)
            f1 = f1_score(df_records["label"], preds, zero_division=0)
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            
            print(f"{t:<8.2f} | {tp:<4} | {tn:<4} | {fp:<4} | {fn:<4} | {prec:<7.4f} | {rec:<7.4f} | {f1:<7.4f} | {fpr:<7.4f}")
            
    print_sweep(val_df, "VALIDATION")
    print_sweep(test_df, "FINAL TEST")

    # False Positives Breakdown on Final Test at 0.45
    print("\n================ FALSE POSITIVES (Test Set, Thresh=0.45) ================")
    preds = (test_df["conf"] >= 0.45).astype(int)
    fps = test_df[(test_df["label"] == 0) & (preds == 1)]
    print(f"Total FPs: {len(fps)}")
    
    summary = fps.groupby(["src_ip", "scenario"]).agg(
        count=("src_ip", "count"),
        median_conn=("conn", "median"),
        median_anom=("anom", "median"),
        median_conf=("conf", "median")
    ).reset_index().sort_values(by="count", ascending=False)
    
    for _, r in summary.iterrows():
        print(f"IP: {r['src_ip']:<15} | Scenario: {r['scenario']:<25} | "
              f"Count: {r['count']:<3} | Med_Conn: {r['median_conn']:<5.1f} | "
              f"Med_Anom: {r['median_anom']:<6.4f} | Med_Conf: {r['median_conf']:<6.4f}")

if __name__ == "__main__":
    main()
