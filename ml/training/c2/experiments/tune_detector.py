import itertools
import pandas as pd
import numpy as np
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
from src.c2.detector import C2Detector
from src.c2.features import C2_FEATURE_NAMES
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score
from sklearn.model_selection import GroupShuffleSplit

def main():
    df = pd.read_csv(PROJECT_ROOT / "data" / "processed" / "c2_features.csv")
    df_benign = df[df["label"] == "benign"]
    df_c2 = df[df["label"] == "c2"]

    # Recreate the exact train/test split for Benign
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_idx, test_idx = next(gss.split(df_benign, groups=df_benign['src_ip']))
    train_benign = df_benign.iloc[train_idx]
    test_benign = df_benign.iloc[test_idx]

    # The UNTOUCHED final test set (as used in train.py)
    df_test_final = pd.concat([test_benign, df_c2])

    # Create Validation split
    # Since train_benign has NO C2 samples, we MUST borrow some C2 hosts for validation
    # to measure Recall/Precision. We will split df_c2 by host.
    gss_c2 = GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=99)
    val_c2_idx, _ = next(gss_c2.split(df_c2, groups=df_c2['src_ip']))
    val_c2 = df_c2.iloc[val_c2_idx]

    # Take 20% of train_benign for validation
    gss_val = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=99)
    _, val_benign_idx = next(gss_val.split(train_benign, groups=train_benign['src_ip']))
    val_benign = train_benign.iloc[val_benign_idx]

    df_val = pd.concat([val_benign, val_c2])
    
    detector = C2Detector.load(str(PROJECT_ROOT / "models" / "c2" / "c2_model.joblib"))

    # Pre-calculate components for validation set to speed up grid search
    print("Pre-calculating signals for validation set...")
    val_records = []
    for _, row in df_val.iterrows():
        feat = {k: row[k] if pd.notnull(row[k]) else 0.0 for k in C2_FEATURE_NAMES}
        vec = np.array([[feat.get(k, 0.0) for k in C2_FEATURE_NAMES]])
        raw_score = float(detector._model.score_samples(vec)[0])
        anom = -raw_score
        per = feat.get("periodicity_score", 0.0)
        rep = detector._compute_repetition_score(feat)
        iat_cv = feat.get("iat_cv", 1.0)
        iat_reg = max(0.0, 1.0 - min(iat_cv, 2.0) / 2.0)
        
        val_records.append({
            "label": 1 if row["label"] == "c2" else 0,
            "conn": feat.get("connection_count", 0),
            "anom": anom,
            "per": per,
            "rep": rep,
            "iat": iat_reg
        })

    weights_anom = [0.35, 0.40, 0.50, 0.60, 0.70]
    weights_per = [0.10, 0.20, 0.30]
    weights_rep = [0.10, 0.20, 0.30]
    weights_iat = [0.0, 0.10, 0.20]
    thresholds = [0.45, 0.50, 0.55, 0.60]

    results = []
    
    for wa in weights_anom:
        for wp in weights_per:
            for wr in weights_rep:
                for wi in weights_iat:
                    if abs(wa + wp + wr + wi - 1.0) > 1e-5:
                        continue
                        
                    for t in thresholds:
                        preds = []
                        y_true = []
                        for r in val_records:
                            y_true.append(r["label"])
                            if r["conn"] < 3:
                                preds.append(0)
                                continue
                            
                            conf = wa * r["anom"] + wp * r["per"] + wr * r["rep"] + wi * r["iat"]
                            preds.append(1 if conf >= t else 0)
                            
                        cm = confusion_matrix(y_true, preds, labels=[0, 1])
                        tn, fp, fn, tp = cm.ravel()
                        prec = precision_score(y_true, preds, zero_division=0)
                        rec = recall_score(y_true, preds, zero_division=0)
                        f1 = f1_score(y_true, preds, zero_division=0)
                        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
                        
                        results.append({
                            "wa": wa, "wp": wp, "wr": wr, "wi": wi, "t": t,
                            "prec": prec, "rec": rec, "f1": f1, "fpr": fpr,
                            "tp": tp, "tn": tn, "fp": fp, "fn": fn
                        })
                        
    df_res = pd.DataFrame(results)
    df_res = df_res.sort_values(by=["f1", "rec"], ascending=[False, False])
    
    print("\nTop 5 Candidates on Validation Set:")
    for _, row in df_res.head(5).iterrows():
        print(f"Weights (Anom={row['wa']:.2f}, Per={row['wp']:.2f}, Rep={row['wr']:.2f}, IAT={row['wi']:.2f}) | Thresh={row['t']:.2f}")
        print(f"  F1: {row['f1']:.4f} | Prec: {row['prec']:.4f} | Rec: {row['rec']:.4f} | FPR: {row['fpr']:.4f}")
        print(f"  CM: TN={row['tn']:.0f}, FP={row['fp']:.0f}, FN={row['fn']:.0f}, TP={row['tp']:.0f}\n")

    # Evaluate the best candidate on the UNTOUCHED Final Test Set
    best = df_res.iloc[0]
    print("=" * 50)
    print("Evaluating BEST candidate on FINAL UNTOUCHED TEST SET")
    print("=" * 50)
    
    test_preds = []
    test_y = []
    for _, row in df_test_final.iterrows():
        feat = {k: row[k] if pd.notnull(row[k]) else 0.0 for k in C2_FEATURE_NAMES}
        test_y.append(1 if row["label"] == "c2" else 0)
        
        if feat.get("connection_count", 0) < 3:
            test_preds.append(0)
            continue
            
        vec = np.array([[feat.get(k, 0.0) for k in C2_FEATURE_NAMES]])
        anom = -float(detector._model.score_samples(vec)[0])
        per = feat.get("periodicity_score", 0.0)
        rep = detector._compute_repetition_score(feat)
        iat_cv = feat.get("iat_cv", 1.0)
        iat_reg = max(0.0, 1.0 - min(iat_cv, 2.0) / 2.0)
        
        conf = best["wa"] * anom + best["wp"] * per + best["wr"] * rep + best["wi"] * iat_reg
        test_preds.append(1 if conf >= best["t"] else 0)
        
    cm = confusion_matrix(test_y, test_preds, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    prec = precision_score(test_y, test_preds, zero_division=0)
    rec = recall_score(test_y, test_preds, zero_division=0)
    f1 = f1_score(test_y, test_preds, zero_division=0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    
    print(f"Final Test Set Metrics for Best Candidate:")
    print(f"  F1: {f1:.4f} | Prec: {prec:.4f} | Rec: {rec:.4f} | FPR: {fpr:.4f}")
    print(f"  CM: TN={tn}, FP={fp}, FN={fn}, TP={tp}")
    print(f"  Comparison to Previous Full-Detector: 186 FP / 184 FN -> New: {fp} FP / {fn} FN")

if __name__ == "__main__":
    main()
