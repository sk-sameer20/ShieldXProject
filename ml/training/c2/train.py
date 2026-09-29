"""
training/c2/train.py — Train and save the C2 IsolationForest detector.

Reads: data/processed/c2_features.csv
Saves: models/c2/c2_model.joblib
       models/c2/c2_model_metadata.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.c2.detector import C2Detector
from src.c2.features import C2_FEATURE_NAMES

FEATURES_CSV = PROJECT_ROOT / "data" / "processed" / "c2_features.csv"
MODEL_DIR = PROJECT_ROOT / "models" / "c2"
MODEL_PATH = MODEL_DIR / "c2_model.joblib"
METADATA_PATH = MODEL_DIR / "c2_model_metadata.json"


def main() -> None:
    print("=" * 60)
    print("  C2 Detector — Training")
    print("=" * 60)

    if not FEATURES_CSV.exists():
        print(f"  ERROR: {FEATURES_CSV} not found.")
        print("  Run: python training/c2/prepare_dataset.py first.")
        sys.exit(1)

    df = pd.read_csv(FEATURES_CSV)
    print(f"  Loaded {len(df)} rows from {FEATURES_CSV.name}")
    print(f"  Label distribution:\n{df['label'].value_counts()}\n")

    df_benign = df[df["label"] == "benign"]
    df_c2 = df[df["label"] == "c2"]
    
    if len(df_benign) < 10:
        print("  ERROR: Very few benign samples for training.")
        sys.exit(1)

    from sklearn.model_selection import GroupShuffleSplit
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_idx, test_idx = next(gss.split(df_benign, groups=df_benign['src_ip']))
    
    train_benign = df_benign.iloc[train_idx]
    test_benign = df_benign.iloc[test_idx]
    
    X_train = train_benign[C2_FEATURE_NAMES].fillna(0.0).values
    
    print(f"  Training IsolationForest on {len(X_train)} benign samples...")

    import time
    start_t = time.time()
    detector = C2Detector()
    detector.fit(X_train)
    train_t = time.time() - start_t

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    detector.save(str(MODEL_PATH))
    print(f"\n  Model saved -> {MODEL_PATH}")
    
    # Extract params
    print("\n  [Training Parameters]")
    print(f"  - Samples: {len(X_train)}")
    print(f"  - Features: {len(C2_FEATURE_NAMES)}")
    print(f"  - Contamination: {detector._model.contamination}")
    print(f"  - Random Seed: {detector._model.random_state}")
    print(f"  - Feature Names: {C2_FEATURE_NAMES}")
    print(f"  - Training Time: {train_t:.3f} seconds")
    print(f"  - Model Version: {detector.MODEL_VERSION}")

    # ── Save metadata ─────────────────────────────────────────────────────
    metadata = {
        "model_name": "C2 Beaconing Detector",
        "model_type": "IsolationForest + heuristic periodicity/repetition scorer",
        "model_version": C2Detector.MODEL_VERSION,
        "feature_version": "1.0",
        "features": C2_FEATURE_NAMES,
        "training_samples": int(len(X_train)),
        "training_data": "CTU-13 Benign Temporal Windows",
        "confidence_note": (
            "confidence is a weighted combination of: anomaly_score (0.35), "
            "periodicity_score (0.30), repetition_score (0.20), iat_regularity (0.15). "
            "It is NOT a calibrated probability."
        ),
    }

    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
        
    print("\n  [Evaluation on Held-Out Test Set]")
    
    df_test = pd.concat([test_benign, df_c2])
    
    y_true = (df_test["label"] == "c2").astype(int).values
    
    preds = []
    anomaly_scores = []
    decision_scores = []
    
    for _, row in df_test.iterrows():
        feat_dict = {f: row[f] if pd.notnull(row[f]) else 0.0 for f in C2_FEATURE_NAMES}
        alert = detector.predict(feat_dict)
        preds.append(1 if alert.detected else 0)
        anomaly_scores.append(alert.technical_evidence.get('anomaly_score', 0.0))
        decision_scores.append(alert.technical_evidence.get('decision_function_score', 0.0))
        
    df_test["pred"] = preds
    df_test["anomaly_score"] = anomaly_scores
    df_test["decision_function_score"] = decision_scores
    
    from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score
    
    cm = confusion_matrix(y_true, preds)
    tn, fp, fn, tp = cm.ravel()
    
    print("  Confusion Matrix:")
    print(f"    TN: {tn:<5} | FP: {fp:<5}")
    print(f"    FN: {fn:<5} | TP: {tp:<5}")
    
    prec = precision_score(y_true, preds, zero_division=0)
    rec = recall_score(y_true, preds, zero_division=0)
    f1 = f1_score(y_true, preds, zero_division=0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    
    print("\n  Metrics (C2-v2 Original Weights: 0.35, 0.30, 0.20, 0.15):")
    print(f"  - Precision: {prec:.4f}")
    print(f"  - Recall (Detection Rate): {rec:.4f}")
    print(f"  - F1 Score:  {f1:.4f}")
    print(f"  - FPR:       {fpr:.4f}")

    # Specific FP breakdown for host 164
    fp_164 = df_test[(df_test["label"] == "benign") & (df_test["src_ip"] == "147.32.84.164") & (df_test["pred"] == 1)]
    total_164 = len(df_test[(df_test["label"] == "benign") & (df_test["src_ip"] == "147.32.84.164")])
    print(f"\n  - Host 147.32.84.164 False Positives: {len(fp_164)} / {total_164}")
    
    print("\n  Raw decision_function Distributions (negative = anomaly):")
    benign_dec = df_test[df_test["label"] == "benign"]["decision_function_score"]
    c2_dec = df_test[df_test["label"] == "c2"]["decision_function_score"]
    print(f"  - Benign -> Min: {benign_dec.min():.4f}, Median: {benign_dec.median():.4f}, Max: {benign_dec.max():.4f}, Mean: {benign_dec.mean():.4f}")
    print(f"  - C2     -> Min: {c2_dec.min():.4f}, Median: {c2_dec.median():.4f}, Max: {c2_dec.max():.4f}, Mean: {c2_dec.mean():.4f}")

    print("\n  Anomaly Score Distributions (Continuous [0,1]):")
    benign_scores = df_test[df_test["label"] == "benign"]["anomaly_score"]
    c2_scores = df_test[df_test["label"] == "c2"]["anomaly_score"]
    
    print(f"  - Benign -> Min: {benign_scores.min():.4f}, Median: {benign_scores.median():.4f}, Max: {benign_scores.max():.4f}, Mean: {benign_scores.mean():.4f}")
    print(f"  - C2     -> Min: {c2_scores.min():.4f}, Median: {c2_scores.median():.4f}, Max: {c2_scores.max():.4f}, Mean: {c2_scores.mean():.4f}")
    
    print("\n  Results broken down by C2 Host:")
    for ip, group in df_test[df_test["label"] == "c2"].groupby("src_ip"):
        host_tp = int(group["pred"].sum())
        total = len(group)
        dr = host_tp / total
        med_score = group["anomaly_score"].median()
    print("=" * 60)

    # ── Second Evaluation: Candidate 1 Weights ─────────────────────────────
    print("\n  [Evaluation on Held-Out Test Set - Candidate 1 Weights]")
    print("  Weights: Anomaly: 0.70, Periodicity: 0.10, Repetition: 0.10, IAT: 0.10")
    
    # Temporarily override detector weights
    detector._weight_anomaly = 0.70
    detector._weight_periodicity = 0.10
    detector._weight_repetition = 0.10
    detector._weight_iat = 0.10
    
    preds_cand1 = []
    
    for _, row in df_test.iterrows():
        feat_dict = {f: row[f] if pd.notnull(row[f]) else 0.0 for f in C2_FEATURE_NAMES}
        alert = detector.predict(feat_dict)
        preds_cand1.append(1 if alert.detected else 0)
        
    df_test["pred_cand1"] = preds_cand1
    
    cm_c1 = confusion_matrix(y_true, preds_cand1)
    tn_c1, fp_c1, fn_c1, tp_c1 = cm_c1.ravel()
    
    print("\n  Confusion Matrix (Candidate 1):")
    print(f"    TN: {tn_c1:<5} | FP: {fp_c1:<5}")
    print(f"    FN: {fn_c1:<5} | TP: {tp_c1:<5}")
    
    prec_c1 = precision_score(y_true, preds_cand1, zero_division=0)
    rec_c1 = recall_score(y_true, preds_cand1, zero_division=0)
    f1_c1 = f1_score(y_true, preds_cand1, zero_division=0)
    fpr_c1 = fp_c1 / (fp_c1 + tn_c1) if (fp_c1 + tn_c1) > 0 else 0.0
    
    print("\n  Metrics (Candidate 1):")
    print(f"  - Precision: {prec_c1:.4f}")
    print(f"  - Recall:    {rec_c1:.4f}")
    print(f"  - F1 Score:  {f1_c1:.4f}")
    print(f"  - FPR:       {fpr_c1:.4f}")
    
    fp_164_c1 = df_test[(df_test["label"] == "benign") & (df_test["src_ip"] == "147.32.84.164") & (df_test["pred_cand1"] == 1)]
    print(f"\n  - Host 147.32.84.164 False Positives (Candidate 1): {len(fp_164_c1)} / {total_164}")

    print("=" * 60)


if __name__ == "__main__":
    main()
