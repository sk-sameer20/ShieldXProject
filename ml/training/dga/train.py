"""
training/dga/train.py — Train and save the DGA Random Forest detector.

Reads: data/processed/dga_features.csv
Saves: models/dga/dga_model.joblib
       models/dga/dga_model_metadata.json
       data/processed/dga_splits.csv
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, accuracy_score

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.dns.detector import DGADetector
from src.dns.features import DGA_FEATURE_NAMES

FEATURES_CSV = PROJECT_ROOT / "data" / "processed" / "dga_features.csv"
MODEL_DIR = PROJECT_ROOT / "models" / "dga"
MODEL_PATH = MODEL_DIR / "dga_model.joblib"
METADATA_PATH = MODEL_DIR / "dga_model_metadata.json"
SPLITS_CSV = PROJECT_ROOT / "data" / "processed" / "dga_splits.csv"

def evaluate_split(y_true, y_pred, df_split, split_name):
    print(f"\n  --- {split_name} Evaluation ---")
    
    cm = confusion_matrix(y_true, y_pred)
    # Binary classification: 0 is benign, 1 is malicious
    # cm:
    # [[TN, FP],
    #  [FN, TP]]
    
    if cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel()
    else:
        tn = fp = fn = tp = 0
        if len(np.unique(y_true)) == 1:
            if y_true[0] == 0:
                tn = cm[0,0]
            else:
                tp = cm[0,0]
                
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    acc = accuracy_score(y_true, y_pred)
    
    print(f"Confusion Matrix:\n[[{tn} (TN)  {fp} (FP)]\n [{fn} (FN)  {tp} (TP)]]")
    print(f"Accuracy:  {acc:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1 Score:  {f1:.4f}")
    print(f"FPR:       {fpr:.4f}")
    print(f"Benign False Positives: {fp}")
    print(f"Malicious False Negatives: {fn}")
    
    print("\nPer-Family Recall:")
    families = df_split[df_split['label'] == 1]['family'].unique()
    for fam in families:
        fam_idx = df_split['family'] == fam
        y_true_fam = y_true[fam_idx]
        y_pred_fam = y_pred[fam_idx]
        if len(y_true_fam) > 0:
            tp_fam = np.sum(y_pred_fam == 1)
            rec_fam = tp_fam / len(y_true_fam)
            print(f"  {fam}: {rec_fam*100:.1f}% ({tp_fam}/{len(y_true_fam)})")

def main() -> None:
    print("=" * 60)
    print("  DGA Detector — Training (OOD Baseline)")
    print("=" * 60)

    if not FEATURES_CSV.exists():
        print(f"  ERROR: {FEATURES_CSV} not found.")
        print("  Run: python training/dga/prepare_dataset.py first.")
        sys.exit(1)

    df = pd.read_csv(FEATURES_CSV)
    
    # ── 1. SPLIT DATASET ──────────────────────────────────────────────────
    # Benign
    df_benign = df[df["label"] == 0].sample(frac=1, random_state=42).reset_index(drop=True)
    df_train_benign = df_benign.iloc[:35000]
    df_val_benign = df_benign.iloc[35000:42500]
    df_test_benign = df_benign.iloc[42500:50000]

    # Malicious Train: qakbot (5000), corebot (40), ramdo (20)
    df_train_mal = df[df["family"].isin(["qakbot", "corebot", "ramdo"])]
    
    # Malicious Val: banjori (1000), dircrypt (30)
    df_val_mal = df[df["family"].isin(["banjori", "dircrypt"])]
    
    # Malicious Test: simda (1000), nymaim (128)
    df_test_mal = df[df["family"].isin(["simda", "nymaim"])]

    df_train = pd.concat([df_train_benign, df_train_mal]).reset_index(drop=True)
    df_val = pd.concat([df_val_benign, df_val_mal]).reset_index(drop=True)
    df_test = pd.concat([df_test_benign, df_test_mal]).reset_index(drop=True)

    df_train["split"] = "train"
    df_val["split"] = "validation"
    df_test["split"] = "test"
    
    df_splits = pd.concat([df_train, df_val, df_test]).reset_index(drop=True)
    df_splits[["domain", "label", "family", "split"]].to_csv(SPLITS_CSV, index=False)

    # ── 2. DATASET AUDIT ──────────────────────────────────────────────────
    print("\n=== DATASET AUDIT ===")
    print("Exact counts per split:")
    print(f"  Train:      Benign={len(df_train_benign)}, Malicious={len(df_train_mal)}, Total={len(df_train)}")
    print(f"  Validation: Benign={len(df_val_benign)}, Malicious={len(df_val_mal)}, Total={len(df_val)}")
    print(f"  Test:       Benign={len(df_test_benign)}, Malicious={len(df_test_mal)}, Total={len(df_test)}")
    
    print("\nFamily assignments across splits:")
    for split_name, df_s in [("Train", df_train), ("Validation", df_val), ("Test", df_test)]:
        print(f"  {split_name}: {dict(df_s[df_s['label']==1]['family'].value_counts())}")

    print("\nDuplicate checks:")
    total_dupes = df_splits["domain"].duplicated().sum()
    print(f"  Total duplicate domains in entire dataset: {total_dupes}")
    
    print("\nFeature NaN/Inf checks:")
    features_df = df_splits[DGA_FEATURE_NAMES]
    nans = features_df.isna().sum().sum()
    infs = np.isinf(features_df).sum().sum()
    print(f"  NaN values: {nans}")
    print(f"  Inf values: {infs}")

    print("\nConstant features:")
    constant_features = [f for f in DGA_FEATURE_NAMES if features_df[f].nunique() <= 1]
    print(f"  {constant_features if constant_features else 'None'}")

    print("\nHighly Correlated Features (>0.95):")
    corr_matrix = features_df.corr().abs()
    high_corr = []
    for i in range(len(DGA_FEATURE_NAMES)):
        for j in range(i+1, len(DGA_FEATURE_NAMES)):
            if corr_matrix.iloc[i, j] > 0.95:
                high_corr.append(f"{DGA_FEATURE_NAMES[i]} <-> {DGA_FEATURE_NAMES[j]}: {corr_matrix.iloc[i, j]:.4f}")
    for c in high_corr:
        print(f"  {c}")

    print("\nCross-split family leakage check:")
    train_fams = set(df_train_mal["family"].unique())
    val_fams = set(df_val_mal["family"].unique())
    test_fams = set(df_test_mal["family"].unique())
    overlap = train_fams.intersection(val_fams) | train_fams.intersection(test_fams) | val_fams.intersection(test_fams)
    print(f"  Families overlapping splits: {overlap if overlap else 'None'}")
    
    # ── 3. TRAIN DGA-v1 ───────────────────────────────────────────────────
    print("\n=== TRAINING ===")
    X_train = df_train[DGA_FEATURE_NAMES].fillna(0.0).values
    y_train = df_train["label"].values.astype(int)
    
    X_val = df_val[DGA_FEATURE_NAMES].fillna(0.0).values
    y_val = df_val["label"].values.astype(int)
    
    X_test = df_test[DGA_FEATURE_NAMES].fillna(0.0).values
    y_test = df_test["label"].values.astype(int)
    
    detector = DGADetector()
    print("Fitting model... (class_weight='balanced')")
    detector.fit(X_train, y_train)

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    detector.save(str(MODEL_PATH))
    print(f"Model saved -> {MODEL_PATH}")

    # ── 4. EVALUATION ─────────────────────────────────────────────────────
    print("\n=== EVALUATION ===")
    
    # Validation Evaluation
    y_val_pred = detector._model.predict(X_val)
    evaluate_split(y_val, y_val_pred, df_val, "VALIDATION")
    
    # Test Evaluation
    y_test_pred = detector._model.predict(X_test)
    evaluate_split(y_test, y_test_pred, df_test, "FINAL UNSEEN-FAMILY TEST")

    # Save metadata
    metadata = {
        "model_name": "DGA Domain Detector (OOD Baseline)",
        "model_type": "Random Forest (supervised, lexical features)",
        "model_version": DGADetector.MODEL_VERSION,
        "feature_version": "1.0",
        "features": DGA_FEATURE_NAMES,
        "training_samples": int(len(X_train)),
        "validation_samples": int(len(X_val)),
        "test_samples": int(len(X_test)),
        "training_data": "tranco + baderj",
        "split_method": "Strict family-level OOD split",
        "class_weight": "balanced"
    }
    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print("\n" + "=" * 60)

if __name__ == "__main__":
    main()
