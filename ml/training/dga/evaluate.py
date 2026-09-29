"""
training/dga/evaluate.py — Evaluate DGA + DNS Tunnel detectors on labeled samples.

Reports Precision, Recall, F1, FPR, and confusion matrix.
Never reports only accuracy.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.dns.detector import DGADetector
from src.dns.features import DGA_FEATURE_NAMES

FEATURES_CSV = PROJECT_ROOT / "data" / "processed" / "dga_features.csv"
MODEL_PATH = PROJECT_ROOT / "models" / "dga" / "dga_model.joblib"
OUTPUT_DIR = PROJECT_ROOT / "outputs"


def main() -> None:
    print("=" * 60)
    print("  DGA Detector — Evaluation")
    print("=" * 60)

    if not MODEL_PATH.exists():
        print(f"  ERROR: Model not found. Run: python training/dga/train.py first.")
        sys.exit(1)

    if not FEATURES_CSV.exists():
        print(f"  ERROR: Features CSV not found. Run: python training/dga/prepare_dataset.py first.")
        sys.exit(1)

    df = pd.read_csv(FEATURES_CSV)
    X = df[DGA_FEATURE_NAMES].fillna(0.0).values
    y_true = df["label"].values.astype(int)

    detector = DGADetector.load(str(MODEL_PATH))
    y_pred = detector._model.predict(X)

    tp = int(np.sum((y_pred == 1) & (y_true == 1)))
    fp = int(np.sum((y_pred == 1) & (y_true == 0)))
    fn = int(np.sum((y_pred == 0) & (y_true == 1)))
    tn = int(np.sum((y_pred == 0) & (y_true == 0)))

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print(f"\n  Samples: {len(df)}")
    print(f"  Labels: {dict(zip(*np.unique(df['label'], return_counts=True)))}")
    print(f"\n  Confusion Matrix:")
    print(f"    TP={tp}  FP={fp}")
    print(f"    FN={fn}  TN={tn}")
    print(f"\n  Precision:           {precision:.4f}")
    print(f"  Recall (TPR):        {recall:.4f}")
    print(f"  F1 Score:            {f1:.4f}")
    print(f"  False Positive Rate: {fpr:.4f}")

    if len(df) < 50:
        print("\n  ⚠  WARNING: SYNTHETIC DATA — numbers are not representative.")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    results = {
        "model": "dga_model.joblib",
        "samples": len(df),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
        "data_note": "SYNTHETIC — replace with real dataset",
    }
    with open(OUTPUT_DIR / "dga_evaluation.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n  Results saved → {OUTPUT_DIR / 'dga_evaluation.json'}")
    print("=" * 60)


if __name__ == "__main__":
    main()
