"""
training/c2/evaluate.py — Evaluate the C2 detector on labeled samples.

Loads the trained model and evaluates against all labeled data.
Reports Precision, Recall, F1, FPR, and confusion matrix.
Never reports only accuracy.

NOTE: With synthetic data the numbers are illustrative only.
Document clearly when running on real datasets.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.c2.detector import C2Detector
from src.c2.features import C2_FEATURE_NAMES

FEATURES_CSV = PROJECT_ROOT / "data" / "processed" / "c2_features.csv"
MODEL_PATH = PROJECT_ROOT / "models" / "c2" / "c2_model.joblib"
OUTPUT_DIR = PROJECT_ROOT / "outputs"


def main() -> None:
    print("=" * 60)
    print("  C2 Detector — Evaluation")
    print("=" * 60)

    if not MODEL_PATH.exists():
        print(f"  ERROR: Model not found at {MODEL_PATH}")
        print("  Run: python training/c2/train.py first.")
        sys.exit(1)

    if not FEATURES_CSV.exists():
        print(f"  ERROR: Features CSV not found at {FEATURES_CSV}")
        print("  Run: python training/c2/prepare_dataset.py first.")
        sys.exit(1)

    df = pd.read_csv(FEATURES_CSV)
    X = df[C2_FEATURE_NAMES].fillna(0.0).values
    y_true = (df["label"] == "c2").astype(int).values

    detector = C2Detector.load(str(MODEL_PATH))

    # ── Predict ───────────────────────────────────────────────────────────
    y_pred = []
    confidences = []
    for i, row in enumerate(X):
        features = dict(zip(C2_FEATURE_NAMES, row))
        features["connection_count"] = max(features.get("connection_count", 0), 3.0)
        alert = detector.predict(features)
        y_pred.append(1 if alert.detected else 0)
        confidences.append(alert.confidence)

    y_pred = np.array(y_pred)
    confidences = np.array(confidences)

    # ── Metrics ───────────────────────────────────────────────────────────
    tp = int(np.sum((y_pred == 1) & (y_true == 1)))
    fp = int(np.sum((y_pred == 1) & (y_true == 0)))
    fn = int(np.sum((y_pred == 0) & (y_true == 1)))
    tn = int(np.sum((y_pred == 0) & (y_true == 0)))

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print(f"\n  Samples evaluated: {len(df)}")
    print(f"  Label distribution: {dict(zip(*np.unique(df['label'], return_counts=True)))}")
    print()
    print(f"  Confusion Matrix:")
    print(f"    TP={tp}  FP={fp}")
    print(f"    FN={fn}  TN={tn}")
    print()
    print(f"  Precision:           {precision:.4f}")
    print(f"  Recall (TPR):        {recall:.4f}")
    print(f"  F1 Score:            {f1:.4f}")
    print(f"  False Positive Rate: {fpr:.4f}")
    print()

    if len(df) < 20:
        print("  ⚠  WARNING: Evaluation on SYNTHETIC data only.")
        print("     These numbers are NOT representative of real performance.")
        print("     Replace with a real labeled dataset before reporting results.")

    # ── Save results ──────────────────────────────────────────────────────
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    results = {
        "model": str(MODEL_PATH.name),
        "samples": len(df),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
        "data_note": "SYNTHETIC — replace with real dataset",
    }
    import json
    with open(OUTPUT_DIR / "c2_evaluation.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"  Results saved → {OUTPUT_DIR / 'c2_evaluation.json'}")
    print("=" * 60)


if __name__ == "__main__":
    main()
