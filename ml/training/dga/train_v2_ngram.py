"""
training/dga/train_v2_ngram.py — Train DGA-v2 using character TF-IDF and Logistic Regression.

Reads: data/processed/dga_splits.csv
Saves: models/dga/dga_v2_model.joblib
       models/dga/dga_v2_metadata.json
"""

import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import confusion_matrix, accuracy_score

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Same preprocessing function as used in DGA-v1 (src/dns/features.py)
def _extract_label(query: str) -> str:
    """Extract the leftmost label (subdomain) from a DNS query string."""
    parts = str(query).rstrip(".").split(".")
    return parts[0] if parts else str(query)

def preprocess_domain(query: str) -> str:
    """Exact same representation used before feature extraction in DGA-v1."""
    return _extract_label(query).lower()

SPLITS_CSV = PROJECT_ROOT / "data" / "processed" / "dga_splits.csv"
MODEL_DIR = PROJECT_ROOT / "models" / "dga"
MODEL_PATH = MODEL_DIR / "dga_v2_model.joblib"
METADATA_PATH = MODEL_DIR / "dga_v2_metadata.json"

def evaluate_split(y_true, y_pred, df_split, split_name):
    print(f"\n  --- {split_name} Evaluation ---")
    
    cm = confusion_matrix(y_true, y_pred)
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
            
def main():
    print("=" * 60)
    print("  DGA-v2 Detector — Character N-Gram Baseline")
    print("=" * 60)

    if not SPLITS_CSV.exists():
        print(f"  ERROR: {SPLITS_CSV} not found. Run train.py first to generate splits.")
        sys.exit(1)

    # 1. LOAD EXACT SPLITS
    print("Loading exact explicit split artifact...")
    df = pd.read_csv(SPLITS_CSV)
    
    # 2. EXACT PREPROCESSING
    # We apply the identical preprocessing function that DGA-v1 used before extracting features.
    print("Applying identical domain preprocessing (leftmost label, lowercase)...")
    df['processed_domain'] = df['domain'].apply(preprocess_domain)
    
    df_train = df[df['split'] == 'train'].copy()
    df_val = df[df['split'] == 'validation'].copy()
    df_test = df[df['split'] == 'test'].copy()
    
    X_train_text = df_train['processed_domain'].values
    y_train = df_train['label'].values.astype(int)
    
    X_val_text = df_val['processed_domain'].values
    y_val = df_val['label'].values.astype(int)
    
    X_test_text = df_test['processed_domain'].values
    y_test = df_test['label'].values.astype(int)
    
    print(f"\nTrain: {len(X_train_text)} | Val: {len(X_val_text)} | Test: {len(X_test_text)}")
    
    # 3. PIPELINE SETUP
    print("\nInitializing Pipeline (TF-IDF + LogisticRegression)...")
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(analyzer='char', ngram_range=(2, 5), min_df=2)),
        ('clf', LogisticRegression(class_weight='balanced', random_state=42, max_iter=1000))
    ])
    
    # 4. TRAINING
    print("\nTraining DGA-v2...")
    start_time = time.time()
    pipeline.fit(X_train_text, y_train)
    train_time = time.time() - start_time
    
    num_features = len(pipeline.named_steps['tfidf'].get_feature_names_out())
    print(f"Training complete in {train_time:.2f} seconds.")
    print(f"Number of TF-IDF features generated: {num_features}")
    
    # 5. INFERENCE TIMING
    print("\nMeasuring inference time...")
    inf_start = time.time()
    _ = pipeline.predict(X_test_text)
    inf_time = time.time() - inf_start
    inf_per_domain = (inf_time / len(X_test_text)) * 1000 # in ms
    print(f"Inference time: {inf_time:.4f}s for {len(X_test_text)} domains ({inf_per_domain:.4f} ms/domain)")

    # 6. EVALUATION
    y_val_pred = pipeline.predict(X_val_text)
    evaluate_split(y_val, y_val_pred, df_val, "VALIDATION")
    
    y_test_pred = pipeline.predict(X_test_text)
    evaluate_split(y_test, y_test_pred, df_test, "FINAL UNSEEN-FAMILY TEST")
    
    # 7. SAVE ARTIFACTS
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)
    print(f"\nModel saved -> {MODEL_PATH}")
    
    metadata = {
        "model_name": "DGA Domain Detector (v2 N-Gram Baseline)",
        "model_type": "TF-IDF + Logistic Regression (supervised, character sequence)",
        "model_version": "v2.0",
        "feature_version": "2.0",
        "features": "char_ngrams_2_5",
        "num_tfidf_features": int(num_features),
        "training_samples": int(len(X_train_text)),
        "validation_samples": int(len(X_val_text)),
        "test_samples": int(len(X_test_text)),
        "training_data": "tranco + baderj",
        "split_method": "Strict family-level OOD split (reused from v1)",
        "class_weight": "balanced",
        "random_seed": 42
    }
    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print("=" * 60)

if __name__ == "__main__":
    main()
