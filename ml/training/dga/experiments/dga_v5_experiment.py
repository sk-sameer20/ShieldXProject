"""
scratch/dga_v5_experiment.py — Train DGA-v5 Nonlinear Hybrid Model using XGBoost.
Combines TF-IDF n-grams and Structural features.
"""

import math
import sys
import time
from pathlib import Path
from collections import Counter, defaultdict

import numpy as np
import pandas as pd
import joblib
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, accuracy_score

try:
    import xgboost as xgb
except ImportError:
    print("XGBoost is required for DGA-v5.")
    sys.exit(1)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# ---------------------------------------------------------
# PREPROCESSING & STRUCTURAL FEATURE EXTRACTION (Same as V3)
# ---------------------------------------------------------
def _extract_label(query: str) -> str:
    parts = str(query).rstrip(".").split(".")
    return parts[0] if parts else str(query)

def preprocess_domain(query: str) -> str:
    return _extract_label(query).lower()

def compute_entropy(s):
    p, lns = Counter(s), float(len(s))
    return -sum(count/lns * math.log2(count/lns) for count in p.values()) if lns else 0.0

def count_vowels(s):
    return sum(1 for c in s if c in 'aeiou')

def max_consecutive_consonants(s):
    max_c = 0
    curr_c = 0
    for c in s:
        if c.isalpha() and c not in 'aeiou':
            curr_c += 1
            max_c = max(max_c, curr_c)
        else:
            curr_c = 0
    return max_c

def build_benign_transition_matrix(train_benign_domains):
    bigrams = Counter()
    unigrams = Counter()
    for domain in train_benign_domains:
        for i in range(len(domain) - 1):
            c1, c2 = domain[i], domain[i+1]
            unigrams[c1] += 1
            bigrams[c1 + c2] += 1
            
    matrix = defaultdict(lambda: defaultdict(float))
    for (c1, c2), count in bigrams.items():
        matrix[c1][c2] = count / unigrams[c1]
    return matrix

def get_transition_features(domain, matrix, threshold=0.01):
    if len(domain) < 2:
        return 0.0, 0.0, 0
    probs = []
    for i in range(len(domain) - 1):
        c1, c2 = domain[i], domain[i+1]
        p = matrix.get(c1, {}).get(c2, 0.0)
        probs.append(p)
    avg_p = sum(probs) / len(probs)
    min_p = min(probs)
    unusual = sum(1 for p in probs if p < threshold)
    return avg_p, min_p, unusual

def extract_structural_features(df, transition_matrix, unusual_threshold=0.01):
    features = []
    for d in df['processed_domain']:
        prefix, suffix = d[:4], d[4:]
        
        pre_ent, suf_ent = compute_entropy(prefix), compute_entropy(suffix)
        pre_v_ratio = count_vowels(prefix) / max(len(prefix), 1)
        suf_v_ratio = count_vowels(suffix) / max(len(suffix), 1)
        pre_div = len(set(prefix)) / max(len(prefix), 1)
        suf_div = len(set(suffix)) / max(len(suffix), 1)
        
        unique_char_ratio = len(set(d)) / max(len(d), 1)
        max_cons = max_consecutive_consonants(d)
        avg_p, min_p, unus = get_transition_features(d, transition_matrix, unusual_threshold)
        
        features.append([
            pre_ent, suf_ent, abs(pre_ent - suf_ent),
            pre_v_ratio, suf_v_ratio, abs(pre_v_ratio - suf_v_ratio),
            pre_div, suf_div, abs(pre_div - suf_div),
            unique_char_ratio, max_cons,
            avg_p, min_p, unus
        ])
    return np.array(features)

# ---------------------------------------------------------
# EVALUATION HELPER
# ---------------------------------------------------------
def evaluate_split(y_true, y_pred, df_split, split_name):
    print(f"\n  --- {split_name} Evaluation ---")
    cm = confusion_matrix(y_true, y_pred)
    tn = fp = fn = tp = 0
    if cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel()
    else:
        if len(np.unique(y_true)) == 1:
            if y_true[0] == 0: tn = cm[0,0]
            else: tp = cm[0,0]
            
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

# ---------------------------------------------------------
# MAIN EXPERIMENT
# ---------------------------------------------------------
def main():
    print("=" * 60)
    print("  DGA-v5 Detector — Nonlinear Hybrid (XGBoost)")
    print("=" * 60)
    
    splits_csv = PROJECT_ROOT / "data" / "processed" / "dga_splits.csv"
    df = pd.read_csv(splits_csv)
    df['processed_domain'] = df['domain'].apply(preprocess_domain)
    
    df_train = df[df['split'] == 'train'].copy()
    df_val = df[df['split'] == 'validation'].copy()
    df_test = df[df['split'] == 'test'].copy()
    
    print("Building transition matrix from train benign domains...")
    train_benign = df_train[df_train['label'] == 0]['processed_domain']
    t_matrix = build_benign_transition_matrix(train_benign)
    
    print("Extracting structural features (DGA-v3) for all splits...")
    X_train_struct = extract_structural_features(df_train, t_matrix)
    X_val_struct = extract_structural_features(df_val, t_matrix)
    X_test_struct = extract_structural_features(df_test, t_matrix)
    
    y_train = df_train['label'].values.astype(int)
    y_val = df_val['label'].values.astype(int)
    y_test = df_test['label'].values.astype(int)
    
    # Scale structural features (good practice, though trees are less sensitive)
    scaler = StandardScaler()
    X_train_struct_scaled = scaler.fit_transform(X_train_struct)
    X_val_struct_scaled = scaler.transform(X_val_struct)
    X_test_struct_scaled = scaler.transform(X_test_struct)

    print("Extracting TF-IDF Character N-Grams (DGA-v2)...")
    tfidf = TfidfVectorizer(analyzer='char', ngram_range=(2, 5), min_df=2)
    start_time = time.time()
    
    X_train_tfidf = tfidf.fit_transform(df_train['processed_domain'])
    X_val_tfidf = tfidf.transform(df_val['processed_domain'])
    X_test_tfidf = tfidf.transform(df_test['processed_domain'])
    
    print("Combining sparse TF-IDF with dense structural features...")
    X_train_combined = hstack([X_train_tfidf, X_train_struct_scaled]).tocsr()
    X_val_combined = hstack([X_val_tfidf, X_val_struct_scaled]).tocsr()
    X_test_combined = hstack([X_test_tfidf, X_test_struct_scaled]).tocsr()
    
    print("Training XGBClassifier (DGA-v5)...")
    # Calculate scale_pos_weight
    num_neg = sum(y_train == 0)
    num_pos = sum(y_train == 1)
    scale_pos_weight = num_neg / num_pos if num_pos > 0 else 1.0
    
    clf = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        scale_pos_weight=scale_pos_weight,
        tree_method="hist", # Optimized for sparse/dense mix
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train_combined, y_train)
    
    train_time = time.time() - start_time
    print(f"Training complete in {train_time:.2f} seconds.")
    print(f"Total features: {X_train_combined.shape[1]}")
    
    # Inference Time
    inf_start = time.time()
    y_test_pred = clf.predict(X_test_combined)
    inf_time = time.time() - inf_start
    print(f"Inference time: {inf_time:.4f}s for {X_test_combined.shape[0]} domains ({(inf_time/X_test_combined.shape[0])*1000:.4f} ms/domain)")
    
    y_val_pred = clf.predict(X_val_combined)
    evaluate_split(y_val, y_val_pred, df_val, "VALIDATION")
    evaluate_split(y_test, y_test_pred, df_test, "FINAL TEST")
    
    print("=" * 60)

if __name__ == "__main__":
    main()
