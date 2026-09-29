"""
scratch/dga_v4_experiment.py — Train DGA-v4 Hybrid Models.
Variant A: Feature Concatenation
Variant B: Stacking Meta-Classifier with Strict OOF predictions.
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
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import confusion_matrix, accuracy_score

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
    print("  DGA-v4 Detector — Hybrid Representation")
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
    
    # Scale structural features
    scaler = StandardScaler()
    X_train_struct_scaled = scaler.fit_transform(X_train_struct)
    X_val_struct_scaled = scaler.transform(X_val_struct)
    X_test_struct_scaled = scaler.transform(X_test_struct)

    # ---------------------------------------------------------
    # VARIANT A: FEATURE CONCATENATION
    # ---------------------------------------------------------
    print("\n" + "=" * 40)
    print(" VARIANT A: Feature Concatenation")
    print("=" * 40)
    
    print("Extracting TF-IDF Character N-Grams (DGA-v2)...")
    tfidf = TfidfVectorizer(analyzer='char', ngram_range=(2, 5), min_df=2)
    start_time = time.time()
    
    X_train_tfidf = tfidf.fit_transform(df_train['processed_domain'])
    X_val_tfidf = tfidf.transform(df_val['processed_domain'])
    X_test_tfidf = tfidf.transform(df_test['processed_domain'])
    
    print("Combining sparse TF-IDF with scaled dense structural features...")
    X_train_A = hstack([X_train_tfidf, X_train_struct_scaled])
    X_val_A = hstack([X_val_tfidf, X_val_struct_scaled])
    X_test_A = hstack([X_test_tfidf, X_test_struct_scaled])
    
    print("Training LogisticRegression (Variant A)...")
    clf_A = LogisticRegression(class_weight='balanced', max_iter=1000, random_state=42)
    clf_A.fit(X_train_A, y_train)
    
    train_time_A = time.time() - start_time
    print(f"Training complete in {train_time_A:.2f} seconds.")
    print(f"Total features: {X_train_A.shape[1]}")
    
    # Inference Time A
    inf_start_A = time.time()
    y_test_pred_A = clf_A.predict(X_test_A)
    inf_time_A = time.time() - inf_start_A
    print(f"Inference time: {inf_time_A:.4f}s for {X_test_A.shape[0]} domains ({(inf_time_A/X_test_A.shape[0])*1000:.4f} ms/domain)")
    
    y_val_pred_A = clf_A.predict(X_val_A)
    evaluate_split(y_val, y_val_pred_A, df_val, "VALIDATION (Variant A)")
    evaluate_split(y_test, y_test_pred_A, df_test, "FINAL TEST (Variant A)")

    # ---------------------------------------------------------
    # VARIANT B: STRICT OOF STACKING META-CLASSIFIER
    # ---------------------------------------------------------
    print("\n" + "=" * 40)
    print(" VARIANT B: Strict OOF Stacking Meta-Classifier")
    print("=" * 40)
    
    start_time_B = time.time()
    
    # 1. K-Fold OOF Predictions
    K = 5
    print(f"Performing {K}-Fold Strict OOF generation on Train set...")
    skf = StratifiedKFold(n_splits=K, shuffle=True, random_state=42)
    
    oof_v2_prob = np.zeros(len(y_train))
    oof_v3_prob = np.zeros(len(y_train))
    
    for fold, (train_idx, val_idx) in enumerate(skf.split(df_train['processed_domain'], y_train)):
        print(f"  Fold {fold+1}/{K}...")
        
        X_text_fold_train, X_text_fold_val = df_train['processed_domain'].iloc[train_idx], df_train['processed_domain'].iloc[val_idx]
        X_struct_fold_train, X_struct_fold_val = X_train_struct_scaled[train_idx], X_train_struct_scaled[val_idx]
        y_fold_train = y_train[train_idx]
        
        # Fit V2 (TFIDF+LR) strictly on this fold
        tfidf_fold = TfidfVectorizer(analyzer='char', ngram_range=(2, 5), min_df=2)
        X_tfidf_fold_train = tfidf_fold.fit_transform(X_text_fold_train)
        X_tfidf_fold_val = tfidf_fold.transform(X_text_fold_val)
        
        clf_v2_fold = LogisticRegression(class_weight='balanced', max_iter=1000, random_state=42)
        clf_v2_fold.fit(X_tfidf_fold_train, y_fold_train)
        oof_v2_prob[val_idx] = clf_v2_fold.predict_proba(X_tfidf_fold_val)[:, 1]
        
        # Fit V3 (Struct+RF) strictly on this fold
        clf_v3_fold = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42, n_jobs=-1)
        clf_v3_fold.fit(X_struct_fold_train, y_fold_train)
        oof_v3_prob[val_idx] = clf_v3_fold.predict_proba(X_struct_fold_val)[:, 1]

    # 2. Train Meta Classifier
    print("\nTraining Meta-Classifier on OOF probabilities + scaled structural features...")
    # Meta features: V2 Prob, V3 Prob, Structural Features
    X_meta_train = np.column_stack([oof_v2_prob, oof_v3_prob, X_train_struct_scaled])
    
    meta_clf = LogisticRegression(class_weight='balanced', max_iter=1000, random_state=42)
    meta_clf.fit(X_meta_train, y_train)
    
    # 3. Final Retraining of Base Models on FULL Train Set
    print("\nRetraining final base models (V2 and V3) on COMPLETE Train set...")
    final_tfidf = TfidfVectorizer(analyzer='char', ngram_range=(2, 5), min_df=2)
    X_train_tfidf_final = final_tfidf.fit_transform(df_train['processed_domain'])
    
    final_v2_clf = LogisticRegression(class_weight='balanced', max_iter=1000, random_state=42)
    final_v2_clf.fit(X_train_tfidf_final, y_train)
    
    final_v3_clf = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42, n_jobs=-1)
    final_v3_clf.fit(X_train_struct_scaled, y_train)
    
    train_time_B = time.time() - start_time_B
    print(f"Variant B Training complete in {train_time_B:.2f} seconds.")
    print(f"Meta-Classifier Feature Count: {X_meta_train.shape[1]}")
    
    # 4. Meta-Inference (Validation & Test)
    print("\nGenerating meta-predictions for Validation and Test...")
    
    # For Validation
    X_val_tfidf_final = final_tfidf.transform(df_val['processed_domain'])
    val_v2_prob = final_v2_clf.predict_proba(X_val_tfidf_final)[:, 1]
    val_v3_prob = final_v3_clf.predict_proba(X_val_struct_scaled)[:, 1]
    X_meta_val = np.column_stack([val_v2_prob, val_v3_prob, X_val_struct_scaled])
    y_val_pred_B = meta_clf.predict(X_meta_val)
    
    # For Test
    inf_start_B = time.time()
    X_test_tfidf_final = final_tfidf.transform(df_test['processed_domain'])
    test_v2_prob = final_v2_clf.predict_proba(X_test_tfidf_final)[:, 1]
    test_v3_prob = final_v3_clf.predict_proba(X_test_struct_scaled)[:, 1]
    X_meta_test = np.column_stack([test_v2_prob, test_v3_prob, X_test_struct_scaled])
    y_test_pred_B = meta_clf.predict(X_meta_test)
    inf_time_B = time.time() - inf_start_B
    
    print(f"Inference time: {inf_time_B:.4f}s for {len(df_test)} domains ({(inf_time_B/len(df_test))*1000:.4f} ms/domain)")

    evaluate_split(y_val, y_val_pred_B, df_val, "VALIDATION (Variant B)")
    evaluate_split(y_test, y_test_pred_B, df_test, "FINAL TEST (Variant B)")
    
    print("=" * 60)

if __name__ == "__main__":
    main()
