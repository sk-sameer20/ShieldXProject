"""
scratch/dga_v3_experiment.py — Train DGA-v3 using structural features and Random Forest.
"""

import math
import sys
from pathlib import Path
from collections import Counter, defaultdict

import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, accuracy_score

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

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

def extract_features(df, transition_matrix, unusual_threshold=0.01):
    features = []
    for d in df['processed_domain']:
        prefix = d[:4]
        suffix = d[4:]
        
        pre_ent = compute_entropy(prefix)
        suf_ent = compute_entropy(suffix)
        ent_diff = abs(pre_ent - suf_ent)
        
        pre_v_ratio = count_vowels(prefix) / max(len(prefix), 1)
        suf_v_ratio = count_vowels(suffix) / max(len(suffix), 1)
        v_diff = abs(pre_v_ratio - suf_v_ratio)
        
        pre_div = len(set(prefix)) / max(len(prefix), 1)
        suf_div = len(set(suffix)) / max(len(suffix), 1)
        div_diff = abs(pre_div - suf_div)
        
        unique_char_ratio = len(set(d)) / max(len(d), 1)
        max_cons = max_consecutive_consonants(d)
        
        avg_p, min_p, unus = get_transition_features(d, transition_matrix, unusual_threshold)
        
        features.append({
            'pre_ent': pre_ent,
            'suf_ent': suf_ent,
            'ent_diff': ent_diff,
            'pre_v_ratio': pre_v_ratio,
            'suf_v_ratio': suf_v_ratio,
            'v_diff': v_diff,
            'pre_div': pre_div,
            'suf_div': suf_div,
            'div_diff': div_diff,
            'unique_char_ratio': unique_char_ratio,
            'max_cons': max_cons,
            'avg_p': avg_p,
            'min_p': min_p,
            'unus': unus
        })
    return pd.DataFrame(features)

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

def analyze_features(df, features_df, v2_model_path):
    print("\n=== FEATURE DISTRIBUTION ANALYSIS (MEDIANS) ===")
    comb = pd.concat([df.reset_index(drop=True), features_df.reset_index(drop=True)], axis=1)
    
    # Needs v2 labels for detected vs missed
    pipeline = joblib.load(v2_model_path)
    comb['v2_pred'] = pipeline.predict(comb['processed_domain'])
    
    # 1. Family Medians
    families = ['qakbot', 'corebot', 'ramdo', 'banjori', 'dircrypt', 'simda', 'nymaim']
    cols_to_print = ['ent_diff', 'v_diff', 'div_diff', 'max_cons', 'unique_char_ratio', 'avg_p', 'min_p', 'unus']
    
    benign = comb[comb['label'] == 0]
    print(f"\nBenign (N={len(benign)})")
    for c in cols_to_print: print(f"  {c}: {benign[c].median():.4f}")
    
    for fam in families:
        fdf = comb[comb['family'] == fam]
        if not fdf.empty:
            print(f"\n{fam.capitalize()} (N={len(fdf)})")
            for c in cols_to_print: print(f"  {c}: {fdf[c].median():.4f}")
            
    # 2. Banjori Detected vs Missed by DGA-v2
    print("\n=== BANJORI: V2 DETECTED VS MISSED ===")
    banj = comb[comb['family'] == 'banjori']
    det = banj[banj['v2_pred'] == 1]
    mis = banj[banj['v2_pred'] == 0]
    print(f"Detected (N={len(det)})")
    for c in cols_to_print: print(f"  {c}: {det[c].median():.4f}")
    print(f"\nMissed (N={len(mis)})")
    for c in cols_to_print: print(f"  {c}: {mis[c].median():.4f}")
    
def main():
    print("=" * 60)
    print("  DGA-v3 Detector — Structural Features Baseline")
    print("=" * 60)
    
    splits_csv = PROJECT_ROOT / "data" / "processed" / "dga_splits.csv"
    df = pd.read_csv(splits_csv)
    df['processed_domain'] = df['domain'].apply(preprocess_domain)
    
    df_train = df[df['split'] == 'train'].copy()
    df_val = df[df['split'] == 'validation'].copy()
    df_test = df[df['split'] == 'test'].copy()
    
    # 1. Build transition matrix from Train Benign
    print("Building transition matrix from train benign domains...")
    train_benign = df_train[df_train['label'] == 0]['processed_domain']
    t_matrix = build_benign_transition_matrix(train_benign)
    
    # 2. Extract Features
    print("Extracting structural features for all splits...")
    X_train = extract_features(df_train, t_matrix)
    y_train = df_train['label'].values.astype(int)
    
    X_val = extract_features(df_val, t_matrix)
    y_val = df_val['label'].values.astype(int)
    
    X_test = extract_features(df_test, t_matrix)
    y_test = df_test['label'].values.astype(int)
    
    # 3. Analyze Features
    v2_path = PROJECT_ROOT / "models" / "dga" / "dga_v2_model.joblib"
    analyze_features(df, extract_features(df, t_matrix), v2_path)
    
    # 4. Train Model
    print("\nTraining DGA-v3 RandomForest on structural features...")
    clf = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)
    
    # 5. Evaluate
    y_val_pred = clf.predict(X_val)
    evaluate_split(y_val, y_val_pred, df_val, "VALIDATION")
    
    y_test_pred = clf.predict(X_test)
    evaluate_split(y_test, y_test_pred, df_test, "FINAL UNSEEN-FAMILY TEST")
    
    # Save Model
    out_path = PROJECT_ROOT / "models" / "dga" / "dga_v3_model.joblib"
    joblib.dump({"model": clf, "transition_matrix": dict(t_matrix)}, out_path)
    print(f"\nSaved model to {out_path}")
    print("=" * 60)

if __name__ == "__main__":
    main()
