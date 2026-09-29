"""
scratch/dga_v8_experiment.py — DGA-v8 Late-Fusion Experiment (v2 + v6).
"""

import sys
import time
import json
import random
from pathlib import Path

import numpy as np
import pandas as pd
from collections import Counter
from sklearn.metrics import confusion_matrix, accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, Conv1D, GlobalMaxPooling1D, Dense, Dropout
from tensorflow.keras.callbacks import EarlyStopping

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# ---------------------------------------------------------
# SETUP & CONFIG
# ---------------------------------------------------------
SEED = 42
random.seed(SEED)
np.random.seed(SEED)
tf.random.set_seed(SEED)

def _extract_label(query: str) -> str:
    parts = str(query).rstrip(".").split(".")
    return parts[0] if parts else str(query)

def preprocess_domain(query: str) -> str:
    return _extract_label(query).lower()

# ---------------------------------------------------------
# EVALUATION HELPER
# ---------------------------------------------------------
def evaluate_preds(y_true, y_pred, df_split, split_name, rule_name):
    print(f"\n  --- {split_name} | {rule_name} ---")
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
    
    print(f"Confusion Matrix: [[{tn} (TN)  {fp} (FP)] [{fn} (FN)  {tp} (TP)]]")
    print(f"Accuracy:  {acc:.4f} | Precision: {precision:.4f} | Recall: {recall:.4f} | F1 Score: {f1:.4f} | FPR: {fpr:.4f}")
    
    families = df_split[df_split['label'] == 1]['family'].unique()
    for fam in families:
        fam_idx = df_split['family'] == fam
        y_true_fam = y_true[fam_idx]
        y_pred_fam = y_pred[fam_idx]
        if len(y_true_fam) > 0:
            tp_fam = np.sum(y_pred_fam == 1)
            rec_fam = tp_fam / len(y_true_fam)
            print(f"  {fam}: {rec_fam*100:.1f}% ({tp_fam}/{len(y_true_fam)})")
            
def evaluate_overlap(y_true, y_pred_v2, y_pred_v6, df_split, family):
    fam_idx = df_split['family'] == family
    y_v2 = y_pred_v2[fam_idx]
    y_v6 = y_pred_v6[fam_idx]
    total = np.sum(fam_idx)
    
    both = np.sum((y_v2 == 1) & (y_v6 == 1))
    v2_only = np.sum((y_v2 == 1) & (y_v6 == 0))
    v6_only = np.sum((y_v2 == 0) & (y_v6 == 1))
    neither = np.sum((y_v2 == 0) & (y_v6 == 0))
    
    print(f"\nOverlap Analysis for {family} (Total: {total}):")
    print(f"  Detected by both:      {both} ({(both/total)*100:.1f}%)")
    print(f"  Detected by v2 only:   {v2_only} ({(v2_only/total)*100:.1f}%)")
    print(f"  Detected by v6 only:   {v6_only} ({(v6_only/total)*100:.1f}%)")
    print(f"  Detected by neither:   {neither} ({(neither/total)*100:.1f}%)")

# ---------------------------------------------------------
# MAIN EXPERIMENT
# ---------------------------------------------------------
def main():
    print("=" * 60)
    print("  DGA-v8 Detector — Late-Fusion (v2 + v6)")
    print("=" * 60)
    
    splits_csv = PROJECT_ROOT / "data" / "processed" / "dga_splits.csv"
    df = pd.read_csv(splits_csv)
    df['processed_domain'] = df['domain'].apply(preprocess_domain)
    
    df_train = df[df['split'] == 'train'].copy()
    df_val = df[df['split'] == 'validation'].copy()
    df_test = df[df['split'] == 'test'].copy()
    
    y_train_full = df_train['label'].values.astype(int)
    y_val = df_val['label'].values.astype(int)
    y_test = df_test['label'].values.astype(int)
    
    # ---------------------------------------------------------
    # Train Expert A: DGA-v2 (TF-IDF + LR)
    # ---------------------------------------------------------
    print("\nTraining Expert A (DGA-v2 Char N-grams)...")
    vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2, 5))
    X_train_v2 = vectorizer.fit_transform(df_train['processed_domain'])
    X_val_v2 = vectorizer.transform(df_val['processed_domain'])
    X_test_v2 = vectorizer.transform(df_test['processed_domain'])
    
    clf_v2 = LogisticRegression(class_weight="balanced", random_state=SEED, max_iter=1000)
    clf_v2.fit(X_train_v2, y_train_full)
    
    p_val_v2 = clf_v2.predict_proba(X_val_v2)[:, 1]
    p_test_v2 = clf_v2.predict_proba(X_test_v2)[:, 1]
    
    # ---------------------------------------------------------
    # Train Expert B: DGA-v6 (1D-CNN)
    # ---------------------------------------------------------
    print("\nTraining Expert B (DGA-v6 1D-CNN)...")
    char_counter = Counter()
    lengths = []
    for d in df_train['processed_domain']:
        char_counter.update(d)
        lengths.append(len(d))
        
    vocab = {char: idx + 2 for idx, (char, _) in enumerate(char_counter.most_common())}
    vocab['<PAD>'] = 0
    vocab['<UNK>'] = 1
    vocab_size = len(vocab)
    max_length = int(np.percentile(lengths, 99))
    
    def encode_domains(domains, vocab, max_len):
        encoded = []
        for d in domains:
            seq = [vocab.get(c, 1) for c in d]
            if len(seq) > max_len:
                seq = seq[:max_len]
            else:
                seq = seq + [0] * (max_len - len(seq))
            encoded.append(seq)
        return np.array(encoded)

    X_train_full_v6 = encode_domains(df_train['processed_domain'], vocab, max_length)
    X_val_v6 = encode_domains(df_val['processed_domain'], vocab, max_length)
    X_test_v6 = encode_domains(df_test['processed_domain'], vocab, max_length)
    
    X_train_v6, X_internal_val_v6, y_train_v6, y_internal_val_v6 = train_test_split(
        X_train_full_v6, y_train_full, test_size=0.2, random_state=SEED, stratify=y_train_full
    )
    
    classes = np.unique(y_train_v6)
    weights = compute_class_weight('balanced', classes=classes, y=y_train_v6)
    class_weight_dict = {c: w for c, w in zip(classes, weights)}
    
    model_v6 = Sequential([
        tf.keras.layers.Input(shape=(max_length,)),
        Embedding(input_dim=vocab_size, output_dim=32),
        Conv1D(filters=64, kernel_size=3, activation='relu'),
        GlobalMaxPooling1D(),
        Dense(32, activation='relu'),
        Dropout(0.3),
        Dense(1, activation='sigmoid')
    ])
    
    model_v6.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    early_stop = EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True, verbose=0)
    
    model_v6.fit(
        X_train_v6, y_train_v6,
        validation_data=(X_internal_val_v6, y_internal_val_v6),
        epochs=50,
        batch_size=128,
        class_weight=class_weight_dict,
        callbacks=[early_stop],
        verbose=0
    )
    
    p_val_v6 = model_v6.predict(X_val_v6, verbose=0).flatten()
    p_test_v6 = model_v6.predict(X_test_v6, verbose=0).flatten()
    
    # ---------------------------------------------------------
    # EVALUATION
    # ---------------------------------------------------------
    
    print("\n" + "=" * 60)
    print("  FUSION EVALUATION")
    print("=" * 60)
    
    for df_split, split_name, y_true, p_v2, p_v6 in [
        (df_val, "VALIDATION", y_val, p_val_v2, p_val_v6),
        (df_test, "FINAL TEST", y_test, p_test_v2, p_test_v6)
    ]:
        print(f"\n>>>> {split_name} <<<<")
        
        # Baselines
        evaluate_preds(y_true, (p_v2 >= 0.5).astype(int), df_split, split_name, "Expert A (v2 Baseline)")
        evaluate_preds(y_true, (p_v6 >= 0.5).astype(int), df_split, split_name, "Expert B (v6 Baseline)")
        
        # Fusion Rules
        pred_or = ((p_v2 >= 0.5) | (p_v6 >= 0.5)).astype(int)
        evaluate_preds(y_true, pred_or, df_split, split_name, "Rule 1: OR")
        
        pred_and = ((p_v2 >= 0.5) & (p_v6 >= 0.5)).astype(int)
        evaluate_preds(y_true, pred_and, df_split, split_name, "Rule 2: AND")
        
        p_max = np.maximum(p_v2, p_v6)
        evaluate_preds(y_true, (p_max >= 0.5).astype(int), df_split, split_name, "Rule 3: MAX")
        
        p_mean = (p_v2 + p_v6) / 2.0
        evaluate_preds(y_true, (p_mean >= 0.5).astype(int), df_split, split_name, "Rule 4: MEAN")
        
    print("\n" + "=" * 60)
    print("  OVERLAP ANALYSIS")
    print("=" * 60)
    
    val_pred_v2_bin = (p_val_v2 >= 0.5).astype(int)
    val_pred_v6_bin = (p_val_v6 >= 0.5).astype(int)
    evaluate_overlap(y_val, val_pred_v2_bin, val_pred_v6_bin, df_val, "banjori")
    
    test_pred_v2_bin = (p_test_v2 >= 0.5).astype(int)
    test_pred_v6_bin = (p_test_v6 >= 0.5).astype(int)
    evaluate_overlap(y_test, test_pred_v2_bin, test_pred_v6_bin, df_test, "simda")


if __name__ == "__main__":
    main()
