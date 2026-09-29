"""
scratch/dga_v6_1_experiment.py — Train DGA-v6.1 Character-Level 1D-CNN (Length Augmented).
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
def evaluate_split(y_true, y_pred_prob, df_split, split_name, threshold=0.5):
    print(f"\n  --- {split_name} Evaluation ---")
    y_pred = (y_pred_prob >= threshold).astype(int)
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
    print("  DGA-v6.1 Detector — 1D-CNN with Length Augmentation")
    print("=" * 60)
    
    splits_csv = PROJECT_ROOT / "data" / "processed" / "dga_splits.csv"
    df = pd.read_csv(splits_csv)
    df['processed_domain'] = df['domain'].apply(preprocess_domain)
    
    df_train_full = df[df['split'] == 'train'].copy()
    df_val = df[df['split'] == 'validation'].copy()
    df_test = df[df['split'] == 'test'].copy()
    
    # Vocabulary built from original TRAIN only
    print("Building vocabulary from original TRAIN only...")
    char_counter = Counter()
    for d in df_train_full['processed_domain']:
        char_counter.update(d)
        
    vocab = {char: idx + 2 for idx, (char, _) in enumerate(char_counter.most_common())}
    vocab['<PAD>'] = 0
    vocab['<UNK>'] = 1
    vocab_size = len(vocab)
    
    # Internal Split FIRST to avoid leakage of augmented samples into validation
    df_train, df_internal_val = train_test_split(
        df_train_full, test_size=0.2, random_state=SEED, stratify=df_train_full['label']
    )
    
    print("\nPerforming Training-Time Length Augmentation...")
    original_lengths = df_train['processed_domain'].apply(len)
    print("Original Train Lengths: Min:", original_lengths.min(), 
          "Median:", original_lengths.median(), "Max:", original_lengths.max())
    
    augmented_rows = []
    for _, row in df_train.iterrows():
        domain = row['processed_domain']
        augmented_rows.append(row.to_dict()) # Keep original
        
        if len(domain) >= 12:
            for _ in range(2):
                crop_len = random.randint(6, 11)
                start_idx = random.randint(0, len(domain) - crop_len)
                crop = domain[start_idx:start_idx+crop_len]
                new_row = row.to_dict()
                new_row['processed_domain'] = crop
                augmented_rows.append(new_row)
        elif len(domain) > 6:
            crop_len = random.randint(4, len(domain) - 1)
            start_idx = random.randint(0, len(domain) - crop_len)
            crop = domain[start_idx:start_idx+crop_len]
            new_row = row.to_dict()
            new_row['processed_domain'] = crop
            augmented_rows.append(new_row)
            
    df_train_aug = pd.DataFrame(augmented_rows)
    # Shuffle the augmented training data
    df_train_aug = df_train_aug.sample(frac=1, random_state=SEED).reset_index(drop=True)
    
    aug_lengths = df_train_aug['processed_domain'].apply(len)
    print(f"Generated samples: {len(df_train_aug)} (from {len(df_train)})")
    print("Augmented Train Lengths: Min:", aug_lengths.min(), 
          "Median:", aug_lengths.median(), "Max:", aug_lengths.max())
          
    # Max length based on original train set (like v6)
    max_length = int(np.percentile(df_train_full['processed_domain'].apply(len), 99))
    print(f"\nVocabulary size: {vocab_size}")
    print(f"Max sequence length (99th percentile of original): {max_length}")
    
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

    X_train = encode_domains(df_train_aug['processed_domain'], vocab, max_length)
    y_train = df_train_aug['label'].values.astype(int)
    
    X_internal_val = encode_domains(df_internal_val['processed_domain'], vocab, max_length)
    y_internal_val = df_internal_val['label'].values.astype(int)
    
    X_val = encode_domains(df_val['processed_domain'], vocab, max_length)
    y_val = df_val['label'].values.astype(int)
    
    X_test = encode_domains(df_test['processed_domain'], vocab, max_length)
    y_test = df_test['label'].values.astype(int)
    
    print(f"Final Train samples: {X_train.shape[0]}, Internal Val samples: {X_internal_val.shape[0]}")
    
    # Calculate class weights
    classes = np.unique(y_train)
    weights = compute_class_weight('balanced', classes=classes, y=y_train)
    class_weight_dict = {c: w for c, w in zip(classes, weights)}
    
    print("\nBuilding 1D-CNN Model...")
    model = Sequential([
        tf.keras.layers.Input(shape=(max_length,)),
        Embedding(input_dim=vocab_size, output_dim=32),
        Conv1D(filters=64, kernel_size=3, activation='relu'),
        GlobalMaxPooling1D(),
        Dense(32, activation='relu'),
        Dropout(0.3),
        Dense(1, activation='sigmoid')
    ])
    
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    model.summary()
    param_count = model.count_params()
    
    print("\nTraining Model...")
    start_time = time.time()
    early_stop = EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True, verbose=1)
    
    history = model.fit(
        X_train, y_train,
        validation_data=(X_internal_val, y_internal_val),
        epochs=50,
        batch_size=128,
        class_weight=class_weight_dict,
        callbacks=[early_stop],
        verbose=1
    )
    
    train_time = time.time() - start_time
    print(f"Training complete in {train_time:.2f} seconds.")
    
    # ---------------------------------------------------------
    # RECORD METADATA
    # ---------------------------------------------------------
    metadata = {
        "experiment": "v6.1",
        "python_version": sys.version,
        "tensorflow_version": tf.__version__,
        "keras_version": tf.keras.__version__,
        "numpy_version": np.__version__,
        "random_seed": SEED,
        "max_length": int(max_length),
        "vocabulary_size": int(vocab_size),
        "parameter_count": int(param_count),
        "training_time_seconds": float(train_time),
        "train_samples_original": len(df_train),
        "train_samples_augmented": len(df_train_aug)
    }
    
    metadata_dir = PROJECT_ROOT / "models" / "dga"
    metadata_dir.mkdir(parents=True, exist_ok=True)
    metadata_file = metadata_dir / "dga_v6_1_metadata.json"
    with open(metadata_file, "w") as f:
        json.dump(metadata, f, indent=4)
    print(f"\nMetadata saved to {metadata_file}")
    
    # ---------------------------------------------------------
    # EVALUATION
    # ---------------------------------------------------------
    print("\nGenerating predictions for Validation and Test...")
    
    val_pred_prob = model.predict(X_val).flatten()
    evaluate_split(y_val, val_pred_prob, df_val, "VALIDATION", threshold=0.5)
    
    inf_start = time.time()
    test_pred_prob = model.predict(X_test).flatten()
    inf_time = time.time() - inf_start
    print(f"\nInference time: {inf_time:.4f}s for {len(X_test)} domains ({(inf_time/len(X_test))*1000:.4f} ms/domain)")
    
    evaluate_split(y_test, test_pred_prob, df_test, "FINAL TEST", threshold=0.5)

    print("\n" + "=" * 60)
    print("  COMPARISON SUMMARY (v6 vs v6.1)")
    print("=" * 60)
    print(f"{'Model':<15} | {'Banjori':<10} | {'Simda':<10} | {'Test FPR'}")
    print("-" * 55)
    print(f"{'v6 (1D-CNN)':<15} | {'98.6%':<10} | {'16.6%':<10} | {'0.75%'}")
    
    # Extract final results for v6.1
    test_y_pred_bin = (test_pred_prob >= 0.5).astype(int)
    cm_test = confusion_matrix(y_test, test_y_pred_bin)
    v61_fpr = cm_test[0,1] / (cm_test[0,0] + cm_test[0,1]) if len(cm_test)>1 else 0.0
    
    # Banjori is in validation, Simda in test
    val_y_pred_bin = (val_pred_prob >= 0.5).astype(int)
    banj_idx = df_val['family'] == 'banjori'
    v61_banj_rec = np.sum(val_y_pred_bin[banj_idx] == 1) / np.sum(banj_idx)
    
    simda_idx = df_test['family'] == 'simda'
    v61_simda_rec = np.sum(test_y_pred_bin[simda_idx] == 1) / np.sum(simda_idx)
    
    print(f"{'v6.1 (CNN+Aug)':<15} | {v61_banj_rec*100:.1f}%{'':<5} | {v61_simda_rec*100:.1f}%{'':<5} | {v61_fpr*100:.2f}%")
    print("=" * 60)


if __name__ == "__main__":
    main()
