import sys
from pathlib import Path
import pandas as pd
import numpy as np
import joblib

PROJECT_ROOT = Path(__file__).resolve().parent.parent

def _extract_label(query: str) -> str:
    parts = str(query).rstrip(".").split(".")
    return parts[0] if parts else str(query)

def preprocess_domain(query: str) -> str:
    return _extract_label(query).lower()

def compute_entropy(s):
    import math
    p, lns = collections.Counter(s), float(len(s))
    return -sum(count/lns * math.log2(count/lns) for count in p.values()) if lns else 0

import collections

def main():
    splits_csv = PROJECT_ROOT / "data" / "processed" / "dga_splits.csv"
    model_path = PROJECT_ROOT / "models" / "dga" / "dga_v2_model.joblib"
    
    df = pd.read_csv(splits_csv)
    df['processed_domain'] = df['domain'].apply(preprocess_domain)
    
    pipeline = joblib.load(model_path)
    clf = pipeline.named_steps['clf']
    tfidf = pipeline.named_steps['tfidf']
    
    feature_names = tfidf.get_feature_names_out()
    coefs = clf.coef_[0]
    
    # Top 20 malicious n-grams
    top_malicious_idx = np.argsort(coefs)[-20:][::-1]
    top_benign_idx = np.argsort(coefs)[:20]
    
    print("=== TOP 20 N-GRAMS FOR MALICIOUS (DGA) ===")
    for idx in top_malicious_idx:
        print(f"  '{feature_names[idx]}': {coefs[idx]:.4f}")
        
    print("\n=== TOP 20 N-GRAMS FOR BENIGN ===")
    for idx in top_benign_idx:
        print(f"  '{feature_names[idx]}': {coefs[idx]:.4f}")
        
    # Analyze Banjori vs Benign
    df_banjori = df[df['family'] == 'banjori'].copy()
    df_benign = df[df['label'] == 0].copy()
    
    # Let's predict probabilities
    df_banjori['pred_prob'] = pipeline.predict_proba(df_banjori['processed_domain'])[:, 1]
    df_banjori['pred_label'] = pipeline.predict(df_banjori['processed_domain'])
    
    # Separate detected vs missed Banjori
    detected = df_banjori[df_banjori['pred_label'] == 1]
    missed = df_banjori[df_banjori['pred_label'] == 0]
    
    print(f"\n=== BANJORI STATS ===")
    print(f"Total Banjori: {len(df_banjori)}")
    print(f"Detected: {len(detected)}")
    print(f"Missed: {len(missed)}")
    
    print("\nRepresentative Detected Banjori:")
    for _, row in detected.head(5).iterrows():
        print(f"  {row['processed_domain']} (Prob: {row['pred_prob']: .4f})")
        
    print("\nRepresentative Missed Banjori:")
    for _, row in missed.head(5).iterrows():
        print(f"  {row['processed_domain']} (Prob: {row['pred_prob']: .4f})")
        
    # Let's do some feature analysis on them
    def analyze_group(group, name):
        if len(group) == 0:
            return
        lengths = group['processed_domain'].str.len()
        vowels = group['processed_domain'].apply(lambda x: sum(1 for c in x if c in 'aeiou')) / lengths
        entropies = group['processed_domain'].apply(compute_entropy)
        
        print(f"\n{name} Stats (Median):")
        print(f"  Length: {lengths.median():.2f}")
        print(f"  Vowel Ratio: {vowels.median():.4f}")
        print(f"  Entropy: {entropies.median():.4f}")
        
    analyze_group(df_benign, "All Benign")
    analyze_group(df_banjori, "All Banjori")
    analyze_group(detected, "Detected Banjori")
    analyze_group(missed, "Missed Banjori")

if __name__ == "__main__":
    main()
