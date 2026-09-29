import pandas as pd
import numpy as np
import joblib
from pathlib import Path
from scipy.stats import iqr

PROJECT_ROOT = Path(__file__).resolve().parent.parent

FEATURES = [
    'domain_length', 'full_query_length', 'entropy', 'normalized_entropy',
    'digit_ratio', 'letter_ratio', 'vowel_ratio', 'consonant_ratio',
    'bigram_score', 'trigram_score'
]

def get_stats(group):
    res = {}
    for f in FEATURES:
        res[f"{f}_median"] = group[f].median()
        res[f"{f}_iqr"] = iqr(group[f])
    return pd.Series(res)

def main():
    df = pd.read_csv(PROJECT_ROOT / "data" / "processed" / "dga_features.csv")
    
    # Load model to get predictions
    model_data = joblib.load(PROJECT_ROOT / "models" / "dga" / "dga_model.joblib")
    model = model_data["model"]
    
    X = df[FEATURES].fillna(0.0).values
    df['predicted'] = model.predict(X)
    
    families = ["tranco_benign", "qakbot", "corebot", "ramdo", "banjori", "simda", "nymaim", "dircrypt"]
    df_fams = df[df['family'].isin(families)]
    
    stats = df_fams.groupby('family').apply(get_stats).reset_index()
    
    print("=== MEDIAN AND IQR ===")
    for fam in families:
        fam_stats = stats[stats['family'] == fam].iloc[0]
        print(f"\nFamily: {fam}")
        for f in FEATURES:
            print(f"  {f}: {fam_stats[f+'_median']:.2f} (IQR: {fam_stats[f+'_iqr']:.2f})")
            
    print("\n=== REPRESENTATIVE EXAMPLES ===")
    for fam in families:
        fam_df = df[df['family'] == fam]
        if not fam_df.empty:
            example = fam_df.iloc[0]
            print(f"\n{fam} Example: '{example['domain']}'")
            for f in FEATURES:
                print(f"  {f}: {example[f]:.2f}")
                
    # Detect vs Missed analysis
    print("\n=== DETECTED VS MISSED ===")
    malicious = df[df['label'] == 1]
    detected = malicious[malicious['predicted'] == 1]
    missed = malicious[malicious['predicted'] == 0]
    
    print(f"Total Malicious: {len(malicious)}")
    print(f"Detected: {len(detected)}")
    print(f"Missed: {len(missed)}")
    
    print("\nDetected (Median):")
    if not detected.empty:
        for f in FEATURES:
            print(f"  {f}: {detected[f].median():.2f}")
    
    print("\nMissed (Median):")
    if not missed.empty:
        for f in FEATURES:
            print(f"  {f}: {missed[f].median():.2f}")

if __name__ == "__main__":
    main()
