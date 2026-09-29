import pandas as pd
import numpy as np
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

def main():
    df = pd.read_csv(PROJECT_ROOT / "data" / "processed" / "dga_features.csv")
    
    print("=== 1. Dataset composition ===")
    print(f"Total domains: {len(df)}")
    print(f"Benign count: {len(df[df['label'] == 0])}")
    print(f"Malicious count: {len(df[df['label'] == 1])}")
    print("Family counts:")
    print(df['family'].value_counts())
    
    print("\n=== 2. Deduplication ===")
    print(f"Duplicate domain counts (in csv): {df['domain'].duplicated().sum()}")
    
    print("\n=== 3. Current feature set ===")
    feature_cols = [c for c in df.columns if c not in ["domain", "label", "family"]]
    print(f"Features ({len(feature_cols)}): {feature_cols}")
    
    print("\n=== 4. Feature quality ===")
    for f in feature_cols:
        b_std = df[df['label'] == 0][f].std()
        m_std = df[df['label'] == 1][f].std()
        if b_std == 0 and m_std == 0:
            print(f"CONSTANT FEATURE: {f}")
            
    corr_matrix = df[feature_cols].corr()
    high_corr = []
    for i in range(len(feature_cols)):
        for j in range(i+1, len(feature_cols)):
            if abs(corr_matrix.iloc[i, j]) > 0.95:
                high_corr.append((feature_cols[i], feature_cols[j], corr_matrix.iloc[i, j]))
                
    if high_corr:
        print("\nHighly correlated features (>0.95):")
        for pair in high_corr:
            print(f"  {pair[0]} & {pair[1]}: {pair[2]:.3f}")
            
if __name__ == "__main__":
    main()
