import pandas as pd
import numpy as np
from pathlib import Path

def main():
    csv_path = Path(__file__).resolve().parent.parent / "data" / "processed" / "c2_features.csv"
    df = pd.read_csv(csv_path)

    print("=== Periodicity Score Analysis ===")
    
    # 1. Non-zero scores
    non_zero = df[df["periodicity_score"] > 0]
    print(f"Total Windows: {len(df)}")
    print(f"Non-zero Periodicity Scores: {len(non_zero)} ({len(non_zero)/len(df)*100:.2f}%)")
    
    # 2. Distributions
    benign = df[df["label"] == "benign"]
    c2 = df[df["label"] == "c2"]
    
    print("\nBenign Distribution:")
    print(f"  Count: {len(benign)}")
    print(f"  Median: {benign['periodicity_score'].median():.4f}")
    print(f"  IQR: {benign['periodicity_score'].quantile(0.25):.4f} - {benign['periodicity_score'].quantile(0.75):.4f}")
    print(f"  Zeros: {(benign['periodicity_score'] == 0).sum()} / {len(benign)}")
    
    print("\nC2 Distribution:")
    print(f"  Count: {len(c2)}")
    print(f"  Median: {c2['periodicity_score'].median():.4f}")
    print(f"  IQR: {c2['periodicity_score'].quantile(0.25):.4f} - {c2['periodicity_score'].quantile(0.75):.4f}")
    print(f"  Zeros: {(c2['periodicity_score'] == 0).sum()} / {len(c2)}")
    
    # 3. Per C2 Host
    print("\nPer C2-Host Distribution:")
    for src_ip, group in c2.groupby("src_ip"):
        nz = (group['periodicity_score'] > 0).sum()
        med = group['periodicity_score'].median()
        print(f"  {src_ip}: {len(group)} windows | Median: {med:.4f} | Non-zero: {nz}")
        
    # 4. Correlation with connection_count
    b_corr = benign["periodicity_score"].corr(benign["connection_count"])
    c2_corr = c2["periodicity_score"].corr(c2["connection_count"])
    print(f"\nCorrelation with connection_count:")
    print(f"  Benign: {b_corr:.4f}")
    print(f"  C2:     {c2_corr:.4f}")
    
    # 5. Examples where it should be detectable but is 0
    # C2 windows with connection_count >= 5 (i.e., at least 4 IATs, which is the min required in features.py) 
    # but periodicity == 0
    theoretically_detectable = c2[(c2["connection_count"] >= 5) & (c2["periodicity_score"] == 0)]
    print(f"\nC2 Windows with connection_count >= 5 but periodicity == 0: {len(theoretically_detectable)} / {len(c2[c2['connection_count'] >= 5])}")
    
    if len(theoretically_detectable) > 0:
        print("\nExamples:")
        print(theoretically_detectable[["src_ip", "connection_count", "iat_mean", "iat_std", "periodicity_score"]].head(10).to_string())

if __name__ == "__main__":
    main()
