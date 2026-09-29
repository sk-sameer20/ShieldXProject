import pandas as pd
from sklearn.model_selection import train_test_split
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

def analyze_dga():
    path = PROJECT_ROOT / "data" / "processed" / "dga_features.csv"
    if not path.exists():
        print("DGA features not found.")
        return
        
    df = pd.read_csv(path)
    print("="*50)
    print(" DGA DATASET STATISTICS")
    print("="*50)
    print(f"Total samples: {len(df)}")
    print(f"Feature count (excluding labels): {len(df.columns) - 3}") # domain, label, family
    print("\nMissing values:")
    print(df.isnull().sum()[df.isnull().sum() > 0])
    
    # Duplicates based on features
    feature_cols = [c for c in df.columns if c not in ['domain', 'label', 'family']]
    duplicates = df.duplicated(subset=feature_cols).sum()
    print(f"\nDuplicate feature vectors: {duplicates}")
    
    print("\nClass Distribution:")
    print(df['label'].value_counts(normalize=True).apply(lambda x: f"{x*100:.1f}%"))
    print(f"Benign (0): {len(df[df['label']==0])}")
    print(f"Malicious (1): {len(df[df['label']==1])}")
    
    print("\nDGA Family Distribution:")
    print(df['family'].value_counts())
    
    # Train/Val/Test Split Sizes (80/10/10)
    # Using stratify on family to ensure all families are represented
    try:
        X_train, X_temp, y_train, y_temp = train_test_split(df, df['label'], test_size=0.2, stratify=df['family'], random_state=42)
        X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.5, stratify=X_temp['family'], random_state=42)
        print("\nTrain / Validation / Test Split (80/10/10 stratified by family):")
        print(f"Train: {len(X_train)} samples")
        print(f"Validation: {len(X_val)} samples")
        print(f"Test: {len(X_test)} samples")
    except Exception as e:
        print(f"\nCould not stratify split: {e}")
        
    print("\nPreprocessing exclusions:")
    print("- Only second-level domains analyzed (subdomains stripped if present).")
    print("- Domains resolving to empty strings dropped.")

def analyze_c2():
    path = PROJECT_ROOT / "data" / "processed" / "c2_features.csv"
    if not path.exists():
        print("\nC2 features not found.")
        return
        
    df = pd.read_csv(path)
    print("\n" + "="*50)
    print(" C2 DATASET STATISTICS")
    print("="*50)
    print(f"Total samples (Host-level windows): {len(df)}")
    print(f"Feature count (excluding labels): {len(df.columns) - 2}") # src_ip, label
    
    print("\nMissing values:")
    print(df.isnull().sum()[df.isnull().sum() > 0])
    
    feature_cols = [c for c in df.columns if c not in ['src_ip', 'label']]
    duplicates = df.duplicated(subset=feature_cols).sum()
    print(f"\nDuplicate feature vectors: {duplicates}")
    
    print("\nClass Distribution:")
    if not df.empty:
        print(df['label'].value_counts(normalize=True).apply(lambda x: f"{x*100:.1f}%"))
        print(f"Benign: {len(df[df['label']=='benign'])}")
        print(f"Malicious (C2): {len(df[df['label']=='c2'])}")
    else:
        print("Empty dataset.")
        
    print("\nC2 Scenario Distribution:")
    print("For this demonstration run (due to official CTU-13 404), scenarios are simulated.")
    print("When real CSVs are placed, they map as:")
    print("Scenario 2: Neris")
    print("Scenario 3: Rbot")
    print("Scenario 4: Virut")
    print("Scenario 9: Neris")

    # Train/Val/Test for Isolation Forest (Unsupervised)
    # Train is ONLY benign. Val/Test contains both.
    benign_df = df[df['label'] == 'benign']
    malicious_df = df[df['label'] == 'c2']
    
    if len(benign_df) > 1 and len(malicious_df) > 0:
        # Split benign 80/20. 80 for train, 20 for test.
        train_benign, test_benign = train_test_split(benign_df, test_size=0.2, random_state=42)
        # Test gets 20% of benign + ALL malicious
        test_df = pd.concat([test_benign, malicious_df])
        print("\nTrain / Test Split (Unsupervised Setup):")
        print(f"Train (Benign Only): {len(train_benign)} samples")
        print(f"Test (Mixed): {len(test_df)} samples ({len(test_benign)} benign, {len(malicious_df)} C2)")
    else:
        print("\nNot enough data for a realistic train/test split representation.")
        
    print("\nPreprocessing exclusions:")
    print("- 'Background' traffic dropped.")
    print("- Groups with < 3 connections dropped.")
    print("- Only Botnet labels containing 'CC' retained for malicious class.")

if __name__ == "__main__":
    analyze_dga()
    analyze_c2()
