"""
training/dga/prepare_dataset.py — Build DGA feature CSV from real datasets.

Downloads Tranco top 1M for benign domains.
Executes baderj generators for DGA domains.
Extracts features and builds the training dataset.

Outputs:
    data/processed/dga_features.csv
"""

from __future__ import annotations

import io
import os
import sys
import zipfile
import urllib.request
import subprocess
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.dns.features import extract_domain_features, DGA_FEATURE_NAMES

OUTPUT_PATH = PROJECT_ROOT / "data" / "processed" / "dga_features.csv"
RAW_DIR = PROJECT_ROOT / "data" / "raw"
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"

DGA_FAMILIES = {
    "corebot": ["python", "dga.py", "-d", "2026-09-22"],
    "dircrypt": ["python", "dga.py", "12345"],
    "simda": ["python", "dga.py"],
    "ramdo": ["python", "dga.py"],
    "banjori": ["python", "dga.py"],
    "qakbot": ["python", "dga.py", "-d", "2026-09-22"],
    "nymaim": ["python", "dga.py", "-d", "2026-09-22"]
}

def download_tranco(dest_dir: Path) -> pd.DataFrame:
    dest_dir.mkdir(parents=True, exist_ok=True)
    csv_path = dest_dir / "top-1m.csv"
    
    if not csv_path.exists():
        print("  [DL] Downloading Tranco top-1m...")
        # Download ZIP into memory and extract
        response = urllib.request.urlopen(TRANCO_URL)
        with zipfile.ZipFile(io.BytesIO(response.read())) as z:
            z.extractall(dest_dir)
        print("  [OK] Tranco downloaded and extracted.")
    else:
        print("  [OK] Tranco CSV already exists.")

    print("  [*] Loading benign domains...")
    # Tranco CSV format: rank,domain
    df = pd.read_csv(csv_path, names=["rank", "domain"], nrows=50000) # Use top 50,000 for benign
    df["label"] = 0
    df["family"] = "tranco_benign"
    return df

def generate_dga(repo_dir: Path) -> pd.DataFrame:
    rows = []
    print("  [*] Generating DGA domains using baderj generators...")
    
    for family, cmd in DGA_FAMILIES.items():
        family_dir = repo_dir / family
        if not family_dir.exists():
            print(f"  [!] Skipping {family} (directory not found)")
            continue
            
        print(f"      - Running {family}...")
        try:
            # Run generator
            result = subprocess.run(cmd, cwd=family_dir, capture_output=True, text=True, check=False)
            domains = [d.strip() for d in result.stdout.splitlines() if d.strip() and "." in d]
            
            # Fallback if generator failed or output nothing
            if not domains:
                print(f"        Warning: {family} generated 0 domains. Error: {result.stderr.strip()}")
                continue
                
            # Limit to 5000 per family to balance dataset somewhat
            domains = domains[:5000]
            for d in domains:
                rows.append({"domain": d, "label": 1, "family": family})
            print(f"        -> {len(domains)} domains")
        except Exception as e:
            print(f"        Error running {family}: {e}")
            
    return pd.DataFrame(rows)

def main() -> None:
    print("=" * 60)
    print("  DGA Dataset Preparation (Tranco + baderj)")
    print("=" * 60)

    # 1. Tranco Benign
    tranco_dir = RAW_DIR / "tranco"
    df_benign = download_tranco(tranco_dir)

    # 2. baderj DGA
    dga_repo = RAW_DIR / "baderj_dga"
    if not dga_repo.exists():
        print("  [!] Error: baderj_dga repo not found. Please clone it first.")
        print("      git clone https://github.com/baderj/domain_generation_algorithms.git data/raw/baderj_dga")
        sys.exit(1)
        
    df_dga = generate_dga(dga_repo)

    if df_dga.empty:
        print("  [!] Error: No DGA domains generated.")
        sys.exit(1)

    df_all = pd.concat([df_benign, df_dga], ignore_index=True)
    
    print(f"\n  [*] Total domains before deduplication: {len(df_all)}")
    df_all_dedup = df_all.drop_duplicates(subset=['domain'])
    print(f"  [*] Total domains after deduplication: {len(df_all_dedup)}")
    print(f"  [*] Removed {len(df_all) - len(df_all_dedup)} duplicate domain strings.")
    
    print(f"\n  [*] Extracting features for {len(df_all_dedup)} domains... (this may take a minute)")
    
    # We will use records to build features
    feature_rows = []
    for _, row in df_all_dedup.iterrows():
        domain = row["domain"]
        features = extract_domain_features(domain)
        features["domain"] = domain
        features["label"] = row["label"]
        features["family"] = row["family"]
        feature_rows.append(features)

    df_features = pd.DataFrame(feature_rows)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    df_features.to_csv(OUTPUT_PATH, index=False)

    print(f"\n  [OK] Saved {len(df_features)} rows -> {OUTPUT_PATH}")
    print("\n  DATASET STATISTICS:")
    print("  Class Distribution:")
    print(df_features['label'].value_counts().to_string())
    print("\n  Family Distribution:")
    print(df_features['family'].value_counts().to_string())
    print(f"\n  Total features per row: {len(DGA_FEATURE_NAMES)}")
    print("=" * 60)

if __name__ == "__main__":
    main()
