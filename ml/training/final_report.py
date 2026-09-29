import json
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

def generate_report():
    print("="*60)
    print(" C2 REAL DATASET PREPARATION REPORT (CTU-13)")
    print("="*60)
    
    c2_path = PROJECT_ROOT / "data" / "processed" / "c2_features.csv"
    metrics_path = PROJECT_ROOT / "data" / "processed" / "c2_metrics.json"
    
    if not c2_path.exists() or not metrics_path.exists():
        print("[!] ERROR: Feature CSV or metrics JSON not found.")
        return

    with open(metrics_path, "r") as f:
        metrics = json.load(f)

    # User requested specific items
    print("1. Raw flows:", f"{metrics['raw_rows']:,}")
    print("2. Filtered flows:", f"{metrics['filtered_rows']:,}")
    print("3. Total temporal windows:", f"{metrics['windows_generated']:,}")
    print("4. Benign windows:", f"{metrics['windows_benign']:,}")
    print("5. C2 windows:", f"{metrics['windows_malicious']:,}")
    print("6. Windows dropped for <3 connections:", f"{metrics['dropped_small_windows']:,}")
    print("7. C2 windows dropped for <3 connections:", f"{metrics['dropped_c2_small_windows']:,}")
    
    print("\n8. Windows per C2 host:")
    if 'c2_hosts' in metrics:
        for ip, count in metrics['c2_hosts'].items():
            print(f"   - {ip}: {count:,}")
            
    print("\n9. Windows per Benign host:")
    if 'benign_hosts' in metrics:
        for ip, count in metrics['benign_hosts'].items():
            print(f"   - {ip}: {count:,}")
            
    print(f"\n10. Unique src_ip (C2): {len(metrics.get('c2_hosts', {}))}")
    print(f"11. Unique src_ip (Benign): {len(metrics.get('benign_hosts', {}))}")
    
    print("\n12. Flow counts per window:")
    print(f"   - Windows with 1 flow: {metrics.get('windows_1_flow', 0):,}")
    print(f"   - Windows with 2 flows: {metrics.get('windows_2_flows', 0):,}")
    print(f"   - Windows with >=3 flows: {metrics.get('windows_3plus_flows', 0):,}")
    
    print("\n10. Connections per window (Min/Median/Max):")
    print(f"   - Min: {metrics.get('window_conn_min', 0)}")
    print(f"   - Median: {metrics.get('window_conn_median', 0)}")
    print(f"   - Max: {metrics.get('window_conn_max', 0)}")

    print("\n14. Missing-value handling:")
    print(f"   - Missing values in CSV: {metrics['missing_values']}")
    print("   - Strategy: The feature extractor outputs hardcoded defaults (e.g., 0.0 for IAT, 0.5 for byte_ratio) instead of NaN when flows are insufficient.")
    
    print(f"\n15. Final feature count: {metrics['final_feature_count']}")
    
    df_c2 = pd.read_csv(c2_path)
    
    print("\n16. Train / Test Host & Window Counts (GroupShuffleSplit validation):")
    df_benign = df_c2[df_c2['label'] == 'benign']
    df_malicious = df_c2[df_c2['label'] == 'c2']
    
    if not df_benign.empty:
        # 80/20 split of Benign hosts
        gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
        train_idx, test_idx = next(gss.split(df_benign, groups=df_benign['src_ip']))
        train_benign = df_benign.iloc[train_idx]
        test_benign = df_benign.iloc[test_idx]
        
        train_count = len(train_benign)
        test_count = len(test_benign) + len(df_malicious)
        
        train_ips = set(train_benign['src_ip'])
        test_benign_ips = set(test_benign['src_ip'])
        c2_ips = set(df_malicious['src_ip'])
        test_all_ips = test_benign_ips | c2_ips
        
        overlap = train_ips.intersection(test_all_ips)
        
        print(f"   - Train (Benign only): {train_count:,} windows")
        print(f"   - Test (Mixed): {test_count:,} windows ({len(test_benign):,} benign, {len(df_malicious):,} c2)")
        print(f"   - Train host count (Unique src_ip): {len(train_ips)}")
        print(f"   - Test host count (Unique src_ip): {len(test_all_ips)}")
        print(f"   - src_ip overlap between Train/Test: {len(overlap)}")
        if len(overlap) == 0:
            print("   - [OK] ZERO src_ip overlap confirmed.")
        else:
            print("   - [!] WARNING: Data leakage detected!")
    
    print("\n" + "="*60)

if __name__ == "__main__":
    generate_report()
