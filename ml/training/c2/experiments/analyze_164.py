import pandas as pd
import numpy as np
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
from src.c2.detector import C2Detector
from src.c2.features import C2_FEATURE_NAMES

def get_dists(series):
    return f"Median: {series.median():.4f} | Mean: {series.mean():.4f} | Min: {series.min():.4f} | Max: {series.max():.4f}"

def main():
    print("Loading features...")
    df = pd.read_csv(PROJECT_ROOT / "data" / "processed" / "c2_features.csv")
    
    detector = C2Detector.load(str(PROJECT_ROOT / "models" / "c2" / "c2_model.joblib"))
    wa, wp, wr, wi = 0.70, 0.10, 0.10, 0.10
    
    print("Calculating scores...")
    anom_scores = []
    per_scores = []
    rep_scores = []
    iat_scores = []
    conf_scores = []
    
    for _, row in df.iterrows():
        feat = {k: row[k] if pd.notnull(row[k]) else 0.0 for k in C2_FEATURE_NAMES}
        if feat.get("connection_count", 0) < 3:
            anom = 0.0
            per = 0.0
            rep = 0.0
            iat_reg = 0.0
            conf = 0.0
        else:
            vec = np.array([[feat.get(k, 0.0) for k in C2_FEATURE_NAMES]])
            anom = -float(detector._model.score_samples(vec)[0])
            per = feat.get("periodicity_score", 0.0)
            rep = detector._compute_repetition_score(feat)
            iat_cv = feat.get("iat_cv", 1.0)
            iat_reg = max(0.0, 1.0 - min(iat_cv, 2.0) / 2.0)
            conf = wa * anom + wp * per + wr * rep + wi * iat_reg
            
        anom_scores.append(anom)
        per_scores.append(per)
        rep_scores.append(rep)
        iat_scores.append(iat_reg)
        conf_scores.append(conf)
        
    df["anom"] = anom_scores
    df["per"] = per_scores
    df["rep"] = rep_scores
    df["iat"] = iat_scores
    df["conf"] = conf_scores
    
    host164 = df[(df["label"] == "benign") & (df["src_ip"] == "147.32.84.164")]
    other_benign = df[(df["label"] == "benign") & (df["src_ip"] != "147.32.84.164")]
    det_c2 = df[(df["label"] == "c2") & (df["conf"] >= 0.45)]
    
    print("\n================ HOST 147.32.84.164 WINDOWS ================")
    print(f"Total windows: {len(host164)}")
    print("Windows by scenario:")
    print(host164["scenario"].value_counts())
    
    print("\n================ COMPARISON: CONNECTION COUNT ================")
    print(f"Host 164    : {get_dists(host164['connection_count'])}")
    print(f"Other Benign: {get_dists(other_benign['connection_count'])}")
    print(f"Detected C2 : {get_dists(det_c2['connection_count'])}")
    
    print("\n================ COMPARISON: DETECTOR SCORES ================")
    print("ANOMALY SCORE:")
    print(f"Host 164    : {get_dists(host164['anom'])}")
    print(f"Other Benign: {get_dists(other_benign['anom'])}")
    print(f"Detected C2 : {get_dists(det_c2['anom'])}")
    
    print("\nFINAL CONFIDENCE:")
    print(f"Host 164    : {get_dists(host164['conf'])}")
    print(f"Other Benign: {get_dists(other_benign['conf'])}")
    print(f"Detected C2 : {get_dists(det_c2['conf'])}")
    
    print("\nPERIODICITY SCORE:")
    print(f"Host 164    : {get_dists(host164['per'])}")
    print(f"Other Benign: {get_dists(other_benign['per'])}")
    print(f"Detected C2 : {get_dists(det_c2['per'])}")

    print("\nREPETITION SCORE:")
    print(f"Host 164    : {get_dists(host164['rep'])}")
    print(f"Other Benign: {get_dists(other_benign['rep'])}")
    print(f"Detected C2 : {get_dists(det_c2['rep'])}")

    print("\nIAT REGULARITY SCORE:")
    print(f"Host 164    : {get_dists(host164['iat'])}")
    print(f"Other Benign: {get_dists(other_benign['iat'])}")
    print(f"Detected C2 : {get_dists(det_c2['iat'])}")
    
    print("\n================ COMPARISON: 13 FEATURES ================")
    for f in C2_FEATURE_NAMES:
        print(f"\nFeature: {f}")
        print(f"Host 164    : {get_dists(host164[f])}")
        print(f"Other Benign: {get_dists(other_benign[f])}")
        print(f"Detected C2 : {get_dists(det_c2[f])}")
        
    print("\n================ RAW BINETFLOW INSPECTION FOR 147.32.84.164 ================")
    # Search the raw binetflow files for this IP as source
    raw_dir = PROJECT_ROOT / "data" / "raw" / "ctu-13"
    records = []
    
    for f in raw_dir.glob("*.binetflow"):
        print(f"Reading {f.name}...")
        try:
            chunk_iter = pd.read_csv(f, chunksize=100000)
            for chunk in chunk_iter:
                # Assuming standard CTU-13 columns: StartTime, SrcAddr, DstAddr, Dur, TotPkts, TotBytes, Label...
                if "SrcAddr" in chunk.columns:
                    src_col = "SrcAddr"
                    dst_col = "DstAddr"
                elif "SrcIP" in chunk.columns:
                    src_col = "SrcIP"
                    dst_col = "DstIP"
                else:
                    src_col = [c for c in chunk.columns if "Src" in c][0]
                    dst_col = [c for c in chunk.columns if "Dst" in c][0]
                    
                match = chunk[chunk[src_col] == "147.32.84.164"]
                if not match.empty:
                    records.append(match)
        except Exception as e:
            print(f"Failed to read {f.name}: {e}")
            
    if records:
        raw_df = pd.concat(records)
        print(f"Found {len(raw_df)} total raw flows for 147.32.84.164")
        
        dst_counts = raw_df[dst_col].value_counts()
        print(f"Unique destinations: {len(dst_counts)}")
        print("Top 5 Destinations:")
        print(dst_counts.head(5))
        
        # Check bytes
        if "TotBytes" in raw_df.columns:
            print(f"\nTotal Bytes (orig+resp) -> {get_dists(raw_df['TotBytes'])}")
        elif "SrcBytes" in raw_df.columns:
            print(f"\nSrc Bytes -> {get_dists(raw_df['SrcBytes'])}")
            
        if "Dur" in raw_df.columns:
            print(f"Duration -> {get_dists(raw_df['Dur'])}")
            
        print("\nDestination IP Breakdown (Top 3):")
        for ip in dst_counts.head(3).index:
            sub = raw_df[raw_df[dst_col] == ip]
            print(f"  Dest {ip}: {len(sub)} flows")
            if "TotBytes" in sub.columns:
                print(f"    Bytes: Median={sub['TotBytes'].median():.1f}, Mean={sub['TotBytes'].mean():.1f}, Std={sub['TotBytes'].std():.1f}")
            if "Dur" in sub.columns:
                print(f"    Dur  : Median={sub['Dur'].median():.1f}, Mean={sub['Dur'].mean():.1f}")
    else:
        print("No raw flows found.")

if __name__ == "__main__":
    main()
