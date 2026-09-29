import pandas as pd
import numpy as np
from pathlib import Path
import sys
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score
from sklearn.model_selection import GroupShuffleSplit
import warnings
warnings.filterwarnings("ignore")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
from src.c2.detector import C2Detector
from src.c2.features import C2_FEATURE_NAMES

def main():
    print("Loading features...")
    df = pd.read_csv(PROJECT_ROOT / "data" / "processed" / "c2_features.csv")
    
    # Recreate splits
    df_benign = df[df["label"] == "benign"]
    df_c2 = df[df["label"] == "c2"]

    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_idx, test_idx = next(gss.split(df_benign, groups=df_benign['src_ip']))
    train_benign = df_benign.iloc[train_idx]
    test_benign = df_benign.iloc[test_idx]

    df_test_final = pd.concat([test_benign, df_c2])

    gss_c2 = GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=99)
    val_c2_idx, _ = next(gss_c2.split(df_c2, groups=df_c2['src_ip']))
    val_c2 = df_c2.iloc[val_c2_idx]

    gss_val = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=99)
    _, val_benign_idx = next(gss_val.split(train_benign, groups=train_benign['src_ip']))
    val_benign = train_benign.iloc[val_benign_idx]

    df_val = pd.concat([val_benign, val_c2])
    
    detector = C2Detector.load(str(PROJECT_ROOT / "models" / "c2" / "c2_model.joblib"))
    wa, wp, wr, wi = 0.70, 0.10, 0.10, 0.10
    
    def process(dataset):
        records = []
        for _, row in dataset.iterrows():
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
                
            records.append({
                "src_ip": row["src_ip"],
                "scenario": row["scenario"],
                "label": 1 if row["label"] == "c2" else 0,
                "anom": anom,
                "per": per,
                "rep": rep,
                "iat": iat_reg,
                "conf": conf
            })
        return pd.DataFrame(records)

    val_df = process(df_val)
    test_df = process(df_test_final)

    def eval_rule(df_in, rule_mask, name):
        preds = rule_mask.astype(int)
        cm = confusion_matrix(df_in["label"], preds, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()
        prec = precision_score(df_in["label"], preds, zero_division=0)
        rec = recall_score(df_in["label"], preds, zero_division=0)
        f1 = f1_score(df_in["label"], preds, zero_division=0)
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        return f"{name:<50} | TP:{tp:<3} | TN:{tn:<3} | FP:{fp:<3} | FN:{fn:<3} | P:{prec:.4f} | R:{rec:.4f} | F1:{f1:.4f} | FPR:{fpr:.4f}"

    print("================ VALIDATION SET ================")
    
    # A) Current
    print(eval_rule(val_df, val_df["conf"] >= 0.45, "A) Conf >= 0.45"))
    
    # B) Anomaly + Periodicity
    for ta in [0.4, 0.45, 0.5]:
        for tp in [0.1, 0.3, 0.5]:
            mask = (val_df["anom"] >= ta) & (val_df["per"] >= tp)
            print(eval_rule(val_df, mask, f"B) Anom>={ta} AND Per>={tp}"))
            
    # C) Anomaly + IAT
    print("-" * 20)
    for ta in [0.4, 0.45, 0.5]:
        for ti in [0.1, 0.3, 0.5]:
            mask = (val_df["anom"] >= ta) & (val_df["iat"] >= ti)
            print(eval_rule(val_df, mask, f"C) Anom>={ta} AND IAT>={ti}"))

    # D) Anomaly + Any Signal
    print("-" * 20)
    for ta in [0.4, 0.45, 0.5]:
        for ts in [0.1, 0.3, 0.5]:
            mask = (val_df["anom"] >= ta) & ((val_df["per"] >= ts) | (val_df["iat"] >= ts) | (val_df["rep"] >= ts))
            print(eval_rule(val_df, mask, f"D) Anom>={ta} AND (Per|IAT|Rep)>={ts}"))
            
    
    print("\n================ TEST SET ANALYSIS ================")
    # Apply most informative to Test Set
    rules_to_test = {
        "Base (Conf>=0.45)": test_df["conf"] >= 0.45,
        "Anom>=0.45 & Per>=0.1": (test_df["anom"] >= 0.45) & (test_df["per"] >= 0.1),
        "Anom>=0.45 & IAT>=0.3": (test_df["anom"] >= 0.45) & (test_df["iat"] >= 0.3),
        "Anom>=0.45 & AnySignal>=0.1": (test_df["anom"] >= 0.45) & ((test_df["per"] >= 0.1) | (test_df["iat"] >= 0.1) | (test_df["rep"] >= 0.1))
    }
    
    for name, mask in rules_to_test.items():
        print("\n" + eval_rule(test_df, mask, f"TEST: {name}"))
        
        preds = mask.astype(int)
        
        # False Positives Analysis (especially 147.32.84.164)
        fps = test_df[(test_df["label"] == 0) & (preds == 1)]
        host164_fps = fps[fps["src_ip"] == "147.32.84.164"]
        
        print(f"  Total FPs: {len(fps)}")
        print(f"  Host 147.32.84.164 FPs left: {len(host164_fps)} (Original was 179)")
        
        # FN Analysis (Lost C2)
        fns = test_df[(test_df["label"] == 1) & (preds == 0)]
        print(f"  Lost C2 Windows (FN): {len(fns)} / 560")
        
        if len(fns) > 0:
            lost_hosts = fns["src_ip"].value_counts()
            print("  Lost C2 Hosts (Top 5):")
            for h, c in lost_hosts.head(5).items():
                print(f"    - {h}: {c} windows")

if __name__ == "__main__":
    main()
