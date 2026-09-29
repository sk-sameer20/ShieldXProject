import pandas as pd
import numpy as np
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Scenarios mapped to filenames
SCENARIOS = {
    "capture20110811.binetflow": "2",
    "capture20110812.binetflow": "3",
    "capture20110815.binetflow": "4",
    "capture20110817.binetflow": "9",
}

def main():
    print("Loading existing c2_features.csv...")
    existing_df = pd.read_csv(PROJECT_ROOT / "data" / "processed" / "c2_features.csv")
    
    raw_dir = PROJECT_ROOT / "data" / "raw" / "ctu-13"
    
    new_features_list = []
    
    for filename in SCENARIOS.keys():
        filepath = raw_dir / filename
        if not filepath.exists():
            continue
            
        print(f"Processing {filename}...")
        df = pd.read_csv(filepath, on_bad_lines='skip')
        
        if "Label" not in df.columns:
            continue
            
        df = df[df["Label"].notna()]
        normal_mask = df["Label"].str.contains("Normal", case=False, na=False)
        botnet_mask = df["Label"].str.contains("Botnet", case=False, na=False)
        cc_mask = df["Label"].str.contains("CC", case=False, na=False)
        c2_mask = botnet_mask & cc_mask
        
        df_filtered = df[normal_mask | c2_mask].copy()
        
        dt = pd.to_datetime(df_filtered["StartTime"], utc=True)
        df_filtered["timestamp"] = (dt - pd.Timestamp("1970-01-01", tz="UTC")).dt.total_seconds()
        df_filtered["window_id"] = (df_filtered["timestamp"] // 60) * 60
        df_filtered["src_ip"] = df_filtered["SrcAddr"].astype(str)
        df_filtered["proto"] = df_filtered["Proto"].astype(str).str.lower()
        df_filtered["dport"] = pd.to_numeric(df_filtered["Dport"], errors='coerce').fillna(-1)
        df_filtered["pkts"] = pd.to_numeric(df_filtered["TotPkts"], errors='coerce').fillna(0)
        df_filtered["state"] = df_filtered["State"].astype(str)
        
        # State mapping for success (FPA_FPA, CON)
        # CTU-13 often uses FPA_FPA for successful TCP, and CON for UDP
        # We want to check TCP success specifically
        
        def is_tcp_success(state):
            # Typical successful CTU-13 TCP states: FPA_FPA, SPA_SPA, FA_FA, etc.
            # Things with 'A' and 'P' or 'F' on both sides usually mean success.
            # 'S_' means SYN sent but no reply (e.g. S_RA, S_)
            return 1 if ("PA_" in state or "FA_" in state or "FPA_" in state) else 0

        df_filtered["tcp_success"] = df_filtered["state"].apply(is_tcp_success)
        
        grouped = df_filtered.groupby(["src_ip", "window_id"])
        
        for (src_ip, window_id), group in grouped:
            n_flows = len(group)
            if n_flows == 0:
                continue
            
            udp_count = (group["proto"] == "udp").sum()
            tcp_count = (group["proto"] == "tcp").sum()
            
            udp_ratio = udp_count / n_flows
            tcp_ratio = tcp_count / n_flows
            mean_packets = group["pkts"].mean()
            dport_53_ratio = (group["dport"] == 53).sum() / n_flows
            unique_dports = group["dport"].nunique()
            
            tcp_flows = group[group["proto"] == "tcp"]
            if len(tcp_flows) > 0:
                tcp_success_ratio = tcp_flows["tcp_success"].sum() / len(tcp_flows)
            else:
                tcp_success_ratio = 0.0 # Or NaN? 0.0 is safer
                
            new_features_list.append({
                "scenario": filename,
                "src_ip": src_ip,
                "window_id": window_id,
                "udp_ratio": udp_ratio,
                "mean_packets": mean_packets,
                "dport_53_ratio": dport_53_ratio,
                "unique_dports": unique_dports,
                "tcp_success_ratio": tcp_success_ratio
            })
            
    new_df = pd.DataFrame(new_features_list)
    print("Merging features...")
    
    # Merge with existing dataframe to get only the retained windows
    merged = pd.merge(existing_df, new_df, on=["scenario", "src_ip", "window_id"], how="inner")
    
    # Analyze
    benign = merged[merged["label"] == "benign"]
    c2 = merged[merged["label"] == "c2"]
    
    print("\n================ QUANTITATIVE VERIFICATION ================")
    features = ["udp_ratio", "mean_packets", "dport_53_ratio", "unique_dports", "tcp_success_ratio"]
    
    def q_stats(series):
        if len(series) == 0: return "N/A"
        return f"Med: {series.median():.4f} | IQR: {series.quantile(0.25):.4f} - {series.quantile(0.75):.4f}"

    for f in features:
        print(f"\n--- {f} ---")
        print(f"Benign  : {q_stats(benign[f])}")
        print(f"C2      : {q_stats(c2[f])}")
        
    print("\n================ PER HOST BEHAVIOR ================")
    
    def host_stats(df_subset):
        stats = df_subset.groupby("src_ip")[features].median()
        return stats
        
    c2_hosts = host_stats(c2)
    print("\nC2 Hosts (Median per host):")
    print(c2_hosts)
    
    b_hosts = host_stats(benign)
    print("\nTop 5 Benign Hosts (by window count):")
    b_counts = benign["src_ip"].value_counts().head(5)
    for ip in b_counts.index:
        print(f"{ip} ({b_counts[ip]} windows):")
        print(b_hosts.loc[ip])
        
if __name__ == "__main__":
    main()
