from typing import List, Dict, Any
from src.ingestion.parser import NetworkEvent


class DDoSFeatureAdapter:
    """
    Extracts volumetric and flow rate features from a DDoS sliding time window.
    """

    def extract_features(self, events: List[NetworkEvent], window_seconds: float = 5.0) -> Dict[str, Any]:
        if not events:
            return {
                "pps": 0.0,
                "bps": 0.0,
                "syn_ratio": 0.0,
                "unique_dst_ips": 0,
                "avg_pkt_size": 0.0,
                "flow_count": 0,
                "total_pkts": 0,
                "total_bytes": 0,
            }

        total_pkts = sum(e.orig_pkts + e.resp_pkts for e in events)
        total_bytes = sum(e.orig_bytes + e.resp_bytes for e in events)
        syn_count = sum(1 for e in events if e.conn_state in ("S0", "S1", "SH", "SHR"))
        unique_dst_ips = len({e.dst_ip for e in events})
        
        actual_window = max(window_seconds, 0.1)

        pps = total_pkts / actual_window
        bps = (total_bytes * 8) / actual_window
        syn_ratio = syn_count / len(events) if events else 0.0
        avg_pkt_size = total_bytes / max(total_pkts, 1)

        return {
            "pps": float(pps),
            "bps": float(bps),
            "syn_ratio": float(syn_ratio),
            "unique_dst_ips": unique_dst_ips,
            "avg_pkt_size": float(avg_pkt_size),
            "flow_count": len(events),
            "total_pkts": total_pkts,
            "total_bytes": total_bytes,
        }
