import numpy as np
from typing import List, Dict, Any
from src.ingestion.parser import NetworkEvent


class C2FeatureAdapter:
    """
    Extracts beaconing regularity and payload features from a C2 sliding time window.
    """

    def extract_features(self, events: List[NetworkEvent], window_seconds: float = 60.0) -> Dict[str, Any]:
        if not events:
            return {
                "beacon_regularity_stddev": 999.0,
                "beacon_regularity_score": 0.0,
                "avg_payload_bytes": 0.0,
                "payload_stddev": 0.0,
                "unique_dst_ips": 0,
                "flow_count": 0,
                "avg_interarrival_seconds": 0.0,
            }

        # Sort events by timestamp
        timestamps = sorted([e.timestamp for e in events])
        payloads = [e.orig_bytes for e in events]
        unique_dst_ips = len({e.dst_ip for e in events})

        if len(timestamps) > 1:
            interarrivals = np.diff(timestamps)
            mean_ia = float(np.mean(interarrivals))
            stddev_ia = float(np.std(interarrivals))
            # Inverse score: lower stddev indicates high regularity (beaconing)
            # Regularity score between 0.0 (irregular) and 1.0 (highly periodic)
            regularity_score = 1.0 / (1.0 + stddev_ia) if mean_ia > 0 else 0.0
        else:
            mean_ia = 0.0
            stddev_ia = 999.0
            regularity_score = 0.0

        avg_payload = float(np.mean(payloads)) if payloads else 0.0
        payload_std = float(np.std(payloads)) if len(payloads) > 1 else 0.0

        return {
            "beacon_regularity_stddev": float(stddev_ia),
            "beacon_regularity_score": float(regularity_score),
            "avg_payload_bytes": float(avg_payload),
            "payload_stddev": float(payload_std),
            "unique_dst_ips": unique_dst_ips,
            "flow_count": len(events),
            "avg_interarrival_seconds": float(mean_ia),
        }
