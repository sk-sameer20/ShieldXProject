from typing import Dict, Any, List
from src.ingestion.parser import NetworkEvent
from src.dns.tunnel import DNSTunnelDetector

class RealDNSTunnelAdapter:
    def __init__(self):
        self.detector = DNSTunnelDetector()

    def predict(self, events: List[NetworkEvent]) -> Dict[str, Any]:
        if not events:
            return {"detected": False, "score": 0.0, "evidence": [], "model_version": self.detector.MODEL_VERSION}
            
        src_ip = events[0].src_ip
        records = [e.model_dump() for e in events]
        alert = self.detector.predict_from_records(records, src_ip=src_ip)
        
        return {
            "detected": alert.detected,
            "score": alert.confidence,
            "evidence": alert.evidence,
            "model_version": alert.model_version,
        }
