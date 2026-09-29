import os
from typing import Dict, Any, List
from src.ingestion.parser import NetworkEvent
from src.c2.detector import C2Detector

class RealC2Adapter:
    def __init__(self):
        # We find the models path relative to this file
        current_dir = os.path.dirname(os.path.abspath(__file__))
        model_path = os.path.join(current_dir, "../../../../../models/c2/c2_model.joblib")
        model_path = os.path.abspath(model_path)
        
        if os.path.exists(model_path):
            self.detector = C2Detector.load(model_path)
        else:
            self.detector = C2Detector()

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
