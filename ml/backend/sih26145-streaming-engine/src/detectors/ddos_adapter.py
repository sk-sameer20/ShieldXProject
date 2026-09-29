from typing import Dict, Any, List
from src.ingestion.parser import NetworkEvent
from src.ddos.ddos_detector import detect_ddos

class RealDDoSAdapter:
    def predict(self, events: List[NetworkEvent]) -> Dict[str, Any]:
        records = [e.model_dump() for e in events]
        result = detect_ddos(records)
        
        if result and result.get("confidence", 0) > 50:
            return {
                "detected": True,
                "score": result.get("confidence", 0) / 100.0,
                "evidence": result.get("evidence", []),
                "model_version": "ddos_person2",
            }
        
        return {
            "detected": False,
            "score": 0.0,
            "evidence": [],
            "model_version": "ddos_person2",
        }
