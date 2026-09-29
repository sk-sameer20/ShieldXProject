from typing import Dict, Any, List
from src.ingestion.parser import NetworkEvent
from src.dga.inference import run_dga_detection

class RealDGAAdapter:
    def predict(self, events: List[NetworkEvent]) -> Dict[str, Any]:
        # DGA operates on unique queries
        queries = {e.query for e in events if e.query}
        if not queries:
            return {"detected": False, "score": 0.0, "evidence": [], "model_version": "dga_panel_v8"}
        
        worst_alert = None
        for q in queries:
            alert = run_dga_detection(domain=q)
            if alert.detected:
                if worst_alert is None or alert.confidence > worst_alert.confidence:
                    worst_alert = alert
                    
        if worst_alert and worst_alert.detected:
            return {
                "detected": True,
                "score": worst_alert.confidence,
                "evidence": worst_alert.evidence,
                "model_version": worst_alert.model_version,
            }
            
        return {
            "detected": False,
            "score": 0.0,
            "evidence": [],
            "model_version": "dga_panel_v8",
        }
