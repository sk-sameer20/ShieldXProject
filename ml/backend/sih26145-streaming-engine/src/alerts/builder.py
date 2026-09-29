import time
from typing import List, Dict, Any, Optional
from src.alerts.schema import AlertSchema


class AlertBuilder:
    """
    Constructs standardized AlertSchema instances from pipeline evaluation results.
    """

    def build_alert(
        self,
        threat_type: str,
        src_ip: str,
        confidence: float,
        severity: str,
        evidence: List[str],
        model_version: str = "v1.0",
        dst_ip: Optional[str] = None,
        flow_id: Optional[str] = None,
        timestamp: Optional[float] = None,
        window_start: Optional[float] = None,
        window_end: Optional[float] = None,
        raw_features: Optional[Dict[str, Any]] = None
    ) -> AlertSchema:
        ts = timestamp if timestamp is not None else time.time()
        
        return AlertSchema(
            timestamp=ts,
            flow_id=flow_id,
            threat_type=threat_type,
            confidence=round(confidence, 4),
            severity=severity,
            evidence=evidence,
            model_version=model_version,
            src_ip=src_ip,
            dst_ip=dst_ip,
            window_start=window_start,
            window_end=window_end,
            raw_features=raw_features or {}
        )
