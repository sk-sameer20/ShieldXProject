from typing import Dict, Any


class SeverityEngine:
    """
    Evaluates threat severity based on threat class, confidence level, traffic magnitude, and persistence.
    Confidence != Severity:
    - High confidence on minor anomaly -> Low/Medium Severity
    - High confidence on massive volumetric DDoS -> Critical Severity
    """

    def evaluate_severity(
        self,
        threat_type: str,
        confidence: float,
        features: Dict[str, Any],
        evidence_count: int = 1
    ) -> str:
        if confidence < 0.4:
            return "low"

        pps = features.get("pps", 0.0)
        bps = features.get("bps", 0.0)
        entropy = features.get("avg_shannon_entropy", 0.0)
        regularity = features.get("beacon_regularity_score", 0.0)

        if threat_type == "DDoS":
            if pps > 500 or bps > 1_000_000:
                return "critical"
            elif pps > 150 or confidence > 0.8:
                return "high"
            elif pps > 50 or confidence > 0.6:
                return "medium"
            else:
                return "low"

        elif threat_type == "C2":
            if regularity > 0.8 and confidence > 0.8:
                return "critical"
            elif confidence > 0.7:
                return "high"
            elif confidence > 0.5:
                return "medium"
            else:
                return "low"

        elif threat_type in ("DNS", "DGA", "DNS_TUNNEL"):
            if entropy > 4.0 and confidence > 0.85:
                return "critical"
            elif confidence > 0.75:
                return "high"
            elif confidence > 0.5:
                return "medium"
            else:
                return "low"

        # Fallback based purely on confidence
        if confidence >= 0.85:
            return "high"
        elif confidence >= 0.6:
            return "medium"
        else:
            return "low"
