import math
from typing import Dict, Any, Optional


class ConfidenceEngine:
    """
    Fuses detector model score, anomaly score, and baseline deviation score into a normalized composite confidence.
    
    Semantics:
    - model_score: Output score from detector model adapter [0.0, 1.0].
    - anomaly_score: Rule/heuristic feature threshold exceedance [0.0, 1.0].
    - baseline_score: Standard deviation (Z-score) deviation transformed via sigmoid function [0.0, 1.0].
    """

    def __init__(
        self,
        model_weight: float = 0.5,
        anomaly_weight: float = 0.3,
        baseline_weight: float = 0.2
    ):
        self.model_weight = model_weight
        self.anomaly_weight = anomaly_weight
        self.baseline_weight = baseline_weight

    def z_score_to_confidence(self, z_score: float) -> float:
        """
        Converts a Welford Z-score into a 0.0 to 1.0 score using a smooth sigmoid function.
        Z = 0 -> 0.0, Z = 2 -> 0.5, Z = 4 -> 0.88, Z >= 6 -> 0.98.
        """
        if z_score <= 0:
            return 0.0
        # Sigmoid centered around Z=2.0
        return 1.0 / (1.0 + math.exp(-1.0 * (z_score - 2.0)))

    def calculate_confidence(
        self,
        model_score: Optional[float],
        anomaly_score: Optional[float],
        baseline_z_score: Optional[float]
    ) -> float:
        components = []
        
        if model_score is not None:
            components.append((model_score, self.model_weight))
            
        if anomaly_score is not None:
            components.append((anomaly_score, self.anomaly_weight))
            
        if baseline_z_score is not None:
            baseline_score = self.z_score_to_confidence(baseline_z_score)
            components.append((baseline_score, self.baseline_weight))

        if not components:
            return 0.0

        total_weight = sum(w for _, w in components)
        if total_weight <= 0:
            return 0.0

        weighted_sum = sum(s * w for s, w in components)
        composite = weighted_sum / total_weight

        # Clamp between 0.0 and 1.0
        return round(min(max(composite, 0.0), 1.0), 4)
