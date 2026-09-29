from typing import List, Dict, Any


class EvidenceAggregator:
    """
    Aggregates and formats evidence from model outputs, baseline anomalies, and feature checks.
    """

    def aggregate(
        self,
        model_evidence: List[str],
        baseline_evidence: List[str],
        feature_evidence: List[str]
    ) -> List[str]:
        combined = []
        seen = set()

        for item in model_evidence + baseline_evidence + feature_evidence:
            if item and item not in seen:
                seen.add(item)
                combined.append(item)

        return combined
