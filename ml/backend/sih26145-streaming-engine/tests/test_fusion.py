from src.fusion.confidence import ConfidenceEngine
from src.fusion.severity import SeverityEngine
from src.fusion.evidence import EvidenceAggregator


def test_confidence_engine():
    engine = ConfidenceEngine(model_weight=0.5, anomaly_weight=0.3, baseline_weight=0.2)

    # All signals strong
    conf = engine.calculate_confidence(model_score=0.9, anomaly_score=0.8, baseline_z_score=4.0)
    assert conf > 0.8

    # Missing model score -> dynamic weight re-normalization
    conf_no_model = engine.calculate_confidence(model_score=None, anomaly_score=1.0, baseline_z_score=0.0)
    assert 0.0 <= conf_no_model <= 1.0


def test_severity_engine_distinction():
    engine = SeverityEngine()

    # High confidence on volumetric DDoS -> Critical
    sev_ddos_critical = engine.evaluate_severity(
        threat_type="DDoS",
        confidence=0.95,
        features={"pps": 600.0}
    )
    assert sev_ddos_critical == "critical"

    # High confidence on low pps DDoS -> High/Medium
    sev_ddos_medium = engine.evaluate_severity(
        threat_type="DDoS",
        confidence=0.65,
        features={"pps": 80.0}
    )
    assert sev_ddos_medium in ("medium", "high")


def test_evidence_aggregator():
    agg = EvidenceAggregator()
    model_ev = ["Abnormal packet rate"]
    baseline_ev = ["Baseline deviation Z-score: 4.5"]
    feat_ev = ["Abnormal packet rate"] # Duplicate

    result = agg.aggregate(model_ev, baseline_ev, feat_ev)
    assert len(result) == 2
    assert "Abnormal packet rate" in result
    assert "Baseline deviation Z-score: 4.5" in result
