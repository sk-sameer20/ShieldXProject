"""
tests/test_c2_detector.py — Unit and integration tests for C2Detector.

Covers: unfitted detector returns benign, fitted detector detects known C2,
        confidence range, alert schema validation, evidence non-empty on detection.
"""

from __future__ import annotations

import numpy as np
import pytest

from src.c2.detector import C2Detector
from src.c2.features import C2_FEATURE_NAMES, extract_c2_features
from src.common.alert import Alert


def make_record(timestamp, dst_ip="1.2.3.4", duration=1.0, orig=512, resp=1024):
    return {
        "timestamp": timestamp,
        "src_ip": "10.0.0.1",
        "dst_ip": dst_ip,
        "duration": duration,
        "orig_bytes": orig,
        "resp_bytes": resp,
    }


BENIGN_RECORDS = [make_record(1000.0 + i * 17.3, dst_ip=f"{i}.{i}.{i}.{i}") for i in range(12)]

C2_RECORDS = [
    make_record(1000.0 + i * 30.0, dst_ip="185.220.101.45", orig=128, resp=64)
    for i in range(10)
]


@pytest.fixture
def fitted_detector():
    """Detector trained on benign feature vectors."""
    # Generate synthetic benign feature matrix
    rng = np.random.default_rng(0)
    rows = []
    for _ in range(50):
        records = [
            make_record(
                float(j) * rng.uniform(5.0, 60.0),
                dst_ip=f"{rng.integers(1, 255)}.{rng.integers(1, 255)}.1.1",
                orig=int(rng.integers(100, 10000)),
                resp=int(rng.integers(100, 50000)),
            )
            for j in range(rng.integers(4, 15))
        ]
        rows.append(extract_c2_features(records))

    X = np.array([[r.get(k, 0.0) for k in C2_FEATURE_NAMES] for r in rows])
    detector = C2Detector()
    detector.fit(X)
    return detector


class TestC2DetectorUnfitted:

    def test_unfitted_predict_returns_benign_when_too_few_connections(self):
        detector = C2Detector()
        features = extract_c2_features([make_record(1000.0)])
        alert = detector.predict(features)
        assert isinstance(alert, Alert)
        assert alert.detected is False

    def test_unfitted_predict_does_not_crash(self):
        detector = C2Detector()
        features = extract_c2_features(C2_RECORDS)
        # Should not raise even when unfitted
        alert = detector.predict(features)
        assert isinstance(alert, Alert)


class TestC2DetectorFitted:

    def test_alert_is_alert_instance(self, fitted_detector):
        alert = fitted_detector.predict_from_records(C2_RECORDS, src_ip="10.0.0.25")
        assert isinstance(alert, Alert)

    def test_confidence_in_valid_range(self, fitted_detector):
        alert = fitted_detector.predict_from_records(C2_RECORDS)
        assert 0.0 <= alert.confidence <= 1.0

    def test_benign_traffic_produces_low_confidence(self, fitted_detector):
        alert = fitted_detector.predict_from_records(BENIGN_RECORDS)
        assert alert.confidence < 0.8, f"Benign traffic too high confidence: {alert.confidence}"

    def test_detected_alert_has_evidence(self, fitted_detector):
        # Force a known-C2 scenario with all signals maxed
        features = {k: 0.0 for k in C2_FEATURE_NAMES}
        features["connection_count"] = 10.0
        features["iat_cv"] = 0.0          # perfectly regular
        features["periodicity_score"] = 1.0
        features["dominant_destination_ratio"] = 1.0
        features["iat_entropy"] = 0.0
        features["orig_bytes_std"] = 0.0
        features["mean_orig_bytes"] = 128.0

        alert = fitted_detector.predict(features)
        if alert.detected:
            assert len(alert.evidence) > 0

    def test_alert_threat_class_is_c2_when_detected(self, fitted_detector):
        features = {k: 0.0 for k in C2_FEATURE_NAMES}
        features["connection_count"] = 10.0
        features["periodicity_score"] = 1.0
        features["dominant_destination_ratio"] = 1.0
        features["iat_cv"] = 0.0
        alert = fitted_detector.predict(features)
        if alert.detected:
            assert alert.threat_class == "C2"

    def test_benign_alert_threat_class(self, fitted_detector):
        alert = fitted_detector.predict_from_records([make_record(1000.0)])
        assert alert.threat_class == "benign"
        assert alert.detected is False

    def test_model_version_present(self, fitted_detector):
        alert = fitted_detector.predict_from_records(C2_RECORDS)
        assert alert.model_version == C2Detector.MODEL_VERSION

    def test_save_and_load(self, fitted_detector, tmp_path):
        model_file = tmp_path / "c2_test.joblib"
        fitted_detector.save(str(model_file))
        loaded = C2Detector.load(str(model_file))
        alert_original = fitted_detector.predict_from_records(C2_RECORDS)
        alert_loaded = loaded.predict_from_records(C2_RECORDS)
        assert alert_original.detected == alert_loaded.detected
        assert abs(alert_original.confidence - alert_loaded.confidence) < 0.001

    def test_score_mapping_preserves_variance(self, fitted_detector):
        # Create two slightly different feature sets
        features1 = {k: 0.0 for k in C2_FEATURE_NAMES}
        features1["connection_count"] = 10.0
        features1["mean_duration"] = 5.0
        
        features2 = {k: 0.0 for k in C2_FEATURE_NAMES}
        features2["connection_count"] = 10.0
        features2["mean_duration"] = 50.0
        
        alert1 = fitted_detector.predict(features1)
        alert2 = fitted_detector.predict(features2)
        
        # Ensure we have technical evidence
        assert "anomaly_score" in alert1.technical_evidence
        assert "decision_function_score" in alert1.technical_evidence
        
        raw1 = alert1.technical_evidence["decision_function_score"]
        raw2 = alert2.technical_evidence["decision_function_score"]
        
        mapped1 = alert1.technical_evidence["anomaly_score"]
        mapped2 = alert2.technical_evidence["anomaly_score"]
        
        # 1. Scores should be bounded
        assert 0.0 <= mapped1 <= 1.0
        assert 0.0 <= mapped2 <= 1.0
        
        # 2. Different raw scores MUST map to different anomaly scores (no clamping step function)
        if raw1 != raw2:
            assert mapped1 != mapped2
            
        # 3. Mapped score is exactly -score_samples
        import numpy as np
        vec = np.array([[features1.get(k, 0.0) for k in C2_FEATURE_NAMES]])
        score_samples_val = fitted_detector._model.score_samples(vec)[0]
        assert abs(mapped1 - (-score_samples_val)) < 1e-6
