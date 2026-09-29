"""
src/c2/detector.py — C2 Beaconing Detector

Implements the C2Detector class using:
  - Primary:   IsolationForest (unsupervised anomaly detection)
  - Secondary: Explicit periodicity + repetition heuristic scorer

Design rules:
- Detection logic is here; feature extraction lives in features.py.
- IsolationForest raw score is NOT reported as a probability.
  We expose it as `anomaly_score` and produce a combined `confidence`
  from multiple signals — documented clearly.
- Evidence strings are human-readable; raw values go in technical_evidence.
- Every public method is stateless after .fit() — thread-safe for inference.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from src.common.alert import Alert, Severity, make_benign_alert
from src.c2.features import C2_FEATURE_NAMES, extract_c2_features
from src.config import CONFIG


class C2Detector:
    """
    C2 Beaconing Detector.

    Usage
    -----
    detector = C2Detector()
    detector.fit(benign_feature_matrix)   # numpy array, rows = windows
    alert = detector.predict_from_records(connection_records, src_ip="10.0.0.x")

    Or if features are already extracted:
    alert = detector.predict(feature_dict)
    """

    MODEL_VERSION: str = CONFIG.models.c2_version

    def __init__(
        self,
        contamination: float | None = None,
        periodicity_lag_max: int | None = None,
    ) -> None:
        self._contamination = contamination or CONFIG.c2.contamination
        self._periodicity_lag_max = periodicity_lag_max or CONFIG.c2.periodicity_lag_max
        self._repetition_threshold = CONFIG.c2.repetition_ratio_threshold
        self._min_connections = CONFIG.c2.min_connections
        self._weight_anomaly = 0.35
        self._weight_periodicity = 0.30
        self._weight_repetition = 0.20
        self._weight_iat = 0.15
        self._model: Optional[IsolationForest] = None
        self._fitted = False

    # ── Training ─────────────────────────────────────────────────────────────

    def fit(self, feature_matrix: np.ndarray) -> "C2Detector":
        """
        Train the IsolationForest on benign connection feature vectors.

        Args:
            feature_matrix: (N, len(C2_FEATURE_NAMES)) array of benign features.

        Returns:
            self (for chaining).
        """
        if feature_matrix.shape[0] < 10:
            raise ValueError(
                f"Need at least 10 samples to fit IsolationForest, "
                f"got {feature_matrix.shape[0]}."
            )

        self._model = IsolationForest(
            contamination=self._contamination,
            random_state=42,
            n_estimators=100,
        )
        self._model.fit(feature_matrix)
        self._fitted = True
        return self

    def save(self, path: str) -> None:
        """Serialize the fitted model to disk."""
        if not self._fitted:
            raise RuntimeError("Cannot save unfitted detector.")
        joblib.dump({"model": self._model, "version": self.MODEL_VERSION}, path)

    @classmethod
    def load(cls, path: str) -> "C2Detector":
        """Load a previously saved detector."""
        data = joblib.load(path)
        instance = cls()
        instance._model = data["model"]
        instance._fitted = True
        return instance

    # ── Inference ─────────────────────────────────────────────────────────────

    def predict_from_records(
        self,
        records: List[Dict],
        src_ip: Optional[str] = None,
        window_start: Optional[float] = None,
        window_end: Optional[float] = None,
    ) -> Alert:
        """
        Full pipeline: extract features from raw records then detect.

        Args:
            records:      List of connection dicts for ONE src_ip within a window.
            src_ip:       Source host (informational).
            window_start: Window start timestamp (epoch float).
            window_end:   Window end timestamp (epoch float).

        Returns:
            Alert instance.
        """
        features = extract_c2_features(records, src_ip=src_ip)
        return self.predict(
            features,
            src_ip=src_ip,
            window_start=window_start,
            window_end=window_end,
        )

    def predict(
        self,
        features: Dict[str, float],
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        window_start: Optional[float] = None,
        window_end: Optional[float] = None,
    ) -> Alert:
        """
        Detect C2 beaconing from a pre-extracted feature dict.

        Args:
            features:     Output of extract_c2_features().
            src_ip, dst_ip, window_start, window_end: metadata for the alert.

        Returns:
            Alert instance (detected=True/False).
        """
        # ── Pre-filter: not enough connections ───────────────────────────
        n_conn = features.get("connection_count", 0)
        if n_conn < self._min_connections:
            return make_benign_alert(
                model_version=self.MODEL_VERSION,
                src_ip=src_ip,
                dst_ip=dst_ip,
                window_start=window_start,
                window_end=window_end,
                technical_evidence=features,
            )

        # ── Signal 1: IsolationForest anomaly score ───────────────────────
        if self._fitted and self._model is not None:
            vec = np.array([[features.get(k, 0.0) for k in C2_FEATURE_NAMES]])
            raw_score = float(self._model.score_samples(vec)[0])
            raw_decision = float(self._model.decision_function(vec)[0])
            # score_samples returns [-1, 0]. Negate it to get the original [0, 1] anomaly score
            anomaly_score = -raw_score
        else:
            anomaly_score = 0.0
            raw_decision = 0.0

        # ── Signal 2: Periodicity heuristic score ─────────────────────────
        periodicity_score = features.get("periodicity_score", 0.0)

        # ── Signal 3: Repetition heuristic score ─────────────────────────
        repetition_score = self._compute_repetition_score(features)

        # ── Signal 4: IAT consistency ─────────────────────────────────────
        iat_cv = features.get("iat_cv", 1.0)
        # Low CoV → high regularity; map to [0,1] score
        iat_regularity_score = max(0.0, 1.0 - min(iat_cv, 2.0) / 2.0)

        # ── Combined confidence ───────────────────────────────────────────
        # Weighted sum of individual signals.
        # Weights are configurable in config.yaml (future) — documented here.
        #
        # IMPORTANT: This is NOT a calibrated probability.
        # It is a normalized combination of multiple behavioral signals.
        # We document it as "evidence strength score" in the alert.
        confidence = (
            self._weight_anomaly * anomaly_score
            + self._weight_periodicity * periodicity_score
            + self._weight_repetition * repetition_score
            + self._weight_iat * iat_regularity_score
        )
        confidence = float(max(0.0, min(1.0, confidence)))

        # ── Threshold ─────────────────────────────────────────────────────
        detection_threshold = 0.45
        detected = confidence >= detection_threshold

        if not detected:
            return make_benign_alert(
                model_version=self.MODEL_VERSION,
                src_ip=src_ip,
                dst_ip=dst_ip,
                window_start=window_start,
                window_end=window_end,
                technical_evidence={
                    **features, 
                    "confidence": confidence,
                    "anomaly_score": anomaly_score,
                    "decision_function_score": raw_decision,
                },
            )

        # ── Build evidence list ────────────────────────────────────────────
        evidence = self._build_evidence(
            features=features,
            anomaly_score=anomaly_score,
            periodicity_score=periodicity_score,
            repetition_score=repetition_score,
            iat_regularity_score=iat_regularity_score,
        )

        severity = self._compute_severity(confidence)

        return Alert(
            threat_class="C2",
            detected=True,
            confidence=confidence,
            severity=severity,
            evidence=evidence,
            technical_evidence={
                **features,
                "anomaly_score": anomaly_score,
                "decision_function_score": raw_decision,
                "periodicity_score": periodicity_score,
                "repetition_score": repetition_score,
                "iat_regularity_score": iat_regularity_score,
            },
            model_version=self.MODEL_VERSION,
            src_ip=src_ip,
            dst_ip=dst_ip,
            window_start=window_start,
            window_end=window_end,
        )

    # ── Private helpers ───────────────────────────────────────────────────────

    def _compute_repetition_score(self, features: Dict[str, float]) -> float:
        """
        Score based on destination concentration.

        If >threshold of connections go to ONE destination, score is high.
        """
        ratio = features.get("dominant_destination_ratio", 0.0)
        if ratio >= self._repetition_threshold:
            # Scale from threshold→1 to score 0→1
            score = (ratio - self._repetition_threshold) / (1.0 - self._repetition_threshold)
            return float(min(1.0, score))
        return 0.0

    def _build_evidence(
        self,
        *,
        features: Dict[str, float],
        anomaly_score: float,
        periodicity_score: float,
        repetition_score: float,
        iat_regularity_score: float,
    ) -> List[str]:
        """Produce human-readable evidence strings for triggered signals."""
        evidence: List[str] = []

        if anomaly_score > 0.5:
            evidence.append(
                f"Connection pattern is anomalous compared to baseline "
                f"(anomaly score: {anomaly_score:.2f})"
            )

        if periodicity_score > 0.4:
            evidence.append(
                f"Highly periodic inter-arrival times detected "
                f"(periodicity score: {periodicity_score:.2f})"
            )

        iat_cv = features.get("iat_cv", 1.0)
        if iat_regularity_score > 0.6:
            evidence.append(
                f"Very low IAT variation (CV={iat_cv:.3f}) — consistent with automated beaconing"
            )

        if repetition_score > 0.0:
            ratio = features.get("dominant_destination_ratio", 0.0)
            n_dest = int(features.get("unique_destinations", 0))
            evidence.append(
                f"Repeated connections to same destination "
                f"({ratio*100:.0f}% of flows, {n_dest} unique dst)"
            )

        orig_bytes_std = features.get("orig_bytes_std", 0.0)
        mean_orig = features.get("mean_orig_bytes", 0.0)
        if mean_orig > 0 and (orig_bytes_std / mean_orig) < 0.1:
            evidence.append(
                f"Payload size is unusually consistent "
                f"(mean={mean_orig:.0f}B, std={orig_bytes_std:.1f}B)"
            )

        # Fallback — should not happen if threshold tuning is correct,
        # but avoids Alert validation error
        if not evidence:
            evidence.append(
                f"Multiple behavioral signals elevated (combined score: "
                f"anomaly={anomaly_score:.2f}, periodicity={periodicity_score:.2f})"
            )

        return evidence

    @staticmethod
    def _compute_severity(confidence: float) -> Severity:
        if confidence >= 0.80:
            return "high"
        elif confidence >= 0.60:
            return "medium"
        else:
            return "low"
