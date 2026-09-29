"""
Legacy Random Forest DGA Detector (v1/v3 architecture).
Preserved for historical reproduction of early DGA baselines.
"""

from typing import Dict, List, Optional, Any
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier

# NOTE: These imports rely on the old dns/features.py which might have been refactored.
# They are kept as-is for historical preservation.
from src.dns.features import DGA_FEATURE_NAMES, extract_domain_features, extract_host_dns_features

class LegacyDGADetector:
    """
    Supervised DGA detector using Random Forest on lexical + behavioral features.

    Per-domain features (entropy, bigrams, digit ratio, etc.) are the primary
    signal. Host-level behavioral features (NXDOMAIN ratio, query frequency)
    can be included for context but are optional.
    """

    MODEL_VERSION: str = "v1_lexical_rf"

    def __init__(self) -> None:
        self._model: Optional[RandomForestClassifier] = None
        self._fitted = False
        self._entropy_threshold = 3.5
        self._length_threshold = 15
        self._digit_ratio_threshold = 0.2
        self._nxdomain_ratio_threshold = 0.1

    def fit(self, X: np.ndarray, y: np.ndarray) -> "LegacyDGADetector":
        self._model = RandomForestClassifier(
            n_estimators=100,
            max_depth=None,
            random_state=42,
            class_weight="balanced",
        )
        self._model.fit(X, y)
        self._fitted = True
        return self

    def save(self, path: str) -> None:
        if not self._fitted:
            raise RuntimeError("Cannot save unfitted detector.")
        joblib.dump({"model": self._model, "version": self.MODEL_VERSION}, path)

    @classmethod
    def load(cls, path: str) -> "LegacyDGADetector":
        data = joblib.load(path)
        instance = cls()
        instance._model = data["model"]
        instance._fitted = True
        return instance

    def _score_domain(self, features: Dict[str, float]) -> float:
        if self._fitted and self._model is not None:
            vec = np.array([[features.get(k, 0.0) for k in DGA_FEATURE_NAMES]])
            try:
                proba = self._model.predict_proba(vec)[0]
                classes = list(self._model.classes_)
                dga_idx = classes.index(1) if 1 in classes else -1
                return float(proba[dga_idx]) if dga_idx >= 0 else 0.0
            except Exception:
                pass
        return 0.0
