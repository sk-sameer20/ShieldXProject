"""
src/dga/inference.py — "Expert Panel" DGA Detection.

Uses two models (Expert A: TF-IDF + LR, Expert B: 1D-CNN) as an independent panel.
"""

import json
from pathlib import Path
from typing import Optional, Dict, Any
import numpy as np
import joblib

from src.common.schema import Alert, Severity, make_benign_alert
from src.dga.preprocessing import preprocess_domain, encode_domain_for_cnn

try:
    import tensorflow as tf
except ImportError:
    tf = None

MODELS_DIR = Path(__file__).resolve().parent.parent.parent / "models" / "dga"

class DGADetectorPanel:
    def __init__(self):
        self.v2_model = None
        self.v2_vectorizer = None
        self.v6_model = None
        self.v6_vocab = None
        self.v6_max_len = 24

        self._load_models()

    def _load_models(self):
        # Load Expert A (v2)
        v2_path = MODELS_DIR / "dga_v2_model.joblib"
        if v2_path.exists():
            try:
                data = joblib.load(v2_path)
                if hasattr(data, "predict_proba"):
                    self.v2_model = data
                    self.v2_vectorizer = None
                else:
                    self.v2_model = data.get("model")
                    self.v2_vectorizer = data.get("vectorizer")
            except Exception as e:
                print(f"Warning: Failed to load Expert A (v2): {e}")

        # Load Expert B (v6)
        v6_path = MODELS_DIR / "dga_v6_model.keras"
        v6_vocab_path = MODELS_DIR / "dga_v6_vocab.json"
        
        if v6_vocab_path.exists():
            with open(v6_vocab_path, "r") as f:
                self.v6_vocab = json.load(f)
                
        if v6_path.exists() and tf is not None:
            try:
                self.v6_model = tf.keras.models.load_model(v6_path)
            except Exception as e:
                print(f"Warning: Failed to load Expert B (v6): {e}")

    def predict_domain(self, domain: str) -> Dict[str, float]:
        """Run both experts on a single domain and return their probabilities."""
        processed = preprocess_domain(domain)
        
        scores = {"expert_a_v2_score": 0.0, "expert_b_v6_score": 0.0}

        # Expert A Inference
        if self.v2_model is not None:
            try:
                if self.v2_vectorizer is not None:
                    X = self.v2_vectorizer.transform([processed])
                    scores["expert_a_v2_score"] = float(self.v2_model.predict_proba(X)[0, 1])
                else:
                    scores["expert_a_v2_score"] = float(self.v2_model.predict_proba([processed])[0, 1])
            except Exception:
                pass

        # Expert B Inference
        if self.v6_model is not None and self.v6_vocab is not None:
            try:
                X_seq = encode_domain_for_cnn(processed, self.v6_vocab, self.v6_max_len)
                X_input = np.array([X_seq])
                scores["expert_b_v6_score"] = float(self.v6_model.predict(X_input, verbose=0)[0, 0])
            except Exception:
                pass

        return scores


# Global instance to avoid reloading models on every query
_GLOBAL_DGA_PANEL = None

def run_dga_detection(
    domain: str,
    src_ip: Optional[str] = None,
    window_start: Optional[float] = None,
    window_end: Optional[float] = None,
) -> Alert:
    """
    Main entry point for Person 4 integration.
    """
    global _GLOBAL_DGA_PANEL
    if _GLOBAL_DGA_PANEL is None:
        _GLOBAL_DGA_PANEL = DGADetectorPanel()

    if not domain:
        return make_benign_alert(
            model_version="dga_panel_v8",
            src_ip=src_ip,
            window_start=window_start,
            window_end=window_end
        )

    if isinstance(domain, list):
        queries = [r.get("query") for r in domain if isinstance(r, dict) and r.get("query")]
        if not queries:
            return make_benign_alert(model_version="dga_panel_v8", src_ip=src_ip, window_start=window_start, window_end=window_end)
        best_domain = queries[0]
        max_scores = {"expert_a_v2_score": 0.0, "expert_b_v6_score": 0.0}
        for q in queries:
            sc = _GLOBAL_DGA_PANEL.predict_domain(q)
            if max(sc["expert_a_v2_score"], sc["expert_b_v6_score"]) > max(max_scores["expert_a_v2_score"], max_scores["expert_b_v6_score"]):
                max_scores = sc
                best_domain = q
        domain = best_domain
        scores = max_scores
    else:
        scores = _GLOBAL_DGA_PANEL.predict_domain(domain)

    p_a = scores["expert_a_v2_score"]
    p_b = scores["expert_b_v6_score"]
    
    threshold = 0.5
    
    # We alert if either model detects, but DO NOT fuse the scores mathematically.
    detected = p_a >= threshold or p_b >= threshold
    
    if not detected:
        return make_benign_alert(
            model_version="dga_panel_v8",
            src_ip=src_ip,
            window_start=window_start,
            window_end=window_end,
            technical_evidence={"domain": domain, **scores}
        )

    evidence = []
    if p_a >= threshold:
        evidence.append(f"Expert A (N-gram) flagged domain '{domain}' with probability {p_a:.2f}")
    if p_b >= threshold:
        evidence.append(f"Expert B (1D-CNN) flagged domain '{domain}' with probability {p_b:.2f}")

    max_score = max(p_a, p_b)
    
    severity: Severity = "medium"
    if max_score > 0.9:
        severity = "critical"
    elif max_score > 0.75:
        severity = "high"

    return Alert(
        threat_class="DGA",
        detected=True,
        confidence=max_score,  # Maximum confidence used for severity routing, not fused.
        severity=severity,
        evidence=evidence,
        technical_evidence={
            "domain": domain,
            "fusion_policy": "independent_panel",
            **scores
        },
        model_version="dga_panel_v8",
        src_ip=src_ip,
        window_start=window_start,
        window_end=window_end,
    )
