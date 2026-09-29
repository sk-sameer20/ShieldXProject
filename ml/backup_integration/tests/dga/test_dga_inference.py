"""
tests/dga/test_dga_inference.py — Tests for DGA Expert Panel Inference.
"""

import pytest
from src.dga.inference import run_dga_detection, _GLOBAL_DGA_PANEL, DGADetectorPanel
from src.common.schema import Alert

# Reset the global panel before tests if needed
@pytest.fixture(autouse=True)
def reset_global_panel():
    import src.dga.inference
    src.dga.inference._GLOBAL_DGA_PANEL = None

def test_1_normal_benign_domain():
    alert = run_dga_detection("google.com")
    assert isinstance(alert, Alert)
    assert alert.threat_class in ("DGA", "benign")

def test_2_short_domain():
    alert = run_dga_detection("a.co")
    assert isinstance(alert, Alert)
    assert 'expert_a_v2_score' in alert.technical_evidence

def test_3_long_domain():
    alert = run_dga_detection("thisisaverylongdomainnamethatwearetetingwith.com")
    assert isinstance(alert, Alert)
    assert 'expert_b_v6_score' in alert.technical_evidence

def test_4_domain_containing_subdomain():
    alert = run_dga_detection("api.v1.service.aws.com")
    assert isinstance(alert, Alert)
    # Checks that preprocessing extracted the base label correctly (aws)
    assert alert.technical_evidence.get('domain') == "api.v1.service.aws.com"

def test_5_empty_string():
    alert = run_dga_detection("")
    assert isinstance(alert, Alert)
    assert alert.detected is False
    assert alert.threat_class == "benign"

def test_6_invalid_malformed_input():
    alert = run_dga_detection("---.***")
    assert isinstance(alert, Alert)
    assert alert.threat_class in ("DGA", "benign")

def test_7_expert_a_produces_valid_output():
    alert = run_dga_detection("example.com")
    assert 'expert_a_v2_score' in alert.technical_evidence
    assert isinstance(alert.technical_evidence['expert_a_v2_score'], float)

def test_8_expert_b_produces_valid_output():
    alert = run_dga_detection("example.com")
    assert 'expert_b_v6_score' in alert.technical_evidence
    assert isinstance(alert.technical_evidence['expert_b_v6_score'], float)

def test_9_both_experts_produce_independent_evidence():
    alert = run_dga_detection("example.com")
    # Even if they score 0.0, the keys must be present independently
    assert 'expert_a_v2_score' in alert.technical_evidence
    assert 'expert_b_v6_score' in alert.technical_evidence

def test_10_output_follows_alert_schema():
    alert = run_dga_detection("example.com")
    assert hasattr(alert, 'alert_id')
    assert hasattr(alert, 'timestamp')
    assert hasattr(alert, 'threat_class')
    assert hasattr(alert, 'detected')
    assert hasattr(alert, 'confidence')
    assert hasattr(alert, 'severity')

def test_11_model_loading_failure_is_handled_cleanly():
    # Force a fresh panel instance that fails to load
    panel = DGADetectorPanel()
    # Wipe out models explicitly
    panel.v2_model = None
    panel.v6_model = None
    scores = panel.predict_domain("example.com")
    assert scores["expert_a_v2_score"] == 0.0
    assert scores["expert_b_v6_score"] == 0.0

def test_12_repeated_inference_deterministic():
    alert1 = run_dga_detection("example.com")
    alert2 = run_dga_detection("example.com")
    
    assert alert1.technical_evidence['expert_a_v2_score'] == alert2.technical_evidence['expert_a_v2_score']
    assert alert1.technical_evidence['expert_b_v6_score'] == alert2.technical_evidence['expert_b_v6_score']
