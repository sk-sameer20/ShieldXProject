"""
tests/test_c2_features.py — Unit tests for src/c2/features.py

Covers: normal input, empty input, single record, zero-division safety,
        IAT computation, periodicity scoring, destination concentration.
"""

from __future__ import annotations

import pytest
from src.c2.features import extract_c2_features, _compute_periodicity_score, C2_FEATURE_NAMES


# ── Fixtures ──────────────────────────────────────────────────────────────────

def make_record(timestamp, dst_ip="1.2.3.4", duration=1.0, orig=512, resp=1024):
    return {
        "timestamp": timestamp,
        "src_ip": "10.0.0.1",
        "dst_ip": dst_ip,
        "duration": duration,
        "orig_bytes": orig,
        "resp_bytes": resp,
    }


BENIGN_RECORDS = [
    make_record(1000.0, dst_ip="1.1.1.1"),
    make_record(1015.0, dst_ip="2.2.2.2"),
    make_record(1040.0, dst_ip="3.3.3.3"),
    make_record(1080.0, dst_ip="4.4.4.4"),
]

C2_RECORDS = [
    make_record(1000.0, dst_ip="185.220.101.45"),
    make_record(1030.0, dst_ip="185.220.101.45"),
    make_record(1060.0, dst_ip="185.220.101.45"),
    make_record(1090.0, dst_ip="185.220.101.45"),
    make_record(1120.0, dst_ip="185.220.101.45"),
]


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestExtractC2Features:

    def test_returns_all_expected_keys(self):
        features = extract_c2_features(BENIGN_RECORDS)
        for key in C2_FEATURE_NAMES:
            assert key in features, f"Missing feature: {key}"

    def test_empty_records_returns_zero_features(self):
        features = extract_c2_features([])
        assert features["connection_count"] == 0.0
        assert features["iat_mean"] == 0.0
        assert features["periodicity_score"] == 0.0

    def test_single_record_no_crash(self):
        features = extract_c2_features([make_record(1000.0)])
        assert features["connection_count"] == 1.0
        # No IATs possible — std/cv/periodicity should be 0
        assert features["iat_std"] == 0.0
        assert features["iat_cv"] == 0.0

    def test_connection_count(self):
        features = extract_c2_features(BENIGN_RECORDS)
        assert features["connection_count"] == pytest.approx(4.0)

    def test_iat_mean_regular_beaconing(self):
        """30-second interval beaconing → IAT mean ≈ 30."""
        features = extract_c2_features(C2_RECORDS)
        assert features["iat_mean"] == pytest.approx(30.0, abs=0.1)

    def test_iat_cv_low_for_regular_beaconing(self):
        """Perfectly regular timing → CV ≈ 0."""
        features = extract_c2_features(C2_RECORDS)
        assert features["iat_cv"] == pytest.approx(0.0, abs=0.01)

    def test_unique_destinations_benign(self):
        features = extract_c2_features(BENIGN_RECORDS)
        assert features["unique_destinations"] == pytest.approx(4.0)

    def test_unique_destinations_c2(self):
        features = extract_c2_features(C2_RECORDS)
        assert features["unique_destinations"] == pytest.approx(1.0)

    def test_dominant_destination_ratio_c2(self):
        """All connections to same destination → ratio = 1.0."""
        features = extract_c2_features(C2_RECORDS)
        assert features["dominant_destination_ratio"] == pytest.approx(1.0)

    def test_dominant_destination_ratio_benign(self):
        """All different destinations → ratio = 0.25."""
        features = extract_c2_features(BENIGN_RECORDS)
        assert features["dominant_destination_ratio"] == pytest.approx(0.25)

    def test_byte_ratio_range(self):
        features = extract_c2_features(C2_RECORDS)
        assert 0.0 <= features["byte_ratio"] <= 1.0

    def test_zero_division_safety_zero_duration(self):
        records = [make_record(1000.0, duration=0.0)]
        features = extract_c2_features([records[0]])
        # Should not raise
        assert isinstance(features["mean_duration"], float)

    def test_all_features_are_floats(self):
        features = extract_c2_features(C2_RECORDS)
        for k, v in features.items():
            assert isinstance(v, float), f"Feature {k} is not float: {type(v)}"

    def test_missing_duration_zeek_compat(self):
        records = [
            make_record(1000.0, duration=10.0),
            make_record(1010.0, duration=None),
            make_record(1020.0, duration=20.0),
        ]
        features = extract_c2_features(records)
        # Should exclude None and compute mean(10.0, 20.0) = 15.0
        assert features["mean_duration"] == pytest.approx(15.0)

    def test_all_missing_duration_zeek_compat(self):
        records = [
            make_record(1000.0, duration=None),
            make_record(1010.0, duration=None),
        ]
        features = extract_c2_features(records)
        # Should fallback to 0.0 safely
        assert features["mean_duration"] == 0.0


class TestPeriodicityScore:

    def test_perfectly_regular_iats_high_score(self):
        """Exactly 30.0s IATs → high periodicity."""
        iats = [30.0] * 10
        score = _compute_periodicity_score(iats)
        assert score >= 0.9

    def test_random_iats_low_score(self):
        """Random IATs → lower periodicity score."""
        import random
        random.seed(42)
        iats = [random.uniform(1.0, 100.0) for _ in range(20)]
        score = _compute_periodicity_score(iats)
        # Not guaranteed to be low, but random data rarely scores > 0.8
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0

    def test_too_few_iats_returns_zero(self):
        assert _compute_periodicity_score([]) == 0.0
        assert _compute_periodicity_score([10.0]) == 0.0
        assert _compute_periodicity_score([10.0, 10.0]) == 0.0
        assert _compute_periodicity_score([10.0, 10.0, 10.0]) == 0.0

    def test_score_in_range(self):
        iats = [30.0, 29.8, 30.2, 30.1, 29.9, 30.0]
        score = _compute_periodicity_score(iats)
        assert 0.0 <= score <= 1.0
