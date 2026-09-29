"""
tests/test_dns_features.py — Unit tests for src/dns/features.py

Covers: per-domain lexical features, host-level behavioral features,
        empty/invalid input safety, entropy computation, n-gram scoring.
"""

from __future__ import annotations

import pytest
from src.dns.features import (
    extract_domain_features,
    extract_host_dns_features,
    DGA_FEATURE_NAMES,
    HOST_DNS_FEATURE_NAMES,
)


def make_dns_record(timestamp, query, qtype="A", rcode="NOERROR", query_length=None):
    return {
        "timestamp": timestamp,
        "src_ip": "10.0.0.5",
        "query": query,
        "qtype": qtype,
        "rcode": rcode,
        "query_length": query_length or len(query),
    }


BENIGN_RECORDS = [
    make_dns_record(1000.0, "google.com"),
    make_dns_record(1005.0, "github.com"),
    make_dns_record(1010.0, "wikipedia.org"),
    make_dns_record(1015.0, "stackoverflow.com"),
]

DGA_RECORDS = [
    make_dns_record(1000.0 + i * 0.3, f"xj3kq9ab{i}.com", rcode="NXDOMAIN")
    for i in range(10)
]

TUNNEL_RECORDS = [
    make_dns_record(
        1000.0 + i * 0.5,
        f"aGVsbG8gd29ybGQ{i}dGVzdA.tunnel.example.com",
        qtype="TXT",
        query_length=55,
    )
    for i in range(10)
]


class TestExtractDomainFeatures:

    def test_returns_all_expected_keys(self):
        features = extract_domain_features("google.com")
        for key in DGA_FEATURE_NAMES:
            assert key in features, f"Missing: {key}"

    def test_empty_query_returns_zeros(self):
        features = extract_domain_features("")
        assert features["entropy"] == 0.0
        assert features["domain_length"] == 0.0

    def test_benign_domain_low_entropy(self):
        features = extract_domain_features("google.com")
        assert features["entropy"] < 3.5

    def test_dga_domain_high_entropy(self):
        features = extract_domain_features("xj3kq9ab8k.com")
        assert features["entropy"] > 3.0

    def test_digit_ratio_range(self):
        features = extract_domain_features("ab12cd34.com")
        assert 0.0 <= features["digit_ratio"] <= 1.0

    def test_vowel_ratio_for_english_word(self):
        features = extract_domain_features("google.com")
        # "google" has o, o, e = 3 vowels out of 6 letters → 0.5
        assert features["vowel_ratio"] == pytest.approx(0.5, abs=0.1)

    def test_all_features_are_float(self):
        features = extract_domain_features("example.com")
        for k, v in features.items():
            assert isinstance(v, float), f"{k}: {type(v)}"

    def test_bigram_score_english_higher_than_random(self):
        english_features = extract_domain_features("google.com")
        random_features = extract_domain_features("xj3kq9ab.com")
        # English bigram score should be less negative (closer to 0)
        assert english_features["bigram_score"] > random_features["bigram_score"]

    def test_domain_length_correct(self):
        features = extract_domain_features("abcdefgh.com")
        assert features["domain_length"] == pytest.approx(8.0)


class TestExtractHostDNSFeatures:

    def test_returns_all_expected_keys(self):
        features = extract_host_dns_features(BENIGN_RECORDS)
        for key in HOST_DNS_FEATURE_NAMES:
            assert key in features, f"Missing: {key}"

    def test_empty_records_returns_zeros(self):
        features = extract_host_dns_features([])
        assert features["query_count"] == 0.0
        assert features["nxdomain_ratio"] == 0.0

    def test_query_count(self):
        features = extract_host_dns_features(BENIGN_RECORDS)
        assert features["query_count"] == pytest.approx(4.0)

    def test_nxdomain_ratio_zero_for_benign(self):
        features = extract_host_dns_features(BENIGN_RECORDS)
        assert features["nxdomain_ratio"] == pytest.approx(0.0)

    def test_nxdomain_ratio_high_for_dga(self):
        features = extract_host_dns_features(DGA_RECORDS)
        assert features["nxdomain_ratio"] == pytest.approx(1.0)

    def test_txt_ratio_high_for_tunnel(self):
        features = extract_host_dns_features(TUNNEL_RECORDS)
        assert features["txt_ratio"] == pytest.approx(1.0)

    def test_mean_query_length_high_for_tunnel(self):
        features = extract_host_dns_features(TUNNEL_RECORDS)
        assert features["mean_query_length"] > 40

    def test_query_frequency_nonzero(self):
        features = extract_host_dns_features(DGA_RECORDS)
        assert features["query_frequency"] > 0.0

    def test_all_features_are_floats(self):
        features = extract_host_dns_features(BENIGN_RECORDS)
        for k, v in features.items():
            assert isinstance(v, float), f"{k}: {type(v)}"

    def test_single_record_no_crash(self):
        features = extract_host_dns_features([make_dns_record(1000.0, "test.com")])
        assert isinstance(features["query_count"], float)
