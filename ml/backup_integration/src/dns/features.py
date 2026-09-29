"""
src/dns/features.py — DNS Feature Extractor (DGA + DNS Tunnelling)

Consumes a list of DNS query records for a single source host within a
time window and produces two feature dictionaries:
  - dga_features: Per-domain lexical and behavioral features (for DGA detection)
  - tunnel_features: Host-level behavioral features (for DNS tunnel detection)

Design rules:
- Pure functions only — no model calls, no alerts, no side effects.
- Division-by-zero handled explicitly everywhere.
- DGA and tunnel features are separate; don't mix them into one vector.
- Documented: which features are per-domain vs per-host-per-window.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Dict, List, Optional, Tuple

from src.common.entropy import shannon_entropy, normalized_entropy
from src.common.ngrams import (
    ngram_frequency_score,
    ENGLISH_BIGRAMS,
    ENGLISH_TRIGRAMS,
)


# ── Type aliases ──────────────────────────────────────────────────────────────
DNSRecord = Dict  # keys: timestamp, src_ip, query, qtype, rcode, query_length, ...

# ── Regex to extract the registered domain (last two labels) ─────────────────
# Simple heuristic — not a full public suffix list lookup.
_REGISTERED_DOMAIN_RE = re.compile(r"([^.]+\.[^.]+)$")


def _extract_label(query: str) -> str:
    """Extract the leftmost label (subdomain) from a DNS query string."""
    parts = query.rstrip(".").split(".")
    return parts[0] if parts else query


def _extract_registered_domain(query: str) -> str:
    """Extract the registered domain (last two labels) from a DNS query."""
    m = _REGISTERED_DOMAIN_RE.search(query.rstrip("."))
    return m.group(1) if m else query


# ─────────────────────────────────────────────────────────────────────────────
# PER-DOMAIN FEATURES (for DGA detection)
# ─────────────────────────────────────────────────────────────────────────────

def extract_domain_features(query: str) -> Dict[str, float]:
    """
    Extract lexical features from a single DNS query string for DGA detection.

    Args:
        query: Full DNS query string (e.g., "xj3kq9ab.com").

    Returns:
        Feature dict with float values.
    """
    label = _extract_label(query)
    label_lower = label.lower()

    if not label_lower:
        return _zero_domain_features()

    length = len(label_lower)

    # Character class counts
    digits = sum(1 for c in label_lower if c.isdigit())
    letters = sum(1 for c in label_lower if c.isalpha())
    vowels = sum(1 for c in label_lower if c in "aeiou")
    consonants = letters - vowels

    # Ratios (safe division)
    digit_ratio = digits / length if length > 0 else 0.0
    letter_ratio = letters / length if length > 0 else 0.0
    vowel_ratio = vowels / letters if letters > 0 else 0.0
    consonant_ratio = consonants / letters if letters > 0 else 0.0

    # Entropy
    entropy = shannon_entropy(label_lower)
    norm_entropy = normalized_entropy(label_lower)

    # N-gram scores — lower score = less English-like = more DGA-like
    bigram_score = ngram_frequency_score(label_lower, 2, ENGLISH_BIGRAMS)
    trigram_score = ngram_frequency_score(label_lower, 3, ENGLISH_TRIGRAMS)

    # Full query length (includes subdomain + TLD dots)
    full_query_length = len(query)

    return {
        "domain_length": float(length),
        "full_query_length": float(full_query_length),
        "entropy": entropy,
        "normalized_entropy": norm_entropy,
        "digit_ratio": digit_ratio,
        "letter_ratio": letter_ratio,
        "vowel_ratio": vowel_ratio,
        "consonant_ratio": consonant_ratio,
        "bigram_score": bigram_score,
        "trigram_score": trigram_score,
    }


def _zero_domain_features() -> Dict[str, float]:
    """Zero-valued domain feature dict for empty/invalid inputs."""
    return {
        "domain_length": 0.0,
        "full_query_length": 0.0,
        "entropy": 0.0,
        "normalized_entropy": 0.0,
        "digit_ratio": 0.0,
        "letter_ratio": 0.0,
        "vowel_ratio": 0.0,
        "consonant_ratio": 0.0,
        "bigram_score": 0.0,
        "trigram_score": 0.0,
    }


# ── Feature name lists for ML input ordering ──────────────────────────────────
DGA_FEATURE_NAMES: List[str] = list(_zero_domain_features().keys())


# ─────────────────────────────────────────────────────────────────────────────
# PER-HOST-WINDOW FEATURES (for DGA behavioral scoring + DNS Tunnel detection)
# ─────────────────────────────────────────────────────────────────────────────

def extract_host_dns_features(
    records: List[DNSRecord],
    src_ip: Optional[str] = None,
) -> Dict[str, float]:
    """
    Extract host-level DNS behavioral features from a list of DNS records
    for ONE source host within a time window.

    Covers both:
    - DGA behavioral signals: query rate, NXDOMAIN ratio, unique domains
    - DNS tunnelling signals: query length, entropy of subdomains, record types

    Args:
        records: List of DNS record dicts. Expected keys:
                 timestamp, query, qtype, rcode, query_length (optional).
        src_ip:  Source IP (informational only).

    Returns:
        Feature dict with float values.
    """
    n = len(records)
    if n == 0:
        return _zero_host_features()

    sorted_records = sorted(records, key=lambda r: r["timestamp"])
    timestamps = [r["timestamp"] for r in sorted_records]
    queries = [r.get("query", "") for r in sorted_records]
    qtypes = [r.get("qtype", "A") for r in sorted_records]
    rcodes = [r.get("rcode", "NOERROR") for r in sorted_records]
    query_lengths = [r.get("query_length", len(q)) for r, q in zip(sorted_records, queries)]

    # ── Timing ────────────────────────────────────────────────────────────
    window_duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 1.0
    window_duration = max(window_duration, 0.001)  # avoid div-by-zero
    query_frequency = n / window_duration  # queries per second

    # ── NXDOMAIN analysis ─────────────────────────────────────────────────
    nxdomain_count = sum(1 for r in rcodes if r.upper() == "NXDOMAIN")
    nxdomain_ratio = nxdomain_count / n

    # ── Unique domain analysis ────────────────────────────────────────────
    unique_queries = len(set(q.lower() for q in queries if q))
    registered_domains = [_extract_registered_domain(q) for q in queries if q]
    unique_reg_domains = len(set(registered_domains))

    # Unique subdomains per registered domain (tunnelling signal)
    from collections import defaultdict
    subdomain_map: Dict[str, set] = defaultdict(set)
    for q in queries:
        reg = _extract_registered_domain(q)
        label = _extract_label(q)
        subdomain_map[reg].add(label)
    max_unique_subdomains = max((len(v) for v in subdomain_map.values()), default=0)
    avg_unique_subdomains = (
        sum(len(v) for v in subdomain_map.values()) / len(subdomain_map)
        if subdomain_map else 0.0
    )

    # ── Query length statistics ────────────────────────────────────────────
    mean_query_length = sum(query_lengths) / n
    max_query_length = max(query_lengths)

    # ── Entropy of subdomain labels (tunnelling signal) ───────────────────
    labels = [_extract_label(q) for q in queries if q]
    label_entropies = [shannon_entropy(lbl.lower()) for lbl in labels if lbl]
    mean_label_entropy = sum(label_entropies) / len(label_entropies) if label_entropies else 0.0
    max_label_entropy = max(label_entropies) if label_entropies else 0.0

    # ── Record type diversity ─────────────────────────────────────────────
    qtype_counts = Counter(qtypes)
    record_type_entropy = shannon_entropy("".join(qtypes))
    txt_ratio = qtype_counts.get("TXT", 0) / n
    mx_ratio = qtype_counts.get("MX", 0) / n

    return {
        # Volume
        "query_count": float(n),
        "query_frequency": query_frequency,
        # Domain diversity
        "unique_queries": float(unique_queries),
        "unique_reg_domains": float(unique_reg_domains),
        "max_unique_subdomains": float(max_unique_subdomains),
        "avg_unique_subdomains": avg_unique_subdomains,
        # NXDOMAIN
        "nxdomain_count": float(nxdomain_count),
        "nxdomain_ratio": nxdomain_ratio,
        # Query length (tunnel signal)
        "mean_query_length": mean_query_length,
        "max_query_length": float(max_query_length),
        # Label entropy (both DGA and tunnel signal)
        "mean_label_entropy": mean_label_entropy,
        "max_label_entropy": max_label_entropy,
        # Record type behavior
        "record_type_entropy": record_type_entropy,
        "txt_ratio": txt_ratio,
        "mx_ratio": mx_ratio,
    }


def _zero_host_features() -> Dict[str, float]:
    """Zero-valued host feature dict for empty windows."""
    return {
        "query_count": 0.0,
        "query_frequency": 0.0,
        "unique_queries": 0.0,
        "unique_reg_domains": 0.0,
        "max_unique_subdomains": 0.0,
        "avg_unique_subdomains": 0.0,
        "nxdomain_count": 0.0,
        "nxdomain_ratio": 0.0,
        "mean_query_length": 0.0,
        "max_query_length": 0.0,
        "mean_label_entropy": 0.0,
        "max_label_entropy": 0.0,
        "record_type_entropy": 0.0,
        "txt_ratio": 0.0,
        "mx_ratio": 0.0,
    }


HOST_DNS_FEATURE_NAMES: List[str] = list(_zero_host_features().keys())
