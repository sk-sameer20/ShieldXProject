"""
src/common/ngrams.py — Character n-gram utilities for DGA lexical feature extraction.

Design rules:
- Functions are pure.
- N-gram size is always a parameter — never hardcoded.
- Reference frequency tables are bundled here so the DGA feature extractor
  can import them directly without external files.
"""

from __future__ import annotations

from collections import Counter
from typing import Dict, List


def get_ngrams(text: str, n: int) -> List[str]:
    """
    Extract all character n-grams from `text`.

    Args:
        text: Input string (e.g., a domain label).
        n:    N-gram size (2 for bigrams, 3 for trigrams).

    Returns:
        List of n-gram strings. Empty list if len(text) < n.
    """
    if not text or len(text) < n:
        return []
    return [text[i : i + n] for i in range(len(text) - n + 1)]


def ngram_frequency_score(
    text: str,
    n: int,
    reference_freq: Dict[str, float],
) -> float:
    """
    Compute the average log-probability of observed n-grams relative to a
    reference frequency table.

    A high (less negative) score means the n-grams look like the reference
    corpus (e.g., English). A low (more negative) score means the n-grams
    are rare/unusual — consistent with algorithmically generated strings.

    Returns 0.0 for empty text or when no n-grams overlap the reference.

    Args:
        text:           Input string.
        n:              N-gram size.
        reference_freq: Dict mapping n-gram → probability (values should sum ~1).

    Returns:
        Average log2 probability of observed n-grams (float <= 0).
    """
    ngrams = get_ngrams(text.lower(), n)
    if not ngrams:
        return 0.0

    # Use a small floor probability for unseen n-grams (Laplace smoothing proxy)
    floor_prob = 1e-6
    total_log = 0.0
    for ng in ngrams:
        prob = reference_freq.get(ng, floor_prob)
        import math
        total_log += math.log2(max(prob, floor_prob))

    return total_log / len(ngrams)


# ── English bigram frequency reference ───────────────────────────────────────
# Source: Compiled from public letter-frequency research (approximate values).
# These are character-pair frequencies in lowercase English text.
# Used as a reference to score how "English-like" a domain label is.
ENGLISH_BIGRAMS: Dict[str, float] = {
    "th": 0.0356, "he": 0.0307, "in": 0.0243, "er": 0.0205, "an": 0.0199,
    "re": 0.0185, "on": 0.0176, "at": 0.0149, "en": 0.0145, "nd": 0.0135,
    "ti": 0.0134, "es": 0.0134, "or": 0.0128, "te": 0.0120, "of": 0.0117,
    "ed": 0.0117, "is": 0.0113, "it": 0.0112, "al": 0.0109, "ar": 0.0107,
    "st": 0.0105, "to": 0.0104, "nt": 0.0104, "ng": 0.0095, "se": 0.0093,
    "ha": 0.0093, "as": 0.0087, "ou": 0.0087, "io": 0.0083, "le": 0.0083,
    "ve": 0.0083, "co": 0.0079, "me": 0.0079, "de": 0.0076, "hi": 0.0076,
    "ri": 0.0073, "ro": 0.0073, "ic": 0.0070, "ne": 0.0069, "ea": 0.0069,
    "ra": 0.0069, "ce": 0.0065, "li": 0.0062, "ch": 0.0060, "ll": 0.0058,
    "be": 0.0058, "ma": 0.0057, "si": 0.0055, "om": 0.0055, "ur": 0.0054,
    "ca": 0.0053, "el": 0.0050, "ta": 0.0050, "la": 0.0047, "na": 0.0046,
    "fo": 0.0045, "sh": 0.0033, "wh": 0.0030, "qu": 0.0010,
}

# ── English trigram frequency reference ──────────────────────────────────────
ENGLISH_TRIGRAMS: Dict[str, float] = {
    "the": 0.0181, "and": 0.0073, "ing": 0.0072, "ion": 0.0042, "tio": 0.0031,
    "ent": 0.0028, "ati": 0.0026, "for": 0.0025, "her": 0.0024, "ter": 0.0024,
    "hat": 0.0023, "tha": 0.0021, "ere": 0.0020, "ate": 0.0020, "his": 0.0019,
    "con": 0.0018, "res": 0.0017, "ver": 0.0017, "all": 0.0016, "ons": 0.0016,
    "nce": 0.0016, "men": 0.0015, "ith": 0.0015, "ted": 0.0015, "ers": 0.0015,
    "pro": 0.0014, "thi": 0.0014, "wit": 0.0014, "are": 0.0014, "ess": 0.0014,
    "not": 0.0013, "ive": 0.0013, "was": 0.0013, "ect": 0.0012, "rea": 0.0012,
    "com": 0.0012, "eve": 0.0012, "per": 0.0012, "int": 0.0011, "est": 0.0011,
    "sta": 0.0011, "cti": 0.0011, "ica": 0.0010, "ist": 0.0010, "ear": 0.0010,
}
