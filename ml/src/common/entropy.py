"""
src/common/entropy.py — Shannon entropy utilities used by both C2 and DNS modules.

Design rules:
- Functions are pure (no side effects, no global state).
- Division-by-zero and empty-input cases are handled explicitly.
- No detection logic here — only feature computation.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Sequence


def shannon_entropy(text: str) -> float:
    """
    Compute the Shannon entropy (bits) of the character distribution in `text`.

    H(X) = -Σ p(x) * log2(p(x))

    Returns 0.0 for empty strings.

    Args:
        text: Input string.

    Returns:
        Entropy in bits (float >= 0).
    """
    if not text:
        return 0.0

    counts = Counter(text)
    total = len(text)
    entropy = 0.0
    for count in counts.values():
        prob = count / total
        entropy -= prob * math.log2(prob)
    return entropy


def normalized_entropy(text: str) -> float:
    """
    Compute Shannon entropy normalized to [0, 1] by dividing by log2(|alphabet|).

    Returns 0.0 for strings with fewer than 2 distinct characters.

    Args:
        text: Input string.

    Returns:
        Normalized entropy in [0.0, 1.0].
    """
    if not text:
        return 0.0

    distinct = len(set(text))
    if distinct < 2:
        return 0.0

    return shannon_entropy(text) / math.log2(distinct)


def sequence_entropy(values: Sequence[float]) -> float:
    """
    Compute Shannon entropy over a sequence of numeric values by binning into
    a histogram of 10 equal-width buckets.

    Useful for measuring timing irregularity in inter-arrival time sequences.
    Returns 0.0 for empty or constant sequences.

    Args:
        values: Sequence of floats (e.g., inter-arrival times).

    Returns:
        Entropy in bits (float >= 0).
    """
    if not values:
        return 0.0

    min_val = min(values)
    max_val = max(values)

    if min_val == max_val:
        # Constant sequence — zero entropy
        return 0.0

    n_bins = 10
    bin_width = (max_val - min_val) / n_bins
    bins: Counter = Counter()

    for v in values:
        # Clamp the last bin boundary to avoid off-by-one
        bucket = min(int((v - min_val) / bin_width), n_bins - 1)
        bins[bucket] += 1

    total = len(values)
    entropy = 0.0
    for count in bins.values():
        prob = count / total
        entropy -= prob * math.log2(prob)
    return entropy
