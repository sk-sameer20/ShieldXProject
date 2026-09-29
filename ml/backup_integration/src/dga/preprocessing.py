"""
src/dga/preprocessing.py — DGA text preprocessing functions.
"""

def extract_label(query: str) -> str:
    """Extract the primary label (registered domain) from a FQDN."""
    parts = str(query).rstrip(".").split(".")
    # Basic extraction (ideally tldextract should be used in production)
    return parts[0] if parts else str(query)

def preprocess_domain(query: str) -> str:
    """Normalize domain strings for DGA detection."""
    return extract_label(query).lower()

def encode_domain_for_cnn(domain: str, vocab: dict, max_len: int) -> list:
    """Encode a domain string into character indices with padding."""
    seq = [vocab.get(c, 1) for c in domain] # 1 is UNK
    if len(seq) > max_len:
        return seq[:max_len]
    return seq + [0] * (max_len - len(seq)) # 0 is PAD
