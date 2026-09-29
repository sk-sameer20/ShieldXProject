import math
from typing import List, Dict, Any
from src.ingestion.parser import NetworkEvent


def calculate_shannon_entropy(text: str) -> float:
    """
    Computes Shannon entropy of a string (bits per character).
    Higher values indicate random/generated domain names (DGA).
    """
    if not text:
        return 0.0
    text = text.lower()
    length = float(len(text))
    frequencies = {}
    for char in text:
        frequencies[char] = frequencies.get(char, 0) + 1
    
    entropy = 0.0
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(entropy)


class DNSFeatureAdapter:
    """
    Extracts domain name entropy, length, and query frequency features from a DNS sliding window.
    """

    def extract_features(self, events: List[NetworkEvent], window_seconds: float = 60.0) -> Dict[str, Any]:
        # Filter for DNS events or events containing query strings
        dns_events = [e for e in events if e.query or e.dst_port == 53 or e.src_port == 53]
        
        if not dns_events:
            return {
                "unique_domains_count": 0,
                "avg_domain_length": 0.0,
                "avg_shannon_entropy": 0.0,
                "max_shannon_entropy": 0.0,
                "query_rate": 0.0,
                "total_queries": 0,
            }

        queries = [e.query for e in dns_events if e.query]
        if not queries:
            queries = [e.dst_ip for e in dns_events]

        unique_domains = set(queries)
        domain_lengths = [len(q) for q in queries]
        entropies = [calculate_shannon_entropy(q) for q in queries]

        actual_window = max(window_seconds, 0.1)

        return {
            "unique_domains_count": len(unique_domains),
            "avg_domain_length": float(sum(domain_lengths) / len(domain_lengths)) if domain_lengths else 0.0,
            "avg_shannon_entropy": float(sum(entropies) / len(entropies)) if entropies else 0.0,
            "max_shannon_entropy": float(max(entropies)) if entropies else 0.0,
            "query_rate": float(len(dns_events) / actual_window),
            "total_queries": len(dns_events),
        }
