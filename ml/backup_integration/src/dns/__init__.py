"""
src/dns/__init__.py
"""
from src.dns.inference import run_dns_tunnel_detection
from src.dns.tunnel import DNSTunnelDetector

__all__ = ["run_dns_tunnel_detection", "DNSTunnelDetector"]
