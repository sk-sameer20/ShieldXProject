"""
src/config.py — Central configuration loader for SIH26145 C2+DGA/DNS module.

Loads config.yaml from the project root and exposes typed accessors.
All thresholds and parameters must be read from here — never hardcoded.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import List

import yaml


# ── Locate the project root (two levels up from this file) ──────────────────
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_CONFIG_PATH = _PROJECT_ROOT / "config.yaml"


@dataclass
class WindowConfig:
    c2_seconds: int
    dns_seconds: int


@dataclass
class NetworkConfig:
    internal_subnets: List[str]


@dataclass
class C2Config:
    min_connections: int
    contamination: float
    periodicity_lag_max: int
    repetition_ratio_threshold: float


@dataclass
class DGAConfig:
    entropy_threshold: float
    length_threshold: int
    digit_ratio_threshold: float
    nxdomain_ratio_threshold: float


@dataclass
class DNSTunnelConfig:
    query_length_threshold: int
    entropy_threshold: float
    query_freq_threshold: float
    unique_subdomain_threshold: int


@dataclass
class ModelsConfig:
    c2_version: str
    dga_version: str
    dns_version: str


@dataclass
class AppConfig:
    windows: WindowConfig
    network: NetworkConfig
    c2: C2Config
    dga: DGAConfig
    dns_tunnel: DNSTunnelConfig
    models: ModelsConfig


def load_config(path: Path | None = None) -> AppConfig:
    """Load and parse config.yaml. Raises FileNotFoundError if missing."""
    config_path = path or _CONFIG_PATH
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    return AppConfig(
        windows=WindowConfig(**raw["windows"]),
        network=NetworkConfig(**raw["network"]),
        c2=C2Config(**raw["c2"]),
        dga=DGAConfig(**raw["dga"]),
        dns_tunnel=DNSTunnelConfig(**raw["dns_tunnel"]),
        models=ModelsConfig(**raw["models"]),
    )


# Module-level singleton — import and use directly in other modules.
# Example:  from src.config import CONFIG
#           CONFIG.c2.contamination
CONFIG: AppConfig = load_config()
