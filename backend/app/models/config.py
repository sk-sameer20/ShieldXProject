"""
SQLAlchemy 2.0 Model for Hardware Enclave Settings & Calibration
"""
from typing import Any, Dict
from sqlalchemy import Boolean, Float, Integer, JSON
from sqlalchemy.orm import Mapped, mapped_column
from .base import Base, TimestampMixin


class EnclaveConfig(Base, TimestampMixin):
    """
    Singleton configuration row (id=1) representing hardware optical tap settings,
    Zeek sliding window durations, and ML detection engine thresholds.
    """
    __tablename__ = "enclave_configs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)

    # Hardware Diode & Buffer
    rx_diode_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    tx_airgap_enforced: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    ring_buffer_size_mb: Mapped[int] = mapped_column(Integer, default=4096, nullable=False)

    # Zeek DPI & Sliding Window
    sliding_window_sec: Mapped[float] = mapped_column(Float, default=10.0, nullable=False)
    track_protocols: Mapped[Dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        default=lambda: {"tcp": True, "udp": True, "dns": True, "icmp": True},
    )

    # ML Detection Thresholds
    syn_threshold_pps: Mapped[int] = mapped_column(Integer, default=5000, nullable=False)
    entropy_cutoff: Mapped[float] = mapped_column(Float, default=1.12, nullable=False)
    c2_jitter_threshold: Mapped[float] = mapped_column(Float, default=2.4, nullable=False)
    confidence_floor: Mapped[int] = mapped_column(Integer, default=85, nullable=False)

    # Telemetry Stream & Alert Dispatch
    ws_batch_rate_ms: Mapped[int] = mapped_column(Integer, default=1000, nullable=False)
    zstd_compression: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    sound_alerts: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    auto_escalate_critical: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
