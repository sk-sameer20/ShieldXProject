"""
SQLAlchemy 2.0 Models for System Health and Hardware Diode Integrity
"""
from datetime import datetime
from typing import Any, Dict, List
from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Integer,
    String,
    JSON,
)
from sqlalchemy.orm import Mapped, mapped_column
from .base import Base, TimestampMixin, utc_now


class SystemHealth(Base, TimestampMixin):
    """
    SOC system telemetry, hardware resource gauges, and data collector statuses.
    """
    __tablename__ = "system_health"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        index=True,
        nullable=False,
    )

    status: Mapped[str] = mapped_column(String(32), default="Healthy", nullable=False)
    cpu_pct: Mapped[float] = mapped_column(Float, default=98.0, nullable=False)
    cpu_detail: Mapped[str] = mapped_column(String(64), default="32 Cores · 48°C")

    memory_pct: Mapped[float] = mapped_column(Float, default=76.0, nullable=False)
    memory_detail: Mapped[str] = mapped_column(String(64), default="24.3 / 32 GB")

    storage_pct: Mapped[float] = mapped_column(Float, default=92.0, nullable=False)
    storage_detail: Mapped[str] = mapped_column(String(64), default="3.8 / 4.0 TB NVMe")

    sensors_pct: Mapped[float] = mapped_column(Float, default=100.0, nullable=False)
    sensors_detail: Mapped[str] = mapped_column(String(64), default="12 / 12 Online")

    sources_json: Mapped[List[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
        doc="List of collector statuses and latencies",
    )
    sensor_network_json: Mapped[Dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
        doc="Sensor network uptime and region distribution",
    )


class DiodeIntegrity(Base, TimestampMixin):
    """
    Hardware Data Diode assurance state and cryptographic tamper-evident audit chain.
    """
    __tablename__ = "diode_integrity"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        index=True,
        nullable=False,
    )

    # Physical Diode Link Specs
    physical_link_rx: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    physical_link_tx: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    optical_power_dbm: Mapped[float] = mapped_column(Float, default=-13.8, nullable=False)
    ring_buffer_utilization_pct: Mapped[float] = mapped_column(Float, default=18.4, nullable=False)
    dropped_frames: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    diode_state: Mapped[str] = mapped_column(String(32), default="NOMINAL", nullable=False)

    # Zeek Worker Metrics
    zeek_worker_threads: Mapped[int] = mapped_column(Integer, default=4, nullable=False)
    zeek_cpu_usage_pct: Mapped[float] = mapped_column(Float, default=14.2, nullable=False)
    zeek_memory_usage_mb: Mapped[int] = mapped_column(Integer, default=842, nullable=False)
    zeek_uptime_seconds: Mapped[int] = mapped_column(Integer, default=432190, nullable=False)

    # Latency & Cryptographic Audit Hash
    pipeline_latency_ms: Mapped[float] = mapped_column(Float, default=1.28, nullable=False)
    tamper_evident_chain_valid: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_audit_hash: Mapped[str] = mapped_column(
        String(128),
        default="8f43a9b1c78e3290deaf1455bb39c011e4f9b8c2d1109a8734e5f901a1829bc3",
        nullable=False,
    )
