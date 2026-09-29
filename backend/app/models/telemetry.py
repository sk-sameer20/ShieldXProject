"""
SQLAlchemy 2.0 Models for Rolling Telemetry Snapshots and Protocol Distributions
"""
from datetime import datetime
from typing import List, Optional
from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .base import Base, TimestampMixin, utc_now


class TelemetrySnapshot(Base, TimestampMixin):
    """
    Periodic sliding-window telemetry captured from the Zeek passive tap.
    Used for KPI metric rows and the live dual-axis traffic rate chart.
    """
    __tablename__ = "telemetry_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        index=True,
        nullable=False,
    )

    # Ingress throughput metrics
    packets_per_sec: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    bytes_per_sec: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    active_flows_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Threat and alert counters
    threat_alerts_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    threat_alerts_critical: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    detection_latency_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    # Passive diode constraint metrics
    actual_egress_packets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    actual_egress_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sliding_window_sec: Mapped[float] = mapped_column(Float, nullable=False, default=10.0)
    flow_asymmetry_index: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)

    # DNS query rate monitoring
    dns_qps: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    dns_surge_pct: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Relationship to protocol breakdown
    protocols: Mapped[List["ProtocolDistribution"]] = relationship(
        "ProtocolDistribution",
        back_populates="snapshot",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_telemetry_timestamp_desc", timestamp.desc()),
    )


class ProtocolDistribution(Base, TimestampMixin):
    """
    Protocol composition breakdown (TCP, UDP, DNS, ICMP) within a sliding window.
    """
    __tablename__ = "protocol_distributions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    snapshot_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("telemetry_snapshots.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        index=True,
        nullable=False,
    )

    protocol_name: Mapped[str] = mapped_column(String(16), nullable=False)
    packet_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    byte_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    bandwidth_pct: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    dot_color: Mapped[str] = mapped_column(String(16), nullable=False, default="#2563eb")

    snapshot: Mapped[Optional["TelemetrySnapshot"]] = relationship(
        "TelemetrySnapshot",
        back_populates="protocols",
    )
