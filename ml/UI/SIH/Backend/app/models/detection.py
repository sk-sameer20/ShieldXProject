"""
SQLAlchemy 2.0 Model for Engine Detection Attributions
"""
from typing import Any, Dict
from sqlalchemy import JSON, String
from sqlalchemy.orm import Mapped, mapped_column
from .base import Base, TimestampMixin


class DetectionAttribution(Base, TimestampMixin):
    """
    Core threat detection engine telemetry and attribution summary:
    - DDOS: SYN surge, ingress IP entropy, unidirectional asymmetry, XGBoost confidence
    - C2: Beaconing rhythm, cadence interval, jitter tolerance, LSTM detector
    - DGA: DNS tunneling, Shannon entropy, NXDOMAIN burst rate, query length
    """
    __tablename__ = "detection_attributions"

    engine_type: Mapped[str] = mapped_column(
        String(16),
        primary_key=True,
        doc="Engine identifier: DDOS, C2, DGA",
    )
    status_badge: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="ACTIVE THREAT",
        doc="Engine status banner: ACTIVE THREAT, 1 BEACON, ENTROPY SPIKE",
    )
    rule_name: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        doc="Detection rule name / ensemble name",
    )
    target_host: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        doc="Active protected target IP or infected internal host",
    )
    attack_vector: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        doc="Vector description or external C2 node IP",
    )
    cadence_or_duration: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        doc="Observed duration or cadence interval metric",
    )
    recommended_action: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        doc="Operational action recommendation",
    )

    metrics_json: Mapped[Dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
        doc="Detailed chart points, thresholds, and sensor values",
    )
