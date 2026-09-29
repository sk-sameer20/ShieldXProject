"""
SQLAlchemy 2.0 Model for Security Alerts
"""
from datetime import datetime
from typing import Any, Dict, Optional
from sqlalchemy import (
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    JSON,
)
from sqlalchemy.orm import Mapped, mapped_column
from .base import Base, TimestampMixin, utc_now


class Alert(Base, TimestampMixin):
    """
    Primary Security Alert entity representing evidence fusion detections
    from Zeek and ML models (DDoS, C2 Beaconing, DGA / DNS Tunneling, Anomalies).
    """
    __tablename__ = "alerts"

    # Primary Identifier (e.g., 'alt-ddos-8901')
    alert_id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        index=True,
        doc="Unique alert identifier string (e.g. alt-ddos-8901)",
    )

    # Ingress Detection Timestamp
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        index=True,
        nullable=False,
        doc="UTC timestamp when the alert event was detected",
    )

    # Classification & Severity
    threat_class: Mapped[str] = mapped_column(
        String(64),
        index=True,
        nullable=False,
        doc="Taxonomy category (DDOS, C2_BEACONING, DGA_DNS_TUNNEL, ANOMALY)",
    )
    attack_classification: Mapped[str] = mapped_column(
        String(128),
        index=True,
        nullable=False,
        doc="Specific attack classification string (e.g., DDOS, C2_BEACONING)",
    )
    severity: Mapped[str] = mapped_column(
        String(16),
        index=True,
        nullable=False,
        doc="Normalized severity level: CRITICAL, HIGH, MEDIUM, LOW",
    )
    confidence: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
        doc="Confidence score from 0.00 to 1.00 (or percentage equivalent)",
    )

    # Network Telemetry
    source_ip: Mapped[str] = mapped_column(
        String(45),
        index=True,
        nullable=False,
        doc="Ingress source IP address from passive TAP",
    )
    destination_ip: Mapped[str] = mapped_column(
        String(45),
        index=True,
        nullable=False,
        doc="Target protected enclave IP address",
    )
    source_port: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        doc="Ingress source port number",
    )
    destination_port: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        doc="Target destination port number",
    )
    transport_protocol: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="TCP",
        doc="Transport / application protocol identifier (e.g. TCP, UDP, DNS, TCP : 443)",
    )

    # Lifecycle & Triage State
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="Mitigated",
        doc="Operational action status: Mitigated, Blocked, Alerted, Monitored",
    )
    triage_status: Mapped[str] = mapped_column(
        String(32),
        index=True,
        nullable=False,
        default="NEW",
        doc="Operator lifecycle state: NEW, INVESTIGATING, ESCALATED, RESOLVED, FALSE_POSITIVE",
    )

    # Machine Learning / Detector Attribution
    model_version: Mapped[Optional[str]] = mapped_column(
        String(32),
        nullable=True,
        doc="Version identifier of the detector model or ensemble (e.g., v3.2.0)",
    )
    detector_model: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        doc="Name of the model or rule generating this alert (e.g., Ensemble-Volumetric-SYN-Burst)",
    )
    mitre_technique: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        doc="MITRE ATT&CK technique ID (e.g., T1498.001, T1071.001)",
    )

    # Human-Readable Reasoning & Explainability
    reason: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="Why the detector flagged this: explainability statement for SOC operator",
    )

    # Structured Data Payloads (JSON)
    evidence: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
        doc="Evidence fusion payload including tactic, triggered features, and heuristic checks",
    )
    trigger_features: Mapped[Dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
        doc="Specific numerical/categorical feature values that triggered the alert decision",
    )
    metadata_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
        doc="Supplementary UI metadata such as waveform bars, date labels, packet dumps",
    )

    # Composite indexes for high-frequency queries and filtering
    __table_args__ = (
        Index("ix_alerts_severity_timestamp", "severity", "timestamp"),
        Index("ix_alerts_threat_class_timestamp", "threat_class", "timestamp"),
        Index("ix_alerts_triage_timestamp", "triage_status", "timestamp"),
        Index("ix_alerts_src_dest_ip", "source_ip", "destination_ip"),
    )

    def __repr__(self) -> str:
        return f"<Alert alert_id={self.alert_id} severity={self.severity} threat_class={self.threat_class} triage={self.triage_status}>"
