"""
Pydantic v2 Validation & Serialization Schemas for ShieldX SOC
Strict validation contracts for Ingestion, REST APIs, and WebSockets.
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    field_validator,
    model_validator,
)


# ═══════════════════════════════════════════════════════════════
# ENUMS
# ═══════════════════════════════════════════════════════════════

class AlertSeverity(str, Enum):
    """Normalized alert severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TriageStatus(str, Enum):
    """Incident operator triage lifecycle states."""
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    ESCALATED = "ESCALATED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class AlertStatus(str, Enum):
    """Operational mitigation / action status."""
    MITIGATED = "Mitigated"
    BLOCKED = "Blocked"
    ALERTED = "Alerted"
    MONITORED = "Monitored"


class ThreatClass(str, Enum):
    """Attack classification taxonomy."""
    DDOS = "DDOS"
    C2_BEACONING = "C2_BEACONING"
    DGA_DNS_TUNNEL = "DGA_DNS_TUNNEL"
    ANOMALY = "ANOMALY"
    SCANNING = "SCANNING"
    EXPLOITATION = "EXPLOITATION"
    MALWARE = "MALWARE"
    BOTNET = "BOTNET"
    POLICY_VIOLATION = "POLICY_VIOLATION"


# ═══════════════════════════════════════════════════════════════
# 4. ALERT EVIDENCE SCHEMA
# ═══════════════════════════════════════════════════════════════

class AlertEvidence(BaseModel):
    """
    Evidence fusion metrics and heuristic explainability.
    """
    model_config = ConfigDict(extra="allow")

    rule_or_model: str = Field(..., min_length=1, description="Rule or ML model name")
    trigger_features: Dict[str, Any] = Field(default_factory=dict, description="Feature triggering values")
    why_flagged: str = Field(..., min_length=1, description="Operator explanation statement")
    mitre_technique_id: Optional[str] = Field(None, pattern=r"^T\d{4}(\.\d{3})?$", description="MITRE Technique ID (e.g. T1498.001)")
    mitre_tactic: Optional[str] = Field(None, description="MITRE Tactic name")


# ═══════════════════════════════════════════════════════════════
# 1. ALERT CREATE SCHEMA (INGESTION & MUTATION)
# ═══════════════════════════════════════════════════════════════

class AlertCreate(BaseModel):
    """
    Schema for creating or ingesting a new security alert into the enclave store.
    Strictly validates IP addresses, confidence bounds [0.0, 1.0], and enums.
    """
    model_config = ConfigDict(extra="forbid")

    alert_id: str = Field(..., min_length=3, max_length=64, description="Unique alert UUID/string")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Detection time in UTC")
    threat_class: Union[ThreatClass, str] = Field(..., description="Threat classification taxonomy")
    attack_classification: str = Field(..., min_length=1, max_length=128, description="Display attack type")
    severity: AlertSeverity = Field(..., description="Normalized severity level")
    
    # Critical requirement: confidence must be between 0 and 1
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score strictly between 0.00 and 1.00",
    )

    # Validated IP Addresses using IPvAnyAddress
    source_ip: IPvAnyAddress = Field(..., description="Ingress source IPv4/IPv6 address")
    destination_ip: IPvAnyAddress = Field(..., description="Protected target IPv4/IPv6 address")
    source_port: Optional[int] = Field(None, ge=1, le=65535, description="Ingress port")
    destination_port: Optional[int] = Field(None, ge=1, le=65535, description="Target port")
    transport_protocol: str = Field(..., min_length=1, max_length=32, description="Protocol (e.g. TCP, UDP, DNS, TCP : 443)")

    status: AlertStatus = Field(default=AlertStatus.MITIGATED, description="Operational action status")
    triage_status: TriageStatus = Field(default=TriageStatus.NEW, description="Triage lifecycle state")
    model_version: Optional[str] = Field(None, max_length=32, description="Detector version (e.g. v3.2.0)")
    detector_model: str = Field(..., min_length=1, max_length=128, description="Detector name")
    mitre_technique: Optional[str] = Field(None, max_length=64, description="MITRE Technique ID")
    reason: str = Field(..., min_length=1, description="Explainability reasoning")

    evidence: Optional[Union[AlertEvidence, Dict[str, Any]]] = Field(default=None, description="Structured evidence details")
    trigger_features: Dict[str, Any] = Field(default_factory=dict, description="Feature values dict")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="UI metadata and waveforms")

    @field_validator("source_ip", "destination_ip", mode="after")
    @classmethod
    def serialize_ip_to_str(cls, v: IPvAnyAddress) -> str:
        """Convert IPvAnyAddress to canonical string representation."""
        return str(v)


# ═══════════════════════════════════════════════════════════════
# 2. ALERT RESPONSE SCHEMA (FRONTEND COMPATIBLE)
# ═══════════════════════════════════════════════════════════════

class AlertResponse(BaseModel):
    """
    Full security alert response contract supporting both camelCase frontend properties
    and snake_case database schema fields.
    """
    model_config = ConfigDict(from_attributes=True)

    # Identifiers
    id: str = Field(..., description="Alert ID for frontend compatibility")
    alert_id: str = Field(..., description="Canonical alert ID")

    # Timestamps
    timestamp: datetime = Field(..., description="UTC detection timestamp")
    time: str = Field(..., description="Formatted time string (e.g. '05:11:12')")
    dateLabel: str = Field("Today", description="Relative date label ('Today', 'Yesterday')")

    # Classification & Severity
    severity: AlertSeverity = Field(..., description="Severity level")
    classification: str = Field(..., description="Attack classification display name")
    attack_classification: Optional[str] = Field(None, description="Canonical attack classification")
    threat_class: str = Field(..., description="Taxonomy classification")

    # Network Telemetry
    srcIp: str = Field(..., description="Source IP string")
    destIp: str = Field(..., description="Destination IP string")
    source_ip: str = Field(..., description="Source IP string")
    destination_ip: str = Field(..., description="Destination IP string")
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: str = Field(..., description="Transport protocol string")

    # Confidence (strictly bounded)
    confidence: float = Field(..., ge=0.0, le=1.0, description="Float confidence between 0 and 1")
    confidence_pct: float = Field(..., ge=0.0, le=100.0, description="Percentage confidence 0 - 100")
    confidenceFormatted: str = Field(..., description="Formatted string (e.g. '98.0%')")

    # Triage & Status
    triage: str = Field(..., description="Triage display label")
    triage_status: TriageStatus = Field(..., description="Canonical triage enum")
    triageType: str = Field("danger", description="Badge styling: danger, info, success, warning")
    status: AlertStatus = Field(..., description="Mitigation action status")
    accentColor: str = Field("#ef4444", description="Hex accent color")

    # Explainability & Attribution
    whyFlagged: str = Field(..., description="Explainability statement")
    reason: str = Field(..., description="Reasoning statement")
    detectorModel: str = Field(..., description="Detector model name")
    detector_model: str = Field(..., description="Detector model name")
    mitre: str = Field("", description="MITRE Technique")
    mitre_technique: Optional[str] = None

    # Payloads
    triggerFeatures: Dict[str, Any] = Field(default_factory=dict, description="Trigger features")
    trigger_features: Dict[str, Any] = Field(default_factory=dict, description="Trigger features")
    evidence: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None
    waveform_bars: Optional[List[int]] = None
    raw_packet_snippet: Optional[str] = None
    throughput_peak: Optional[str] = None


# ═══════════════════════════════════════════════════════════════
# 3. ALERT LIST RESPONSE SCHEMA
# ═══════════════════════════════════════════════════════════════

class AlertListResponse(BaseModel):
    """
    Paginated incident queue list with category counts.
    """
    model_config = ConfigDict(from_attributes=True)

    total: int = Field(..., ge=0, description="Total matching alert count")
    counts: Dict[str, int] = Field(
        default_factory=lambda: {"all": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        description="Pre-aggregated counts per severity category",
    )
    items: List[AlertResponse] = Field(default_factory=list, description="List of alert responses")
    page: int = Field(default=1, ge=1, description="Current page number")
    page_size: int = Field(default=10, ge=1, description="Items per page")
    total_pages: int = Field(default=1, ge=1, description="Total pages")


# ═══════════════════════════════════════════════════════════════
# 5. DETECTOR STATUS SCHEMA
# ═══════════════════════════════════════════════════════════════

class DetectorStatus(BaseModel):
    """
    Active status and operational metrics for an ML detection engine.
    """
    model_config = ConfigDict(from_attributes=True)

    engine_type: str = Field(..., description="Engine identifier: DDOS, C2, DGA")
    status: str = Field(..., description="Engine state: ACTIVE THREAT, 1 BEACON, ENTROPY SPIKE, NOMINAL")
    rule_name: str = Field(..., description="Underlying ensemble or detector rule")
    target_host: str = Field(..., description="Target or infected host IP:port")
    attack_vector: str = Field(..., description="Attack vector or external C2 node")
    cadence_or_duration: str = Field(..., description="Observed cadence or duration statement")
    recommended_action: str = Field(..., description="Operator playbook action")
    metrics: Dict[str, Any] = Field(default_factory=dict, description="Engine specific curve points and thresholds")


# ═══════════════════════════════════════════════════════════════
# 6. STATISTICS SCHEMA (CALCULATED FROM DATABASE RECORDS)
# ═══════════════════════════════════════════════════════════════

class Statistics(BaseModel):
    """
    Dynamic telemetry and alert statistics aggregated from active database rows.
    """
    model_config = ConfigDict(from_attributes=True)

    total_alerts: int = Field(..., ge=0, description="Total alert count")
    critical_count: int = Field(..., ge=0, description="Critical alert count")
    high_count: int = Field(..., ge=0, description="High alert count")
    medium_count: int = Field(..., ge=0, description="Medium alert count")
    low_count: int = Field(..., ge=0, description="Low alert count")

    active_flows: int = Field(..., ge=0, description="Current active flows in window")
    packets_per_sec: float = Field(..., ge=0.0, description="Current ingress packet rate")
    bytes_per_sec: float = Field(..., ge=0.0, description="Current ingress byte rate")
    mbps: float = Field(..., ge=0.0, description="Throughput in Megabits/sec")
    detection_latency_ms: float = Field(..., ge=0.0, description="Average pipeline inference latency")
    actual_egress_packets: int = Field(default=0, ge=0, le=0, description="Egress packet count (guaranteed 0)")
    actual_egress_bytes: int = Field(default=0, ge=0, le=0, description="Egress byte count (guaranteed 0)")


# ═══════════════════════════════════════════════════════════════
# 7. THREAT DISTRIBUTION SCHEMA
# ═══════════════════════════════════════════════════════════════

class ThreatCategoryItem(BaseModel):
    """Individual threat slice in the distribution breakdown."""
    label: str = Field(..., description="Threat label (e.g. DDoS, C2, Scanning)")
    pct: float = Field(..., ge=0.0, le=100.0, description="Percentage share")
    pct_formatted: str = Field(..., description="Formatted percentage string (e.g. '34%')")
    count: int = Field(..., ge=0, description="Incident count")
    color: str = Field(..., description="Hex color token for UI rendering")


class ThreatDistribution(BaseModel):
    """
    Aggregated threat taxonomy distribution for the donut visualization.
    """
    model_config = ConfigDict(from_attributes=True)

    filter_mode: str = Field("Observed (Inbound)", description="Active filter mode")
    total_threats: int = Field(..., ge=0, description="Total classified threat events")
    categories: List[ThreatCategoryItem] = Field(default_factory=list, description="Category slices")


# ═══════════════════════════════════════════════════════════════
# 8. TIMELINE POINT SCHEMA
# ═══════════════════════════════════════════════════════════════

class TimelinePoint(BaseModel):
    """
    Point in time representing an incident event for audit logs and timelines.
    """
    model_config = ConfigDict(from_attributes=True)

    timestamp: datetime = Field(..., description="Event time in UTC")
    time_label: str = Field(..., description="Formatted time string (e.g. '14:24:17')")
    event_type: str = Field(..., description="Event classification (e.g. DDoS Surge, C2 Beacon)")
    severity: AlertSeverity = Field(..., description="Event severity")
    description: str = Field(..., description="Event narrative")
    source_ip: Optional[str] = Field(None, description="Originating ingress IP")


# ═══════════════════════════════════════════════════════════════
# 9. TRAFFIC POINT SCHEMA (TIME SERIES & CHARTS)
# ═══════════════════════════════════════════════════════════════

class TrafficPoint(BaseModel):
    """
    Telemetry sample point for the live traffic rate chart.
    """
    model_config = ConfigDict(from_attributes=True)

    timestamp: datetime = Field(..., description="Sample timestamp in UTC")
    time_label: str = Field(..., description="Display label (e.g. '14:24')")
    packets_per_sec: float = Field(..., ge=0.0, description="Ingress packets per second")
    bytes_per_sec: float = Field(..., ge=0.0, description="Ingress bytes per second")
    mbps: float = Field(..., ge=0.0, description="Throughput in MB/s")
    is_anomaly: bool = Field(default=False, description="Whether this point is flagged as an anomaly")
    anomaly_val: Optional[str] = Field(None, description="Callout text if anomaly (e.g. '21.4K pps')")


# ═══════════════════════════════════════════════════════════════
# 10. HEALTH RESPONSE SCHEMA
# ═══════════════════════════════════════════════════════════════

class GaugeItem(BaseModel):
    """Circular HUD health gauge reading."""
    label: str = Field(..., description="Resource name: CPU, Memory, Storage, Sensors")
    val: float = Field(..., ge=0.0, le=100.0, description="Percentage utilization")
    detail: str = Field(..., description="Human-readable detail string (e.g. '32 Cores · 48°C')")
    color: str = Field(..., description="Hex color indicator")


class DataSourceItem(BaseModel):
    """Collector status and latency reading."""
    name: str = Field(..., description="Data source name")
    status: str = Field("Online", description="Online / Offline status")
    latency: str = Field(..., description="Observed network latency (e.g. '1.2ms')")


class SensorNetworkItem(BaseModel):
    """Sensor network summary metrics."""
    online_sensors: int = Field(..., ge=0)
    total_sensors: int = Field(..., ge=0)
    regions_count: int = Field(..., ge=0)
    uptime_pct: float = Field(..., ge=0.0, le=100.0)
    avg_latency: str = Field(..., description="Average latency string")


class DiodeIntegrityItem(BaseModel):
    """Hardware data diode physical link assurance."""
    physical_link_rx: bool = Field(True, description="Optical RX active")
    physical_link_tx: bool = Field(False, description="Physical TX severed (MUST be False)")
    optical_power_dbm: float = Field(..., description="Measured light intensity (-14 dBm)")
    ring_buffer_utilization_pct: float = Field(..., ge=0.0, le=100.0)
    dropped_frames: int = Field(0, ge=0)
    diode_state: str = Field("NOMINAL", description="NOMINAL / DEGRADED")
    tamper_evident_chain_valid: bool = Field(True, description="Cryptographic audit validity")
    last_audit_hash: str = Field(..., description="SHA-256 block hash")


class HealthResponse(BaseModel):
    """
    Combined system health, gauges, data sources, and diode integrity status.
    """
    model_config = ConfigDict(from_attributes=True)

    status: str = Field("Healthy", description="Overall health indicator")
    gauges: List[GaugeItem] = Field(default_factory=list, description="4 core HUD gauges")
    sources: List[DataSourceItem] = Field(default_factory=list, description="Data collector statuses")
    sensor_network: SensorNetworkItem = Field(..., description="Sensor network status")
    diode_integrity: DiodeIntegrityItem = Field(..., description="Optical diode hardware link status")


# ═══════════════════════════════════════════════════════════════
# 11. WEBSOCKET ALERT EVENT SCHEMA
# ═══════════════════════════════════════════════════════════════

class WebSocketAlertEvent(BaseModel):
    """
    Real-time push event dispatched over WebSocket when a new alert is ingested.
    """
    event: str = Field(default="NEW_ALERT", description="Event name identifier")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Event timestamp")
    data: AlertResponse = Field(..., description="Full alert response payload")
