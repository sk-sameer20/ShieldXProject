"""
Alert Service Layer for ShieldX SOC
Handles querying, filtering, statistics calculation, and mutations for security alerts.
All aggregations, distribution metrics, and counts are calculated dynamically from SQLite.
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.schemas import (
    AlertCreate,
    AlertEvidence,
    AlertListResponse,
    AlertResponse,
    AlertSeverity,
    AlertStatus,
    ThreatCategoryItem,
    ThreatClass,
    ThreatDistribution,
    TimelinePoint,
    TriageStatus,
)


# Color mapping for threat taxonomy slices in frontend donut
THREAT_CLASS_COLORS: Dict[str, str] = {
    "DDOS": "#ef4444",
    "C2_BEACONING": "#f97316",
    "SCANNING": "#f59e0b",
    "MALWARE": "#a855f7",
    "EXPLOITATION": "#3b82f6",
    "BOTNET": "#10b981",
    "POLICY_VIOLATION": "#6366f1",
    "ANOMALY": "#00d2ff",
    "DGA": "#8b5cf6",
    "DNS_TUNNEL": "#eab308",
    "DNS": "#eab308",
    "DGA_DNS_TUNNEL": "#8b5cf6",
}

SEVERITY_COLORS: Dict[str, str] = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#10b981",
}

TRIAGE_TYPE_MAP: Dict[str, str] = {
    "NEW": "danger",
    "INVESTIGATING": "info",
    "ESCALATED": "danger",
    "RESOLVED": "success",
    "FALSE_POSITIVE": "warning",
}


def alert_to_response(alert: Alert) -> AlertResponse:
    """
    Transform SQLAlchemy Alert model to Pydantic AlertResponse.
    Supplies all frontend camelCase fields along with snake_case schema fields.
    """
    sev_str = alert.severity.upper() if isinstance(alert.severity, str) else alert.severity.value
    triage_str = alert.triage_status.upper() if isinstance(alert.triage_status, str) else alert.triage_status.value
    status_str = alert.status if isinstance(alert.status, str) else alert.status.value

    # Confidence calculation (0.0 to 1.0 mapped to pct)
    conf_float = float(alert.confidence)
    conf_pct = round(conf_float * 100.0, 1) if conf_float <= 1.0 else round(conf_float, 1)
    conf_formatted = f"{conf_pct:.1f}%"

    # Time string formatting
    if alert.timestamp:
        time_str = alert.timestamp.strftime("%H:%M:%S")
    else:
        time_str = datetime.now(timezone.utc).strftime("%H:%M:%S")

    # Metadata extraction
    meta = alert.metadata_json or {}
    date_label = meta.get("dateLabel", "Today")
    accent_color = meta.get("accentColor", SEVERITY_COLORS.get(sev_str, "#ef4444"))
    waveform_bars = meta.get("waveform_bars")
    raw_packet_snippet = meta.get("raw_packet_snippet")
    throughput_peak = meta.get("throughput_peak")

    return AlertResponse(
        id=alert.alert_id,
        alert_id=alert.alert_id,
        timestamp=alert.timestamp,
        time=time_str,
        dateLabel=date_label,
        severity=AlertSeverity(sev_str),
        classification=alert.attack_classification,
        attack_classification=alert.attack_classification,
        threat_class=alert.threat_class,
        srcIp=alert.source_ip,
        destIp=alert.destination_ip,
        source_ip=alert.source_ip,
        destination_ip=alert.destination_ip,
        source_port=alert.source_port,
        destination_port=alert.destination_port,
        protocol=alert.transport_protocol,
        confidence=conf_float if conf_float <= 1.0 else conf_float / 100.0,
        confidence_pct=conf_pct,
        confidenceFormatted=conf_formatted,
        triage=triage_str,
        triage_status=TriageStatus(triage_str),
        triageType=TRIAGE_TYPE_MAP.get(triage_str, "info"),
        status=AlertStatus(status_str) if status_str in AlertStatus._value2member_map_ else AlertStatus.MITIGATED,
        accentColor=accent_color,
        whyFlagged=alert.reason,
        reason=alert.reason,
        detectorModel=alert.detector_model,
        detector_model=alert.detector_model,
        mitre=alert.mitre_technique or "",
        mitre_technique=alert.mitre_technique,
        triggerFeatures=alert.trigger_features or {},
        trigger_features=alert.trigger_features or {},
        evidence=alert.evidence,
        metadata=meta,
        waveform_bars=waveform_bars,
        raw_packet_snippet=raw_packet_snippet,
        throughput_peak=throughput_peak,
    )


class AlertService:
    """
    Service layer executing database queries, filters, aggregations,
    and mutations for Security Alerts.
    """

    @staticmethod
    def create_alert(session: Session, alert_in: Union[AlertCreate, Dict[str, Any]]) -> Alert:
        """
        Validate and insert a new security alert record into the database.
        """
        if isinstance(alert_in, dict):
            validated_data = AlertCreate(**alert_in)
        else:
            validated_data = alert_in

        # Prepare evidence and metadata payloads
        evidence_dict = None
        if validated_data.evidence:
            if isinstance(validated_data.evidence, AlertEvidence):
                evidence_dict = validated_data.evidence.model_dump()
            else:
                evidence_dict = dict(validated_data.evidence)

        # Map enum values to strings for DB persistence
        alert_obj = Alert(
            alert_id=validated_data.alert_id,
            timestamp=validated_data.timestamp,
            threat_class=validated_data.threat_class.value if isinstance(validated_data.threat_class, Enum) else str(validated_data.threat_class),
            attack_classification=validated_data.attack_classification,
            severity=validated_data.severity.value if isinstance(validated_data.severity, Enum) else str(validated_data.severity),
            confidence=validated_data.confidence,
            source_ip=str(validated_data.source_ip),
            destination_ip=str(validated_data.destination_ip),
            source_port=validated_data.source_port,
            destination_port=validated_data.destination_port,
            transport_protocol=validated_data.transport_protocol,
            status=validated_data.status.value if isinstance(validated_data.status, Enum) else str(validated_data.status),
            triage_status=validated_data.triage_status.value if isinstance(validated_data.triage_status, Enum) else str(validated_data.triage_status),
            model_version=validated_data.model_version,
            detector_model=validated_data.detector_model,
            mitre_technique=validated_data.mitre_technique,
            reason=validated_data.reason,
            evidence=evidence_dict,
            trigger_features=validated_data.trigger_features or {},
            metadata_json=validated_data.metadata or {},
        )

        session.add(alert_obj)
        session.commit()
        session.refresh(alert_obj)
        return alert_obj

    @staticmethod
    def get_alert(session: Session, alert_id: str) -> Optional[Alert]:
        """
        Retrieve a single alert by its primary alert_id identifier.
        """
        stmt = select(Alert).where(Alert.alert_id == alert_id)
        return session.scalar(stmt)

    @staticmethod
    def get_alerts(
        session: Session,
        severity: Optional[Union[str, AlertSeverity]] = None,
        threat_class: Optional[Union[str, ThreatClass]] = None,
        status: Optional[Union[str, AlertStatus]] = None,
        triage_status: Optional[Union[str, TriageStatus]] = None,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        search: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
        sort_by: str = "timestamp",
        sort_asc: bool = False,
    ) -> Tuple[List[Alert], int]:
        """
        Filter, search, paginate, and sort security alerts.
        Returns a tuple of (items, total_matching_count).
        """
        query = select(Alert)

        # Filter by Severity (supports 'ALL' as no-op)
        if severity and str(severity).upper() != "ALL":
            sev_val = severity.value if isinstance(severity, Enum) else str(severity).upper()
            query = query.where(Alert.severity == sev_val)

        # Filter by Threat Class
        if threat_class and str(threat_class).upper() != "ALL":
            raw_tc = (threat_class.value if isinstance(threat_class, Enum) else str(threat_class)).strip()
            tc_upper = raw_tc.upper()
            if tc_upper == "DGA":
                query = query.where(Alert.threat_class.in_(["DGA"]))
            elif tc_upper in ("DNS", "DNS_TUNNEL", "DNS-TUNNEL"):
                query = query.where(Alert.threat_class.in_(["DNS_TUNNEL", "DNS", "DNS-Tunnel"]))
            elif tc_upper == "DDOS":
                query = query.where(Alert.threat_class.in_(["DDOS", "DDoS"]))
            elif tc_upper in ("C2", "C2_BEACONING"):
                query = query.where(Alert.threat_class.in_(["C2_BEACONING", "C2"]))
            else:
                query = query.where(Alert.threat_class == raw_tc)

        # Filter by Action Status
        if status and str(status).upper() != "ALL":
            st_val = status.value if isinstance(status, Enum) else str(status)
            query = query.where(Alert.status == st_val)

        # Filter by Triage Status
        if triage_status and str(triage_status).upper() != "ALL":
            tr_val = triage_status.value if isinstance(triage_status, Enum) else str(triage_status).upper()
            query = query.where(Alert.triage_status == tr_val)

        # Filter by Source / Destination IP
        if source_ip:
            query = query.where(Alert.source_ip == source_ip.strip())
        if destination_ip:
            query = query.where(Alert.destination_ip == destination_ip.strip())

        # Date Range Filtering
        if start_time:
            query = query.where(Alert.timestamp >= start_time)
        if end_time:
            query = query.where(Alert.timestamp <= end_time)

        # Universal Search across IP, Attack Classification, Threat Class, ID, and Reason
        if search and search.strip():
            term = f"%{search.strip()}%"
            query = query.where(
                or_(
                    Alert.alert_id.ilike(term),
                    Alert.source_ip.ilike(term),
                    Alert.destination_ip.ilike(term),
                    Alert.attack_classification.ilike(term),
                    Alert.threat_class.ilike(term),
                    Alert.reason.ilike(term),
                )
            )

        # Total matching count query before pagination
        count_stmt = select(func.count()).select_from(query.subquery())
        total_count = session.scalar(count_stmt) or 0

        # Whitelist allowed sorting columns for SQL safety
        allowed_sort_columns = {
            "timestamp": Alert.timestamp,
            "confidence": Alert.confidence,
            "severity": Alert.severity,
            "threat_class": Alert.threat_class,
            "alert_id": Alert.alert_id,
            "source_ip": Alert.source_ip,
            "destination_ip": Alert.destination_ip,
            "status": Alert.status,
            "triage_status": Alert.triage_status,
        }
        sort_column = allowed_sort_columns.get(sort_by, Alert.timestamp)
        if sort_asc:
            query = query.order_by(sort_column.asc())
        else:
            query = query.order_by(sort_column.desc())

        # Pagination
        query = query.limit(limit).offset(offset)
        items = list(session.scalars(query).all())

        return items, total_count

    @staticmethod
    def get_recent_alerts(session: Session, limit: int = 5) -> List[Alert]:
        """
        Retrieve the latest alerts strictly ordered by timestamp descending.
        """
        stmt = select(Alert).order_by(Alert.timestamp.desc()).limit(limit)
        return list(session.scalars(stmt).all())

    @staticmethod
    def get_alert_counts(
        session: Session,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> Dict[str, int]:
        """
        Dynamically calculate alert counts by severity and triage state from SQLite.
        Zero hardcoded counts.
        """
        base_filter = []
        if start_time:
            base_filter.append(Alert.timestamp >= start_time)
        if end_time:
            base_filter.append(Alert.timestamp <= end_time)

        # 1. Total Alert Count
        total_stmt = select(func.count(Alert.alert_id))
        if base_filter:
            total_stmt = total_stmt.where(*base_filter)
        total_count = session.scalar(total_stmt) or 0

        # 2. Counts Grouped by Severity
        sev_stmt = select(Alert.severity, func.count(Alert.alert_id))
        if base_filter:
            sev_stmt = sev_stmt.where(*base_filter)
        sev_stmt = sev_stmt.group_by(Alert.severity)
        sev_rows = session.execute(sev_stmt).all()
        sev_counts = {row[0].upper(): row[1] for row in sev_rows}

        # 3. Counts Grouped by Triage Status
        triage_stmt = select(Alert.triage_status, func.count(Alert.alert_id))
        if base_filter:
            triage_stmt = triage_stmt.where(*base_filter)
        triage_stmt = triage_stmt.group_by(Alert.triage_status)
        triage_rows = session.execute(triage_stmt).all()
        triage_counts = {row[0].upper(): row[1] for row in triage_rows}

        return {
            "all": total_count,
            "critical": sev_counts.get("CRITICAL", 0),
            "high": sev_counts.get("HIGH", 0),
            "medium": sev_counts.get("MEDIUM", 0),
            "low": sev_counts.get("LOW", 0),
            # Triage breakdown
            "new": triage_counts.get("NEW", 0),
            "investigating": triage_counts.get("INVESTIGATING", 0),
            "escalated": triage_counts.get("ESCALATED", 0),
            "resolved": triage_counts.get("RESOLVED", 0),
            "false_positive": triage_counts.get("FALSE_POSITIVE", 0),
        }

    @staticmethod
    def get_threat_distribution(
        session: Session,
        filter_mode: str = "Observed (Inbound)",
    ) -> ThreatDistribution:
        """
        Dynamically calculate threat classification distribution directly from SQLite.
        Computes counts, percentages, and color styling for the donut visualization.
        Zero hardcoded numbers.
        """
        # Group by threat_class in SQLite
        stmt = (
            select(Alert.threat_class, func.count(Alert.alert_id))
            .group_by(Alert.threat_class)
            .order_by(func.count(Alert.alert_id).desc())
        )
        rows = session.execute(stmt).all()

        total_threats = sum(r[1] for r in rows)

        categories: List[ThreatCategoryItem] = []
        for threat_cls, count in rows:
            pct = round((count / total_threats * 100.0), 1) if total_threats > 0 else 0.0
            color = THREAT_CLASS_COLORS.get(threat_cls, "#38bdf8")

            # Human-readable display label
            label = threat_cls.replace("_", " ").title()
            if threat_cls == "DDOS":
                label = "DDoS"
            elif threat_cls == "C2_BEACONING":
                label = "C2"
            elif threat_cls == "DGA":
                label = "DGA"
            elif threat_cls in ("DNS_TUNNEL", "DNS", "DNS-Tunnel"):
                label = "DNS Tunnel"
            elif threat_cls == "DGA_DNS_TUNNEL":
                label = "DGA"

            categories.append(
                ThreatCategoryItem(
                    label=label,
                    pct=pct,
                    pct_formatted=f"{round(pct)}%",
                    count=count,
                    color=color,
                )
            )

        return ThreatDistribution(
            filter_mode=filter_mode,
            total_threats=total_threats,
            categories=categories,
        )

    @staticmethod
    def get_timeline(
        session: Session,
        limit: int = 20,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[TimelinePoint]:
        """
        Generate chronological timeline audit points from alert records.
        """
        query = select(Alert)
        if start_time:
            query = query.where(Alert.timestamp >= start_time)
        if end_time:
            query = query.where(Alert.timestamp <= end_time)

        query = query.order_by(Alert.timestamp.desc()).limit(limit)
        alerts = session.scalars(query).all()

        timeline_points = []
        for a in alerts:
            sev_val = a.severity.upper() if isinstance(a.severity, str) else a.severity.value
            time_label = a.timestamp.strftime("%H:%M:%S") if a.timestamp else "N/A"
            timeline_points.append(
                TimelinePoint(
                    timestamp=a.timestamp,
                    time_label=time_label,
                    event_type=f"{a.threat_class} Detection",
                    severity=AlertSeverity(sev_val),
                    description=a.reason,
                    source_ip=a.source_ip,
                )
            )
        return timeline_points

    @staticmethod
    def update_triage(
        session: Session,
        alert_id: str,
        triage_status: Optional[Union[str, TriageStatus]] = None,
        action_status: Optional[Union[str, AlertStatus]] = None,
    ) -> Optional[Alert]:
        """
        Mutate the operator triage state or mitigation action state of an alert.
        """
        alert = session.get(Alert, alert_id)
        if not alert:
            return None

        if triage_status:
            alert.triage_status = triage_status.value if isinstance(triage_status, Enum) else str(triage_status).upper()
        if action_status:
            alert.status = action_status.value if isinstance(action_status, Enum) else str(action_status)

        session.commit()
        session.refresh(alert)
        return alert
