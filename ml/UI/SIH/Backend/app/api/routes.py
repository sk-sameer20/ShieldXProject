"""
FastAPI REST API Routes for ShieldX SOC
Strictly delegates all database queries to the service layer.
"""
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.models.schemas import (
    AlertCreate,
    AlertListResponse,
    AlertResponse,
    AlertSeverity,
    AlertStatus,
    DetectorStatus,
    HealthResponse,
    Statistics,
    ThreatClass,
    ThreatDistribution,
    TimelinePoint,
    TrafficPoint,
    TriageStatus,
)
from app.services.alert_service import AlertService, alert_to_response
from app.services.system_service import SystemService
from app.websocket.manager import ws_manager

api_router = APIRouter(prefix="/api", tags=["ShieldX SOC Telemetry & Defense"])



# ═══════════════════════════════════════════════════════════════
# 1. SYSTEM HEALTH
# ═══════════════════════════════════════════════════════════════

@api_router.get(
    "/health",
    response_model=HealthResponse,
    summary="Get System & Enclave Health",
    description="Returns real-time status of the hardware diode, 4 HUD resource gauges, and data collector latencies.",
)
def get_system_health(db: Session = Depends(get_db)) -> HealthResponse:
    """Retrieve system health and hardware diode verification status."""
    return SystemService.get_health(db)


# ═══════════════════════════════════════════════════════════════
# 2. ALERTS QUEUE & DETAIL
# ═══════════════════════════════════════════════════════════════

@api_router.get(
    "/alerts",
    response_model=AlertListResponse,
    summary="List & Filter Security Alerts",
    description="Paginated alert queue supporting filters for severity, threat taxonomy, triage status, IPs, date ranges, and search.",
)
def get_alerts(
    severity: Optional[str] = Query(None, description="Severity filter: CRITICAL, HIGH, MEDIUM, LOW, or ALL"),
    threat_class: Optional[str] = Query(None, description="Taxonomy filter: DDOS, C2_BEACONING, DGA_DNS_TUNNEL, ANOMALY, etc."),
    status: Optional[str] = Query(None, description="Action status filter: Mitigated, Blocked, Alerted, Monitored"),
    triage_status: Optional[str] = Query(None, description="Triage lifecycle state: NEW, INVESTIGATING, ESCALATED, RESOLVED"),
    source_ip: Optional[str] = Query(None, description="Filter by ingress source IP"),
    destination_ip: Optional[str] = Query(None, description="Filter by destination target IP"),
    search: Optional[str] = Query(None, description="Search term matching IP, alert ID, attack type, or explainability statement"),
    start_time: Optional[datetime] = Query(None, description="ISO8601 start timestamp bound"),
    end_time: Optional[datetime] = Query(None, description="ISO8601 end timestamp bound"),
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(10, ge=1, le=100, description="Items per page"),
    sort_by: str = Query("timestamp", description="Column to sort by (e.g. timestamp, confidence, severity)"),
    sort_asc: bool = Query(False, description="Ascending sort flag"),
    db: Session = Depends(get_db),
) -> AlertListResponse:
    """Query and filter security alerts with dynamic counts."""
    offset = (page - 1) * page_size
    items, total_count = AlertService.get_alerts(
        session=db,
        severity=severity,
        threat_class=threat_class,
        status=status,
        triage_status=triage_status,
        source_ip=source_ip,
        destination_ip=destination_ip,
        search=search,
        start_time=start_time,
        end_time=end_time,
        limit=page_size,
        offset=offset,
        sort_by=sort_by,
        sort_asc=sort_asc,
    )

    # Dynamic counts from database
    counts = AlertService.get_alert_counts(db)
    total_pages = max(1, (total_count + page_size - 1) // page_size)

    return AlertListResponse(
        total=total_count,
        counts=counts,
        items=[alert_to_response(a) for a in items],
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@api_router.get(
    "/alerts/{alert_id}",
    response_model=AlertResponse,
    summary="Get Alert Detail & Evidence Inspector",
    description="Retrieve full packet evidence, explainability reasoning, and trigger features for an alert.",
)
def get_alert_by_id(
    alert_id: str,
    db: Session = Depends(get_db),
) -> AlertResponse:
    """Retrieve a single security alert by its unique alert_id."""
    alert = AlertService.get_alert(db, alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert with ID '{alert_id}' was not found in the enclave store.",
        )
    return alert_to_response(alert)


# ═══════════════════════════════════════════════════════════════
# 3. STATISTICS & AGGREGATIONS
# ═══════════════════════════════════════════════════════════════

@api_router.get(
    "/stats",
    response_model=Statistics,
    summary="Get Operational Statistics",
    description="Aggregated throughput metrics, active flows, latency, and alert totals calculated directly from SQLite.",
)
def get_statistics(db: Session = Depends(get_db)) -> Statistics:
    """Calculate and return operational statistics from database records."""
    return SystemService.get_statistics(db)


@api_router.get(
    "/stats/threat-distribution",
    response_model=ThreatDistribution,
    summary="Get Threat Taxonomy Distribution",
    description="Aggregated threat class counts and percentage shares for the donut visualization.",
)
def get_threat_distribution(
    filter_mode: str = Query("Observed (Inbound)", description="Filter mode label"),
    db: Session = Depends(get_db),
) -> ThreatDistribution:
    """Calculate threat classification distribution directly from SQLite."""
    return AlertService.get_threat_distribution(db, filter_mode=filter_mode)


@api_router.get(
    "/stats/timeline",
    response_model=List[TimelinePoint],
    summary="Get Incident Audit Timeline",
    description="Chronological security events and detections for timeline visualizer.",
)
def get_timeline(
    limit: int = Query(20, ge=1, le=100, description="Max timeline points to return"),
    start_time: Optional[datetime] = Query(None, description="Start timestamp bound"),
    end_time: Optional[datetime] = Query(None, description="End timestamp bound"),
    db: Session = Depends(get_db),
) -> List[TimelinePoint]:
    """Retrieve chronological event points from alert records."""
    return AlertService.get_timeline(db, limit=limit, start_time=start_time, end_time=end_time)


# ═══════════════════════════════════════════════════════════════
# 4. TELEMETRY & TRAFFIC
# ═══════════════════════════════════════════════════════════════

@api_router.get(
    "/traffic",
    response_model=List[TrafficPoint],
    summary="Get Live Traffic Rate Series",
    description="Rolling ingress telemetry (packets/sec and bytes/sec) from the Zeek passive tap.",
)
def get_traffic(
    limit: int = Query(20, ge=1, le=100, description="Number of telemetry samples to retrieve"),
    db: Session = Depends(get_db),
) -> List[TrafficPoint]:
    """Retrieve sliding window traffic telemetry samples."""
    return SystemService.get_traffic(db, limit=limit)


# ═══════════════════════════════════════════════════════════════
# 5. DETECTORS STATUS
# ═══════════════════════════════════════════════════════════════

@api_router.get(
    "/detectors/status",
    response_model=List[DetectorStatus],
    summary="Get Detection Engine Telemetry & Attribution",
    description="Operational status, cadence metrics, and playbooks for DDoS, C2 Beaconing, and DGA DNS Tunnel engines.",
)
def get_detectors_status(db: Session = Depends(get_db)) -> List[DetectorStatus]:
    """Retrieve active status and metrics for all ML detection engines."""
    return SystemService.get_detector_statuses(db)


# ═══════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════
# 6. INTERNAL INGESTION
# ═══════════════════════════════════════════════════════════════

@api_router.post(
    "/internal/alerts",
    response_model=AlertResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest Detection Alert (Internal Hook)",
    description="Endpoint for passive detector modules to ingest newly confirmed security alerts and broadcast via WebSocket.",
)
async def ingest_alert(
    alert_in: AlertCreate,
    db: Session = Depends(get_db),
) -> AlertResponse:
    """
    1. Validate alert payload via Pydantic AlertCreate
    2. Check for duplicate ID / Persist to SQLite
    3. Broadcast WebSocket event to all connected clients only after persistence succeeds
    """
    # Check if alert_id already exists to prevent duplicate key constraint failure
    existing = AlertService.get_alert(db, alert_in.alert_id)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"An alert with ID '{alert_in.alert_id}' already exists in the enclave store.",
        )

    # 1. Save alert to SQLite
    created_alert = AlertService.create_alert(db, alert_in)
    response_dto = alert_to_response(created_alert)

    # 2. Broadcast WebSocket event after database persistence succeeds
    event_payload = {
        "type": "alert",
        "data": response_dto.model_dump(mode="json"),
    }
    await ws_manager.broadcast(event_payload)

    return response_dto

