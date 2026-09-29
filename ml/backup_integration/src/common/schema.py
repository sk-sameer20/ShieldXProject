"""
src/common/alert.py — Shared Pydantic Alert schema for SIH26145 Person 3 module.

Every detector (C2, DGA, DNS_TUNNEL) returns an Alert instance.
Person 4 consumes these directly — do NOT change field names without
coordinating with the integration team.
"""

from __future__ import annotations

import uuid
import time
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


ThreatClass = Literal["C2", "DGA", "DNS_TUNNEL", "benign"]
Severity = Literal["low", "medium", "high", "critical"]


class Alert(BaseModel):
    """
    Standardized alert produced by any Person 3 detector.

    Fields
    ------
    alert_id          : Unique alert identifier (UUID4 string).
    timestamp         : Unix epoch float at time of detection.
    threat_class      : One of C2 / DGA / DNS_TUNNEL / benign.
    detected          : True if the detector classifies this as a threat.
    confidence        : Calibrated or scored probability in [0.0, 1.0].
                        NOTE: For IsolationForest this is a normalized anomaly
                        score, NOT a calibrated probability. Document accordingly.
    severity          : Derived from threat_class + confidence (not raw ML score).
    evidence          : Human-readable signal descriptions (non-empty when detected).
    technical_evidence: Raw feature key→value pairs for downstream logging/display.
    model_version     : Version string of the model/heuristic that produced this.
    src_ip            : Source IP (optional — not always available in DNS windows).
    dst_ip            : Destination IP (optional).
    window_start      : Unix epoch float for window start.
    window_end        : Unix epoch float for window end.
    """

    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = Field(default_factory=time.time)
    threat_class: ThreatClass
    detected: bool
    confidence: float = Field(ge=0.0, le=1.0)
    severity: Severity
    evidence: List[str] = Field(default_factory=list)
    technical_evidence: Dict[str, Any] = Field(default_factory=dict)
    model_version: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    window_start: Optional[float] = None
    window_end: Optional[float] = None

    @field_validator("evidence")
    @classmethod
    def evidence_not_empty_when_detected(cls, v: List[str], info: Any) -> List[str]:
        """Warn if a detection fires but no evidence strings were provided."""
        # We can't access other fields cleanly in field_validator on Pydantic v2,
        # so this is enforced in model_validator below.
        return v

    @model_validator(mode="after")
    def check_evidence_when_detected(self) -> "Alert":
        if self.detected and not self.evidence:
            raise ValueError(
                "An Alert with detected=True must include at least one evidence string."
            )
        return self

    def to_dict(self) -> Dict[str, Any]:
        """Return a plain dict (for JSON serialization or SQLite storage)."""
        return self.model_dump()


def make_benign_alert(
    *,
    model_version: str,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    window_start: Optional[float] = None,
    window_end: Optional[float] = None,
    technical_evidence: Optional[Dict[str, Any]] = None,
) -> Alert:
    """
    Convenience constructor for a benign (non-detected) alert.
    Detectors should call this when confidence is below their threshold.
    """
    return Alert(
        threat_class="benign",
        detected=False,
        confidence=0.0,
        severity="low",
        evidence=[],
        technical_evidence=technical_evidence or {},
        model_version=model_version,
        src_ip=src_ip,
        dst_ip=dst_ip,
        window_start=window_start,
        window_end=window_end,
    )
