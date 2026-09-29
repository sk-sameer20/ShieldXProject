import uuid
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class AlertSchema(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float
    flow_id: Optional[str] = None
    threat_type: str
    confidence: float
    severity: str
    evidence: List[str] = Field(default_factory=list)
    model_version: str = "v1.0"
    src_ip: str
    dst_ip: Optional[str] = None
    window_start: Optional[float] = None
    window_end: Optional[float] = None
    raw_features: Dict[str, Any] = Field(default_factory=dict)
    suppressed_count: int = 0
