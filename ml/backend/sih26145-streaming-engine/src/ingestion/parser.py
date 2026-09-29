import json
import uuid
from typing import Iterator, Optional, Dict, Any
from pydantic import BaseModel, Field


class NetworkEvent(BaseModel):
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str = "tcp"
    duration: Optional[float] = None
    orig_bytes: int = 0
    resp_bytes: int = 0
    orig_pkts: int = 1
    resp_pkts: int = 0
    conn_state: Optional[str] = None
    query: Optional[str] = None
    qtype: Optional[str] = None
    rcode: Optional[str] = None
    flow_id: Optional[str] = None

    def model_post_init(self, __context: Any) -> None:
        if not self.flow_id:
            self.flow_id = f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}"


def parse_event(record: Dict[str, Any]) -> NetworkEvent:
    """
    Parses raw dictionary record into NetworkEvent.
    Supports both direct common format and Zeek format mapping.
    """
    # Check for Zeek field format (e.g., id.orig_h, id.resp_h, ts, proto)
    if "id.orig_h" in record:
        mapped = {
            "timestamp": float(record.get("ts", record.get("timestamp", 0.0))),
            "src_ip": str(record.get("id.orig_h", "")),
            "dst_ip": str(record.get("id.resp_h", "")),
            "src_port": int(record.get("id.orig_p", 0)),
            "dst_port": int(record.get("id.resp_p", 0)),
            "protocol": str(record.get("proto", record.get("protocol", "tcp"))).lower(),
            "duration": float(record.get("duration")) if record.get("duration") is not None else None,
            "orig_bytes": int(record.get("orig_bytes", record.get("orig_ip_bytes", 0)) or 0),
            "resp_bytes": int(record.get("resp_bytes", record.get("resp_ip_bytes", 0)) or 0),
            "orig_pkts": int(record.get("orig_pkts", 1) or 1),
            "resp_pkts": int(record.get("resp_pkts", 0) or 0),
            "conn_state": record.get("conn_state"),
            "query": record.get("query"),
            "qtype": record.get("qtype_name") or record.get("qtype"),
            "rcode": record.get("rcode_name") or record.get("rcode"),
        }
        return NetworkEvent.model_validate(mapped)

    # Standard Common Event format
    return NetworkEvent.model_validate(record)


def parse_jsonl(path: str) -> Iterator[NetworkEvent]:
    """
    Reads a jsonl file and yields validated NetworkEvent instances.
    """
    with open(path, "r", encoding="utf-8") as file:
        for line_num, line in enumerate(file, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                record = json.loads(line)
                yield parse_event(record)
            except Exception as exc:
                # Log or skip malformed lines gracefully
                continue