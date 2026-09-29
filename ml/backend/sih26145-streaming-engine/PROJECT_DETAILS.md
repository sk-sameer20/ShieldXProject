# SIH26145 Streaming Engine - Comprehensive System Architecture & AI Specification

## Executive Summary
`sih26145-streaming-engine` is the real-time orchestration engine for the SIH26145 Threat Detection Pipeline. It ingests high-volume network flow events (or Zeek records), manages stateful sliding time windows, extracts feature vectors, feeds features into threat-specific model adapters (DDoS, C2, DNS/DGA), aggregates evidence via a multi-signal confidence engine, maps confidence to severity levels, deduplicates alert floods, and persists standardized alerts into SQLite for downstream consumption (e.g., Person 5's FastAPI & Dashboard).

---

## Data Pipeline Flow

```text
Network / Zeek Log Events
          ↓
     parser.py (Zeek -> Common Event Schema)
          ↓
   event_queue.py (Bounded Async Queue with Overflow Drop Stats)
          ↓
 window_manager.py (Sliding Windows: 5s DDoS, 60s C2, 60s DNS)
          ↓
 features/ adapters (DDoS, C2, DNS Feature Adapters + Baseline Welford)
          ↓
 detectors/ adapters (Mock / Real ML Model Adapters)
          ↓
  fusion/ (Evidence Aggregation + Composite Confidence + Severity Policy)
          ↓
   alerts/ (Pydantic Alert Schema + Builder + Validator)
          ↓
 deduplication.py (Alert Grouping & Flood Suppression)
          ↓
 storage/sqlite_store.py (SQLite DB: outputs/sih26145.db)
```

---

## Module Interfaces & Integration Points

### 1. Ingestion Interface (Person 1 → Person 4)
- **File**: `src/ingestion/parser.py`
- **Contract**: Accepts raw JSON/Zeek records (`id.orig_h`, `id.resp_h`, `id.orig_p`, `id.resp_p`, `proto`, `ts`, `orig_bytes`, `resp_bytes`) and converts them into standard `NetworkEvent`:
```python
{
    "timestamp": float,
    "src_ip": str,
    "dst_ip": str,
    "src_port": int,
    "dst_port": int,
    "protocol": str,
    "orig_bytes": int,
    "resp_bytes": int,
    "orig_pkts": int,
    "resp_pkts": int,
    "query": Optional[str],
    "syn_flag": bool
}
```

### 2. DDoS Detector Adapter Interface (Person 2 → Person 4)
- **File**: `src/detectors/ddos_adapter.py`
- **Features Input**:
  - `pps`: Packets Per Second in 5s window
  - `bps`: Bits Per Second in 5s window
  - `syn_ratio`: Ratio of SYN-flagged packets
  - `unique_dst_ips`: Count of unique destination IPs targeted by source
- **Model Output Schema**:
```python
{
    "threat_class": "DDoS",
    "detected": bool,
    "score": float,       # Range 0.0 to 1.0
    "evidence": list[str], # Explanatory text strings
    "model_version": str
}
```

### 3. C2 & DNS/DGA Detector Adapter Interfaces (Person 3 → Person 4)
- **Files**: `src/detectors/c2_adapter.py`, `src/detectors/dns_adapter.py`
- **C2 Features**: `beacon_regularity_score`, `avg_payload_bytes`, `avg_interarrival_seconds`.
- **DNS Features**: `unique_domains_count`, `avg_domain_length`, `avg_shannon_entropy`, `query_rate`.
- **Model Output Schema**: Standardized detection result dictionary matching DDoS interface.

### 4. Storage & Dashboard Interface (Person 4 → Person 5)
- **File**: `src/storage/sqlite_store.py`
- **Database Path**: `outputs/sih26145.db`
- **Table**: `alerts`
- **Schema**:
```sql
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    timestamp REAL NOT NULL,
    flow_id TEXT,
    threat_class TEXT NOT NULL,
    confidence REAL NOT NULL,
    severity TEXT NOT NULL,
    evidence TEXT NOT NULL, -- JSON string
    model_version TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    destination_ip TEXT,
    window_start REAL,
    window_end REAL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## Key Technical Decisions & Edge Cases

1. **Baseline Contamination Protection (`src/features/baseline.py`)**:
   - Uses Welford's online mean/variance algorithm.
   - **Crucial Rule**: When a host generates a high-confidence alert, `freeze_host(src_ip)` is triggered to pause baseline updates, preventing attack traffic spikes from polluting the normal host baseline.

2. **Confidence vs. Severity (`src/fusion/severity.py`)**:
   - `Confidence` measures signal strength (composite score of model score, anomaly score, and baseline deviation).
   - `Severity` measures impact (`low`, `medium`, `high`, `critical`) based on threat class, traffic magnitude (PPS/BPS), confidence, and affected target scope.

3. **Sliding Window Out-of-Order Handling (`src/streaming/window_manager.py`)**:
   - Events are kept in binary/sorted position by timestamp.
   - Expired events older than `latest_timestamp - max_window_seconds` are pruned asynchronously.
