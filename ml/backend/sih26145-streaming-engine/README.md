# SIH26145 Streaming Engine - Complete Integration & Technical Documentation

> **Real-Time Threat Detection Streaming & Orchestration Layer (Person 4)**

`sih26145-streaming-engine` is an independent, real-time streaming orchestration framework designed for Security Information and Event Management (SIEM) and Network Intrusion Detection System (NIDS) pipelines. It serves as the central orchestration engine connecting network ingestion, sliding time windows, feature extraction, threat model adapters (DDoS, C2, DNS/DGA), multi-signal evidence fusion, alert deduplication, and SQLite persistence.

---

## 🏛 Architecture & Data Flow Pipeline

```text
                                Network / Zeek Events
                                          ↓
                                      Parser
                           (src/ingestion/parser.py)
                                          ↓
                                     Event Queue
                        (src/streaming/event_queue.py)
                                          ↓
                                   Time Windows
                       (src/streaming/window_manager.py)
                                          ↓
                                Feature Extraction
                        (src/features/*_adapter.py)
                                          ↓
            ┌─────────────────────────────┼─────────────────────────────┐
            ↓                             ↓                             ↓
     DDoS Detector                  C2 Detector                   DGA/DNS Detector
(src/detectors/ddos_adapter.py) (src/detectors/c2_adapter.py) (src/detectors/dns_adapter.py)
            ↓                             ↓                             ↓
            └─────────────────────────────┼─────────────────────────────┘
                                          ↓
                                   Evidence Fusion
              (src/fusion/evidence.py, confidence.py, severity.py)
                                          ↓
                                   Standard Alert
                (src/alerts/schema.py, builder.py, validator.py)
                                          ↓
                                   Deduplication
                         (src/alerts/deduplication.py)
                                          ↓
                                   SQLite Storage
                          (src/storage/sqlite_store.py)
                                          ↓
                             Dashboard / FastAPI Server
                                    (Person 5)
```

---

## 🔌 Comprehensive Integration Guide for Team Members

This streaming engine is designed to be completely independent while providing seamless plug-and-play interfaces for the entire team.

### 1. Person 1 (Zeek & Network Ingestion) → Person 4 Engine

Person 1 provides raw Zeek records or network packet captures. The parser (`src/ingestion/parser.py`) maps Zeek field names to the standardized `NetworkEvent` Pydantic model.

#### Field Mapping Table:
| Zeek Record Field | Common `NetworkEvent` Field | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `ts` / `timestamp` | `timestamp` | `float` | Required | Unix epoch timestamp in seconds |
| `id.orig_h` / `src_ip` | `src_ip` | `str` | Required | Source IP address |
| `id.resp_h` / `dst_ip` | `dst_ip` | `str` | Required | Destination IP address |
| `id.orig_p` / `src_port` | `src_port` | `int` | Required | Source port number |
| `id.resp_p` / `dst_port` | `dst_port` | `int` | Required | Destination port number |
| `proto` / `protocol` | `protocol` | `str` | `"tcp"` | Protocol (`"tcp"`, `"udp"`, `"icmp"`) |
| `orig_ip_bytes` / `orig_bytes` | `orig_bytes` | `int` | `0` | Bytes sent by originator |
| `resp_ip_bytes` / `resp_bytes` | `resp_bytes` | `int` | `0` | Bytes sent by responder |
| `orig_pkts` | `orig_pkts` | `int` | `1` | Packets sent by originator |
| `resp_pkts` | `resp_pkts` | `int` | `0` | Packets sent by responder |
| `query` | `query` | `str` | `None` | DNS query string (if applicable) |
| `conn_state` / `syn_flag` | `syn_flag` | `bool` | `False` | True if TCP SYN flag set |

#### Integration Code Example (Python):
```python
from src.ingestion.parser import parse_event, NetworkEvent
from src.streaming.scheduler import StreamingScheduler

# 1. Parse raw Zeek record
zeek_log_line = {
    "ts": 1727000000.1,
    "id.orig_h": "10.0.0.50",
    "id.resp_h": "192.168.1.100",
    "id.orig_p": 45120,
    "id.resp_p": 80,
    "proto": "tcp",
    "orig_ip_bytes": 64,
    "resp_ip_bytes": 0,
    "conn_state": "S0" # SYN sent without ACK
}

event: NetworkEvent = parse_event(zeek_log_line)

# 2. Push event to streaming scheduler
async def ingest_event(scheduler: StreamingScheduler, event: NetworkEvent):
    await scheduler.push_event(event)
```

---

### 2. Person 2 (DDoS Model Engineer) → Person 4 Engine

Person 2 develops the DDoS ML model (e.g. Random Forest, XGBoost, or Neural Network). Person 4 provides `src/features/ddos_adapter.py` to aggregate features from the 5-second sliding window, and `src/detectors/ddos_adapter.py` to invoke Person 2's model.

#### Features Provided by 5s Window Adapter (`DDoSFeatureAdapter`):
```python
{
    "pps": float,             # Packets Per Second in 5s window
    "bps": float,             # Bits Per Second in 5s window
    "syn_ratio": float,       # Ratio of SYN packets (0.0 to 1.0)
    "unique_dst_ips": int,    # Count of unique target IPs
    "avg_pkt_size": float,    # Average packet size in bytes
    "flow_count": int,        # Total flows in 5s window
    "total_pkts": int,        # Total packet count
    "total_bytes": int        # Total byte count
}
```

#### Detector Interface Contract:
Your model class must implement a `.predict(features: dict) -> dict` method returning:
```python
{
    "threat_class": "DDoS",
    "detected": bool,          # True if threat detected, False otherwise
    "score": float,            # Raw model score [0.0, 1.0]
    "evidence": list[str],     # List of human-readable evidence strings
    "model_version": str,      # Model identifier (e.g. "ddos-rf-v2.1")
    "metadata": dict           # Optional metadata
}
```

#### How Person 2 Plugs Model into `src/detectors/ddos_adapter.py`:
```python
# In src/detectors/ddos_adapter.py
import joblib

class RealDDoSDetector:
    def __init__(self, model_path="models/ddos_rf.joblib"):
        self.model = joblib.load(model_path)
        self.model_version = "ddos-rf-v2.1"

    def predict(self, features: dict) -> dict:
        # 1. Format feature vector for model
        X = [[features["pps"], features["bps"], features["syn_ratio"], features["unique_dst_ips"]]]
        prob = float(self.model.predict_proba(X)[0][1])
        detected = prob >= 0.70
        
        evidence = []
        if features["pps"] > 100:
            evidence.append(f"Abnormal packet rate ({features['pps']:.1f} pps)")
        if features["syn_ratio"] > 0.6:
            evidence.append(f"High SYN flag ratio ({features['syn_ratio']*100:.1f}%)")

        return {
            "threat_class": "DDoS",
            "detected": detected,
            "score": prob,
            "evidence": evidence,
            "model_version": self.model_version
        }
```

---

### 3. Person 3 (C2 & DGA/DNS Model Engineer) → Person 4 Engine

Person 3 develops C2 beaconing and DGA/DNS tunneling models.

#### C2 Features Provided by 60s Window Adapter (`C2FeatureAdapter`):
```python
{
    "beacon_regularity_stddev": float, # Standard deviation of inter-arrival times
    "beacon_regularity_score": float,  # Regularity score [0.0=irregular, 1.0=periodic]
    "avg_payload_bytes": float,        # Average payload bytes per flow
    "payload_stddev": float,           # Payload size standard deviation
    "unique_dst_ips": int,             # Count of unique destination IPs
    "flow_count": int,                 # Connection count in 60s window
    "avg_interarrival_seconds": float  # Mean inter-arrival delay
}
```

#### DGA/DNS Features Provided by 60s Window Adapter (`DNSFeatureAdapter`):
```python
{
    "unique_domains_count": int,     # Count of unique domain names queried
    "avg_domain_length": float,      # Mean domain string character length
    "avg_shannon_entropy": float,    # Mean Shannon entropy (bits/char)
    "max_shannon_entropy": float,    # Maximum Shannon entropy in window
    "query_rate": float,             # DNS queries per second
    "total_queries": int             # Total DNS query count in window
}
```

---

### 4. Person 4 Engine → Person 5 (Dashboard & FastAPI Engineer)

Person 5 builds the frontend dashboard and API server. All alerts emitted by Person 4's engine are automatically persisted to the SQLite database at `outputs/sih26145.db` in table `alerts`.

#### Database Table Schema (`alerts`):
```sql
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,               -- UUID string
    timestamp REAL NOT NULL,           -- Unix epoch timestamp
    flow_id TEXT,                      -- e.g. "10.0.0.50:40000->192.168.1.100:80"
    threat_class TEXT NOT NULL,        -- "DDoS", "C2", or "DNS"
    confidence REAL NOT NULL,          -- Composite confidence score [0.0, 1.0]
    severity TEXT NOT NULL,            -- "low", "medium", "high", "critical"
    evidence TEXT NOT NULL,            -- JSON array string of evidence strings
    model_version TEXT NOT NULL,       -- Model identifier version
    source_ip TEXT NOT NULL,           -- Source IP address
    destination_ip TEXT,               -- Destination IP address
    window_start REAL,                 -- Sliding window start epoch
    window_end REAL,                   -- Sliding window end epoch
    raw_features TEXT,                 -- JSON object string of raw window features
    suppressed_count INTEGER DEFAULT 0,-- Count of repeated alerts grouped/suppressed
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### Integration Code Example for Person 5 (FastAPI / Dashboard):
```python
from src.storage.sqlite_store import SQLiteStore

db_store = SQLiteStore("outputs/sih26145.db")

# Get 50 most recent alerts
alerts = db_store.get_recent_alerts(limit=50)

# Filter by threat class
ddos_alerts = db_store.get_alerts_by_threat("DDoS", limit=20)

# Aggregate statistics for UI metrics
stats = db_store.get_stats()
# Returns:
# {
#   "total_alerts": 120,
#   "by_threat_class": {"DDoS": 80, "C2": 25, "DNS": 15},
#   "by_severity": {"critical": 10, "high": 50, "medium": 40, "low": 20}
# }
```

---

## 🧮 Mathematical & Algorithmic Foundations

### 1. Online Welford Algorithm (Baseline Calculation)
To compute online mean ($\mu$) and sample variance ($s^2$) per host without storing historical traffic arrays:

$$\bar{x}_n = \bar{x}_{n-1} + \frac{x_n - \bar{x}_{n-1}}{n}$$

$$M_{2,n} = M_{2,n-1} + (x_n - \bar{x}_{n-1})(x_n - \bar{x}_n)$$

$$s^2 = \frac{M_{2,n}}{n-1} \quad (n > 1)$$

The Z-score deviation of current window value $x$ is computed as:

$$Z = \frac{x - \mu}{s}$$

### 2. Shannon Entropy (DGA Domain Detection)
For domain query string $S$ of length $L$ with unique character set $C$:

$$H(S) = -\sum_{c \in C} p(c) \log_2 p(c)$$

Where $p(c)$ is the empirical frequency of character $c$ in string $S$. Higher entropy ($H(S) > 3.5$) indicates algorithmic randomness typical of Domain Generation Algorithms (DGA).

### 3. Composite Confidence Fusion
Combining model prediction score ($S_{\text{model}}$), feature anomaly score ($S_{\text{anomaly}}$), and baseline Z-score transformed via sigmoid ($S_{\text{baseline}}$):

$$S_{\text{baseline}} = \frac{1}{1 + e^{-(Z - 2.0)}}$$

$$\text{Confidence} = \frac{w_m \cdot S_{\text{model}} + w_a \cdot S_{\text{anomaly}} + w_b \cdot S_{\text{baseline}}}{w_m + w_a + w_b}$$

With default weights $w_m = 0.5$, $w_a = 0.3$, $w_b = 0.2$.

### 4. Baseline Contamination Prevention
When a high-confidence alert ($\text{Confidence} \ge 0.70$) is detected for host $H$, `baseline.freeze_host(H)` is automatically invoked. This freezes $M_{2}$ and $\mu$ updates for host $H$, preventing attack volume spikes (e.g. 2500 PPS) from being learned into normal baseline statistics.

---

## 📁 Complete Repository Structure

```text
sih26145-streaming-engine/
│
├── .agents/
│   └── AGENTS.md              # AI agent guidelines & coding instructions
│
├── src/
│   ├── __init__.py
│   ├── ingestion/
│   │   ├── __init__.py
│   │   ├── parser.py          # Common Event schema & Zeek record mapper
│   │   └── replay.py          # Async stream replayer with speed multiplier
│   │
│   ├── streaming/
│   │   ├── __init__.py
│   │   ├── event_queue.py     # Bounded queue with drop tracking & stats
│   │   ├── window_manager.py    # Sliding time windows & host state tracking
│   │   └── scheduler.py       # Real-time orchestration loop
│   │
│   ├── features/
│   │   ├── __init__.py
│   │   ├── ddos_adapter.py    # PPS, BPS, SYN ratio, destination counts
│   │   ├── c2_adapter.py      # Beaconing regularity stddev & payload size
│   │   ├── dns_adapter.py     # Domain Shannon entropy & query rates
│   │   └── baseline.py        # Online Welford algorithm & contamination freeze
│   │
│   ├── detectors/
│   │   ├── __init__.py
│   │   ├── ddos_adapter.py    # DDoS detector adapter & mock heuristics
│   │   ├── c2_adapter.py      # C2 detector adapter & mock heuristics
│   │   └── dns_adapter.py     # DGA/DNS detector adapter & mock heuristics
│   │
│   ├── fusion/
│   │   ├── __init__.py
│   │   ├── evidence.py        # Evidence aggregation & deduplication
│   │   ├── confidence.py      # Multi-signal confidence calculation
│   │   └── severity.py        # Confidence vs. Severity policy engine
│   │
│   ├── alerts/
│   │   ├── __init__.py
│   │   ├── schema.py          # Pydantic AlertSchema definition
│   │   ├── builder.py         # Standardized alert builder
│   │   ├── validator.py       # Alert bounds & parameter validator
│   │   └── deduplication.py   # Grouping continuous alert floods
│   │
│   └── storage/
│       ├── __init__.py
│       └── sqlite_store.py    # SQLite database persistence & queries
│
├── data/
│   └── sample/
│       ├── sample_events.jsonl# Mixed traffic sample
│       ├── benign.jsonl       # Normal web/DNS traffic
│       ├── ddos.jsonl         # Volumetric SYN flood burst
│       ├── c2.jsonl           # Regular interval beaconing
│       └── dga.jsonl          # High entropy DGA domain queries
│
├── tests/                    # Pytest suite (17/17 tests passing)
│   ├── test_alerts.py
│   ├── test_baseline.py
│   ├── test_features.py
│   ├── test_fusion.py
│   ├── test_parser.py
│   ├── test_queue.py
│   ├── test_storage.py
│   └── test_windows.py
│
├── scripts/
│   └── benchmark.py          # Throughput, latency p50/p95, CPU/RAM benchmark
│
├── outputs/
│   ├── sih26145.db           # SQLite database
│   └── benchmark_results.json# Performance benchmark report
│
├── config.yaml               # Window, queue, fusion, storage configuration
├── run_demo.py               # CLI demo runner with scenario selection
├── IMPLEMENTATION_PROGRESS.md# Progress checklist
├── PROJECT_DETAILS.md        # AI architecture & integration spec
├── requirements.txt          # Python dependencies
└── README.md                 # Master technical documentation
```

---

## ⚙️ Configuration Reference (`config.yaml`)

```yaml
# Windows duration in seconds
windows:
  ddos_seconds: 5.0
  c2_seconds: 60.0
  dns_seconds: 60.0
  cleanup_ttl_seconds: 300.0

# Queue settings
queue:
  max_size: 10000
  overflow_strategy: "drop"

# Multi-signal fusion weights
fusion:
  model_weight: 0.5
  anomaly_weight: 0.3
  baseline_weight: 0.2

# Alert deduplication settings
deduplication:
  suppression_window_seconds: 30.0

# Database storage path
storage:
  db_path: "outputs/sih26145.db"
```

---

## ⚡ Execution Commands & Demos

### 1. Run Scenario Demos
```bash
# DDoS Volumetric Attack Scenario
python run_demo.py --scenario ddos --speed 0

# C2 Beaconing Attack Scenario
python run_demo.py --scenario c2 --speed 10

# DGA / DNS Tunneling Attack Scenario
python run_demo.py --scenario dga --speed 0

# Normal Benign Traffic Scenario
python run_demo.py --scenario benign --speed 0
```

### 2. Run Test Suite
```bash
python -m pytest
```

### 3. Run Benchmark Suite
```bash
python scripts/benchmark.py --count 5000
```

---

## 📊 Benchmark Metrics Summary

| Metric | Result | Target Constraint |
| :--- | :---: | :---: |
| **Events Processed** | 5,000 | 5,000 |
| **Throughput** | **392.1 events/sec** | > 100 events/sec |
| **Feature Extraction Latency (p50)** | **0.213 ms** | < 5.0 ms |
| **Feature Extraction Latency (p95)** | **0.804 ms** | < 10.0 ms |
| **Detector Evaluation Latency (p50)** | **0.007 ms** | < 1.0 ms |
| **End-to-End Pipeline Latency (p50)** | **2.451 ms** | < 10.0 ms |
| **End-to-End Pipeline Latency (p95)** | **6.565 ms** | < 20.0 ms |
| **Memory Footprint** | **58.19 MB** | < 500 MB |
| **Unit Test Pass Rate** | **17/17 (100%)** | 100% |
