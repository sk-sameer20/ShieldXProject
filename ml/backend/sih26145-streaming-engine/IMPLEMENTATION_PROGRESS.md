# SIH26145 Streaming Engine - Implementation Progress

## Project Overview
Real-time orchestration engine connecting ingestion, sliding-window feature extraction, online baseline calculation, mock/adapter threat detectors (DDoS, C2, DNS/DGA), evidence fusion (confidence & severity), alert deduplication, and SQLite persistence.

---

## Progress Checklist

### 1. Ingestion Engine
- [x] Common Event format (`src/ingestion/parser.py`) - NetworkEvent Pydantic model & Zeek schema mapping
- [x] Async Event Replayer (`src/ingestion/replay.py`) - Speed multiplier control (1x, 10x, 100x, instant)

### 2. Streaming Engine
- [x] Bounded Event Queue (`src/streaming/event_queue.py`) - Overflow handling, drop & throughput stats
- [x] Window Manager (`src/streaming/window_manager.py`) - Configurable sliding windows (5s DDoS, 60s C2, 60s DNS) & TTL cleanup
- [x] Streaming Scheduler (`src/streaming/scheduler.py`) - Real-time orchestration loop

### 3. Feature Adapters & Baseline
- [x] DDoS Feature Adapter (`src/features/ddos_adapter.py`) - PPS, BPS, SYN ratio, destination counts
- [x] C2 Feature Adapter (`src/features/c2_adapter.py`) - Inter-arrival regularity, payload sizes, flow stats
- [x] DNS/DGA Feature Adapter (`src/features/dns_adapter.py`) - Query frequency, domain length, Shannon entropy
- [x] Dynamic Baseline (`src/features/baseline.py`) - Welford online algorithm & baseline freeze on alert

### 4. Detector Adapters & Mocks
- [x] Standard Detector Interface (`src/detectors/`)
- [x] DDoS Detector Adapter & Mock (`src/detectors/ddos_adapter.py`)
- [x] C2 Detector Adapter & Mock (`src/detectors/c2_adapter.py`)
- [x] DNS/DGA Detector Adapter & Mock (`src/detectors/dns_adapter.py`)

### 5. Evidence Fusion & Severity
- [x] Evidence Aggregator (`src/fusion/evidence.py`)
- [x] Confidence Engine (`src/fusion/confidence.py`) - Weighted combination & normalization
- [x] Severity Engine (`src/fusion/severity.py`) - Confidence ≠ Severity policy mapping

### 6. Alert System
- [x] Standard Alert Schema (`src/alerts/schema.py`) - Pydantic model
- [x] Alert Builder (`src/alerts/builder.py`)
- [x] Alert Validator (`src/alerts/validator.py`)
- [x] Alert Deduplicator (`src/alerts/deduplication.py`) - Grouping continuous events

### 7. Storage Engine
- [x] SQLite Store (`src/storage/sqlite_store.py`) - Alert persistence & retrieval

### 8. Data Scenarios & Demo
- [x] Attack Scenarios (`data/sample/`) - sample_events, benign, ddos, c2, dga JSONL datasets
- [x] Demo Runner (`run_demo.py`) - CLI demo execution with scenario selection

### 9. Benchmarking & Testing
- [x] Benchmark Script (`scripts/benchmark.py`) - Throughput, latency p50/p95, CPU/RAM stats
- [x] Pytest Unit Tests (`tests/`) - Complete test suite (17/17 passing)
- [x] Documentation (`README.md`) - Full technical reference & guide
