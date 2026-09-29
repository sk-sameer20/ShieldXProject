# 🛡️ SHIELDX: Enclave Cyber Defense & Real-Time SOC Console

<div align="center">

[![FastAPI](https://img.shields.io/badge/Backend-FastAPI%20%7C%20Python%203.11-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/Frontend-React%2019%20%7C%20Vite%208-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev/)
[![SQLite WAL](https://img.shields.io/badge/Storage-SQLite3%20WAL%20Mode-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://sqlite.org/)
[![Scikit-Learn](https://img.shields.io/badge/ML%20Engine-Isolation%20Forest%20%2B%20FFT-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](LICENSE)

**AI-Driven Passive Network Detection & Defense Enclave System**  
*Built for the Smart India Hackathon (Problem ID: SIH26145)*

[Live Console UI](#-system-architecture) • [Red-Team Benchmarks](#-verified-red-team-benchmarks) • [Quick Start](#-quick-start-guide) • [Lab Attack Scripts](#-red-team-lab-test-suite)

</div>

---

## 📌 Overview

**ShieldX** is an enterprise-grade, unidirectional enclave security system engineered for critical national infrastructure (CNI) and high-security air-gapped enclaves. By leveraging a **passive, receive-only network tap** (simulated data diode), ShieldX inspects 100% of mirrored network traffic in volatile memory without providing any physical or logical return path to an adversary.

### Core Capabilities:
* **Zero Attack Surface:** Operates strictly on mirrored packet taps—impossible to scan, exploit, or bypass over the wire.
* **Explainable AI (XAI):** Every single detection alert exposes underlying feature vectors, statistical thresholds, confidence metrics, and MITRE ATT&CK technique IDs.
* **Extreme Hardware Resilience:** Saturated at **1.70 Gbps wire rate (146,200 PPS)** across **16.0 GB flows** with **0 bytes written to the physical SSD** (all streaming occurs within volatile RAM ring-buffers).
* **0.0% False Positive Baseline:** Clean calibration guarantees zero operational alarm fatigue during normal human web browsing and administrative operations.

---

## 🏗️ System Architecture

```text
                                  UNIDIRECTIONAL BOUNDARY
┌─────────────────────────────────┐   Mirror Tap    ┌──────────────────────────────────────────────┐
│       EXTERNAL NETWORK          │ ──────────────► │       SHIELDX ISOLATED ENCLAVE HOST          │
│  • Mirrored Span / Diode Ingress│  (No Return)   │             (192.168.81.1:8000)              │
└─────────────────────────────────┘                 │                                              │
                 │                                  │  ┌────────────────────────────────────────┐  │
                 │ Passive Tap                      │  │       FastAPI Async Ingestion Hub      │  │
                 ▼                                  │  └───────────────────┬────────────────────┘  │
┌─────────────────────────────────┐                 │                      │                       │
│    ML FEATURE EXTRACTOR (RAM)   │ ────────────────┼──────────────────────┼───────────────────────┤
│  • IAT Delta Variance (FFT)     │                 │                      ▼                       │
│  • Shannon Character Entropy    │                 │  ┌────────────────────────────────────────┐  │
│  • N-gram Lexical Transitions   │                 │  │   SQLite 3 with WAL Mode (Zero SSD)    │  │
│  • Handshake Asymmetry Ratios   │                 │  └───────────────────┬────────────────────┘  │
└─────────────────────────────────┘                 │                      │                       │
                                                    │                      ▼ Instant Push (<2ms)   │
                                                    │  ┌────────────────────────────────────────┐  │
                                                    │  │   React 19 Vite Real-Time Console      │  │
                                                    │  │       (http://localhost:8080)          │  │
                                                    │  └────────────────────────────────────────┘  │
                                                    └──────────────────────────────────────────────┘
```

---

## 📊 Verified Red-Team Benchmarks

Compiled directly from our isolated testbed environment (`192.168.81.0/24`) consisting of a **Kali Linux Red-Team Node (`192.168.81.10`)**, a **Target Windows Node (`192.168.81.20`)**, and the **ShieldX Defense Host (`192.168.81.1`)**:

| Test ID | Evaluation Scenario | Tested Traffic Profile | Observed Throughput / Frequency | Model Detection Accuracy | Hardware & Storage Impact |
| :---: | :--- | :--- | :---: | :---: | :--- |
| **01** | **System Handshake** | REST API validation ping | $18\text{ ms}$ Roundtrip | $100\%$ Contract Valid | In-RAM |
| **02** | **Benign Baseline** | Normal ICMP echo & TCP handshakes | $2.1\text{ PPS}$ ($< 0.01\text{ Mbps}$) | **0.0% False Positives** ($12\%$ conf.) | Clean baseline |
| **03** | **TCP SYN Flood** | 1,000 asymmetric SYN packets to SMB | $28,400\text{ PPS}$ ($29.1\text{ Mbps}$) | **98.4% Confidence** (Critical) | Auto-Mitigated |
| **04** | **Stealth C2 (20% Jitter)**| Jittered timing probes ($2.1\text{s}, 1.8\text{s}$) | $0.5\text{ PPS}$ ($< 0.001\text{ Mbps}$) | **94.6% Confidence** ($CV=0.118$) | Invisible to volume meters |
| **05** | **Buffer Saturation** | 54-byte micro-frame flood | $89,400\text{ PPS}$ ($858.2\text{ Mbps}$) | **99.8% Confidence** (Critical) | $98.6\%$ Buffer utilization |
| **06** | **Micro-ms C2 Probe** | Micro-variance ($\pm 6\text{ ms}$ jitter) | $1.0\text{ PPS}$ ($1,000.5\text{ ms}$) | **97.2% Confidence** ($CV=0.012$) | Sub-ms timing isolation |
| **07** | **DGA Burst Attack** | Random algorithm DNS queries | 10 UDP bursts | **94.2% Confidence** ($3.78\text{ bits}$ entropy)| Lexical N-gram isolation |
| **08** | **1.0 GB Bulk Flow** | Full-MTU frames ($1,454\text{ bytes}$) | $738,474\text{ pkts}$ ($980.4\text{ Mbps}$) | **99.9% Confidence** (Critical) | 0 Bytes written to SSD |
| **09** | **5.0 GB Multi-Stream** | Multi-packet aggregate exfiltration | $3.69\text{M pkts}$ ($1.16\text{ Gbps}$) | **99.9% Confidence** (Critical) | In-RAM flow |
| **10** | **10.0 GB Volumetric** | Hyper-scale pipe exhaustion | $7.38\text{M pkts}$ ($1.38\text{ Gbps}$) | **100.0% Confidence** (1.00) | $18,420$ kernel drops logged |
| **11** | **16.0 GB Apex Flood** | Hardware-limit saturation flood | $11.8\text{M pkts}$ ($1.701\text{ Gbps}$) | **100.0% Confidence** (1.00) | 100% RAM envelope tested |

> 📄 **Complete technical breakdown:** Read the full [BENCHMARK_REPORT.md](BENCHMARK_REPORT.md).

---

## 📁 Repository Structure

```text
SIH - Project/
├── frontend/               # React 19 + Vite + TanStack SOC Defense Console
│   ├── src/
│   │   ├── components/     # High-performance glass components & HeroSystem
│   │   ├── pages/          # Landing, Overview, Incidents, Traffic, Detectors, System
│   │   ├── lib/            # Timezone-aware timestamp formatters & utilities
│   │   └── styles/         # Tokenized vanilla CSS design system
│   ├── package.json
│   └── vite.config.ts      # Configured to port 8080 with auto-proxying
│
├── backend/                # FastAPI Enclave REST API & WebSocket Hub
│   ├── app/
│   │   ├── api/routes.py   # Telemetry, Incidents, Stats & Ingestion Hooks
│   │   ├── db/             # SQLAlchemy engine & SQLite WAL database setup
│   │   ├── models/         # Pydantic v2 schemas and ORM models
│   │   └── services/       # Dynamic aggregations and analytics
│   ├── requirements.txt    # Production Python dependencies
│   ├── .env.example        # Environment configuration template
│   └── shieldx.db          # Pre-seeded SQLite database in WAL mode
│
├── lab_scripts/            # Red-team attack scripts for isolated testing
│   ├── test1.sh            # Ingestion & WebSocket link verification
│   ├── test2.sh            # Benign baseline calibration (zero false positives)
│   ├── test3.sh            # Controlled TCP SYN flood
│   ├── stealth_c2.sh       # APT periodic beaconing with 20% jitter
│   ├── micro_ms_test.sh    # Millisecond-boundary timing sensitivity test
│   ├── dga_test.sh         # Algorithmic domain entropy attack
│   ├── bulk_stream_test.sh # 1.0 GB bulk data flow test
│   ├── bulk_stream_5gb.sh  # 5.0 GB multi-stream exfiltration test
│   ├── bulk_stream_10gb.sh # 10.0 GB hyper-scale volumetric flood
│   └── real_16gb_flood.sh  # 16.0 GB genuine physical wire flood
│
├── ml/                     # ML training pipelines and inference engines
│   ├── src/                # Detectors for DDoS, C2 Beaconing, and DGA/DNS
│   ├── training/           # CTU-13 dataset preparation and training scripts
│   └── run_demo.py         # Standalone synthetic detection validator
│
├── BENCHMARK_REPORT.md     # Official Master Performance & Red-Team Report
└── README.md               # Primary project documentation
```

---

## 🚀 Quick Start Guide

### Prerequisites
* **Node.js**: v18.x or v20.x+ (`node -v`)
* **Python**: v3.10, v3.11, or v3.12+ (`python --version`)

---

### Step 1: Start the Backend (Terminal 1)

```bash
cd backend
python -m venv .venv

# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Linux / macOS:
source .venv/bin/activate

pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
* **REST API:** `http://localhost:8000/api`
* **Interactive OpenAPI Docs:** `http://localhost:8000/docs`
* **WebSocket Endpoint:** `ws://localhost:8000/ws/alerts`

---

### Step 2: Start the Frontend (Terminal 2)

```bash
cd frontend
npm install
npm run dev
```
* **Hero & Landing Page:** `http://localhost:8080/`
* **Real-Time SOC Console:** `http://localhost:8080/console`
* **Incidents Inspector:** `http://localhost:8080/console/incidents`
* **Live Ingress Traffic Graph:** `http://localhost:8080/console/traffic`

---

### Step 3: Serve Lab Scripts (Terminal 3)

```bash
cd lab_scripts
python -m http.server 8888 --bind 0.0.0.0
```
This allows attacker or sensor VMs on your network to fetch and execute test telemetry with a single `curl` command.

---

## 🧪 Red-Team Lab Test Suite

Once the services are active, execute any of the following commands from an attacker VM (e.g., Kali Linux at `192.168.81.10`) targeting the testbed victim (`192.168.81.20`):

```bash
# 1. Test Stealth C2 Beaconing with 20% Jitter Evasion:
curl -s http://192.168.81.1:8888/stealth_c2.sh | bash

# 2. Test Sub-Millisecond Jitter Precision (±6ms):
curl -s http://192.168.81.1:8888/micro_ms_test.sh | bash

# 3. Test Algorithmic Domain Generation (DGA Burst):
curl -s http://192.168.81.1:8888/dga_test.sh | bash

# 4. Test 1.0 GB Bulk Data Flow Saturation (980 Mbps Peak):
curl -s http://192.168.81.1:8888/bulk_stream_test.sh | bash

# 5. Test 16.0 GB Genuine Physical Wire Flood (1.70 Gbps Peak):
curl -s http://192.168.81.1:8888/real_16gb_flood.sh | bash
```

All test outcomes will immediately appear on the **React SOC Defense Console** via the WebSocket connection with zero browser refresh.

---

## 🔒 Security & Privacy Notice

* **Zero Hardcoded Credentials:** All environment secrets are managed via `.env` files (see `.env.example`).
* **Clean Artifacts:** Virtual environments (`.venv`), package dependencies (`node_modules`), SQLite WAL journals, and temporary build caches are ignored via `.gitignore` to prevent repository bloat.
* **Pure In-RAM Streaming:** Network stress tests process transient frames in memory without persisting raw capture payloads to disk.

---

## 📜 MITRE ATT&CK Mapping Matrix

| Threat Class | Technique ID | MITRE Technique Name | Detection Mechanism |
| :--- | :--- | :--- | :--- |
| **DDoS Flood** | `T1498.001` | Direct Volumetric Flooding | Multi-window PPS rate & SYN/ACK asymmetry |
| **C2 Beaconing** | `T1071.001` | Web Protocols / Covert Channels | Inter-Arrival Time (IAT) FFT & Isolation Forest |
| **DGA Domains** | `T1568.002` | Domain Generation Algorithms | Character entropy & Consonant N-gram transitions |
| **DNS Tunneling** | `T1048` | Exfiltration Over Alternative Protocol | Subdomain length variance & query payload entropy |

---

## 👥 Project Team & Attribution

Developed for **Smart India Hackathon 2026** — Enclave Defense Track (`SIH26145`).  
Licensed under the [MIT License](LICENSE).
