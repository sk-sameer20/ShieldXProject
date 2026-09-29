# SIH 26145 — Person 1 Network Ingestion

## Purpose

This folder contains the network-ingestion component for SIH Problem Statement #26145.

Its job is to convert passively observed network traffic into structured network events that can be consumed by downstream streaming, feature-extraction, and AI/ML threat-detection components.

## Pipeline

PCAP / Passive Traffic
→ Zeek
→ Zeek JSON Logs
→ `parser/zeek_parser.py`
→ Normalized Network Events
→ Downstream Detection Pipeline

## For Teammates

- Treat this component as the passive ingestion layer.
- Do not add active network probing or scanning.
- Do not add mitigation or outbound control commands.
- Do not decrypt application payloads.
- Preserve the normalized event schema when integrating with downstream components.
- Use `parser/test_zeek_parser.py` to verify parser changes.
- Generated logs, PCAPs, and build artifacts should not be committed as source files.
- Coordinate schema changes with the streaming/ML team before modifying the parser output.

## Main Files

- `parser/zeek_parser.py` — converts Zeek JSON connection records into normalized events.
- `parser/test_zeek_parser.py` — parser validation tests.
- `README.md` — component documentation and usage.
- `ONE_WAY_ARCHITECTURE.md` — passive/one-way monitoring architecture.
- `requirements.txt` — Python requirements.

## Normalized Event

The parser produces events containing fields such as:

- `timestamp`
- `src_ip`
- `dst_ip`
- `src_port`
- `dst_port`
- `protocol`
- `duration`
- `orig_bytes`
- `resp_bytes`
- `orig_pkts`
- `resp_pkts`

## Integration

Downstream components should consume the normalized events rather than depending directly on Zeek field names.

Threat detection, feature extraction, streaming, correlation, scoring, and alert generation are handled by the downstream project components.
