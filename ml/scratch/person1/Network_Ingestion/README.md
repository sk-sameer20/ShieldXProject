# SIH 26145 — Network Ingestion

## Overview

This component provides the passive network-ingestion foundation for SIH Problem Statement #26145:

**AI-Based Detection of Cyber Threats in Unidirectional IP Traffic**

The pipeline processes passively collected network traffic without sending probes, completing handshakes, or issuing mitigation commands into the monitored network.

## Pipeline

```text
PCAP / Passive Traffic
        |
        v
      Zeek
        |
        v
   conn.log (JSON)
        |
        v
 Python Normalizer
        |
        v
 normalized.json
        |
        v
 Downstream Streaming / ML Detection
