# One-Way Passive Monitoring Architecture

## Purpose

This component is designed for the SIH 26145 requirement of detecting threats from passively observed, unidirectional IP traffic.

## Data Flow

```text
Monitored Network
       |
       |  Passive traffic observation
       v
One-Way Monitoring Boundary
       |
       |  Inbound traffic only
       v
Zeek Sensor
       |
       v
Structured Zeek Logs
       |
       v
Network Event Parser
       |
       v
Normalized Events
       |
       v
Downstream Detection Pipeline
