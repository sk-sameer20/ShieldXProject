# SIH26145 - C2 & DGA Detector Project

## Overview
This repository contains the complete source code for the Command and Control (C2) and Domain Generation Algorithm (DGA) Detector. It is an advanced cybersecurity threat detection platform that identifies malicious network traffic, specifically focusing on C2 communications and DGA-generated domain names.

## Project Structure
The project is divided into several main components:
- **`src/`**: The core Python ML pipelines and detectors (C2, DGA, DNS, DDoS, and network parsers).
- **`training/`**: Scripts and Jupyter notebooks used for data analysis, model training, and evaluation.
- **`UI/SIH/Backend/`**: The Python-based backend API (FastAPI) that interfaces with the detection engine and serves data to the frontend. Uses `shieldx.db` (SQLite).
- **`UI/SIH/Frontend/`**: A React application built with Vite that provides a dashboard (ShieldX) to visualize alerts, live traffic, and system settings.

## Current State
- The core ML pipelines and network parsers (`zeek_parser`) are implemented and tested.
- The React Frontend has a dashboard with Live Traffic Rate Charts, Alerts page, and Settings.
- The Backend API connects to a local database (`shieldx.db`).

## How to Run This Project

### 1. Setup the Backend
1. Navigate to the backend directory:
   ```bash
   cd UI/SIH/Backend
   ```
2. Create and activate a Python virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the backend server:
   ```bash
   uvicorn app.main:app --reload
   ```

### 2. Setup the Frontend
1. Navigate to the frontend directory:
   ```bash
   cd UI/SIH/Frontend
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Run the Vite development server:
   ```bash
   npm run dev
   ```

### 3. Running the Detection Pipeline
Refer to `run_demo.py` in the root directory to see how the Zeek logs (`conn.log`, `dns.log`, etc.) are processed by the ML engine.
