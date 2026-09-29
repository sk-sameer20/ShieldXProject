"""
Database initialization and table creation module for ShieldX SOC
"""
import logging
from sqlalchemy import select
from .session import sync_engine, SyncSessionLocal
from ..models import (
    Base,
    EnclaveConfig,
    SystemHealth,
    DiodeIntegrity,
    DetectionAttribution,
)

logger = logging.getLogger(__name__)


def create_tables():
    """Create all tables defined in Base metadata."""
    Base.metadata.create_all(bind=sync_engine)
    logger.info("All ShieldX database tables successfully verified/created.")


def drop_tables():
    """Drop all tables (primarily for test fixture isolation)."""
    Base.metadata.drop_all(bind=sync_engine)
    logger.info("All ShieldX database tables dropped.")


def init_db():
    """Initialize database tables and default baseline configuration records."""
    create_tables()

    with SyncSessionLocal() as session:
        # 1. Ensure Singleton EnclaveConfig exists
        config = session.scalar(select(EnclaveConfig).where(EnclaveConfig.id == 1))
        if not config:
            config = EnclaveConfig(
                id=1,
                rx_diode_active=True,
                tx_airgap_enforced=True,
                ring_buffer_size_mb=4096,
                sliding_window_sec=10.0,
                track_protocols={"tcp": True, "udp": True, "dns": True, "icmp": True},
                syn_threshold_pps=5000,
                entropy_cutoff=1.12,
                c2_jitter_threshold=2.4,
                confidence_floor=85,
                ws_batch_rate_ms=1000,
                zstd_compression=True,
                sound_alerts=True,
                auto_escalate_critical=False,
            )
            session.add(config)
            session.commit()
            logger.info("Default EnclaveConfig record initialized.")

        # 2. Ensure initial DiodeIntegrity record exists
        integrity = session.scalar(select(DiodeIntegrity).limit(1))
        if not integrity:
            integrity = DiodeIntegrity(
                physical_link_rx=True,
                physical_link_tx=False,
                optical_power_dbm=-13.8,
                ring_buffer_utilization_pct=18.4,
                dropped_frames=0,
                diode_state="NOMINAL",
                zeek_worker_threads=4,
                zeek_cpu_usage_pct=14.2,
                zeek_memory_usage_mb=842,
                zeek_uptime_seconds=432190,
                pipeline_latency_ms=1.28,
                tamper_evident_chain_valid=True,
                last_audit_hash="8f43a9b1c78e3290deaf1455bb39c011e4f9b8c2d1109a8734e5f901a1829bc3",
            )
            session.add(integrity)
            session.commit()
            logger.info("Default DiodeIntegrity record initialized.")

        # 3. Ensure initial SystemHealth record exists
        health = session.scalar(select(SystemHealth).limit(1))
        if not health:
            health = SystemHealth(
                status="Healthy",
                cpu_pct=98.0,
                cpu_detail="32 Cores · 48°C",
                memory_pct=76.0,
                memory_detail="24.3 / 32 GB",
                storage_pct=92.0,
                storage_detail="3.8 / 4.0 TB NVMe",
                sensors_pct=100.0,
                sensors_detail="12 / 12 Online",
                sources_json=[
                    {"name": "Firewall Telemetry", "status": "Online", "latency": "1.2ms"},
                    {"name": "IDS/IPS", "status": "Online", "latency": "0.8ms"},
                    {"name": "NetFlow Collector", "status": "Online", "latency": "2.1ms"},
                    {"name": "Threat Intelligence", "status": "Online", "latency": "4.5ms"},
                    {"name": "AI Detection Engine", "status": "Online", "latency": "0.3ms"},
                ],
                sensor_network_json={
                    "online_sensors": 12,
                    "total_sensors": 12,
                    "regions_count": 3,
                    "uptime_pct": 99.98,
                    "avg_latency_ms": 0.8,
                },
            )
            session.add(health)
            session.commit()
            logger.info("Default SystemHealth record initialized.")

        # 4. Ensure baseline DetectionAttribution records for the 3 engines
        engines = [
            DetectionAttribution(
                engine_type="DDOS",
                status_badge="ACTIVE THREAT",
                rule_name="Ensemble-Volumetric-SYN-Burst",
                target_host="10.240.0.12:443",
                attack_vector="TCP SYN Flood (Unidirectional)",
                cadence_or_duration="45.2 seconds",
                recommended_action="Rate-limit boundary ingress / Notify perimeter upstream",
                metrics_json={
                    "syn_pps": 28400,
                    "syn_delta": "+840%",
                    "entropy": 1.12,
                    "asymmetry_ratio": 1.0,
                    "confidence_pct": 98.4,
                    "model": "XGBoost-Volumetric-v3",
                },
            ),
            DetectionAttribution(
                engine_type="C2",
                status_badge="1 BEACON",
                rule_name="LSTM-Interval-Beacon-Detector",
                target_host="10.240.4.88",
                attack_vector="203.0.113.195:8443",
                cadence_or_duration="45.2s (Jitter: ±0.08s)",
                recommended_action="Isolate endpoint & revoke active Kerberos TGT",
                metrics_json={
                    "interval_mean_sec": 45.2,
                    "jitter_std": 0.08,
                    "payload_entropy": 7.84,
                },
            ),
            DetectionAttribution(
                engine_type="DGA",
                status_badge="ENTROPY SPIKE",
                rule_name="Entropy-DGA-Classifier-v2",
                target_host="10.240.1.19",
                attack_vector="*.ns1.exfil-tunnel.darknet.cc",
                cadence_or_duration="312 NXDOMAIN bursts / min",
                recommended_action="Sinkhole DNS zone at upstream resolver",
                metrics_json={
                    "domain_entropy": 4.62,
                    "txt_ratio": 0.78,
                    "nxdomain_burst_count": 312,
                },
            ),
        ]
        for eng in engines:
            existing = session.get(DetectionAttribution, eng.engine_type)
            if not existing:
                session.add(eng)
        session.commit()
        logger.info("Default DetectionAttribution records verified.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    init_db()
