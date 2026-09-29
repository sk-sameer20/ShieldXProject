import asyncio
import time
from typing import Dict, Any, List, Optional, Callable
from src.ingestion.parser import NetworkEvent
from src.streaming.event_queue import EventQueue
from src.streaming.window_manager import WindowManager
from src.features.baseline import HostBaseline
from src.features.ddos_adapter import DDoSFeatureAdapter
from src.features.c2_adapter import C2FeatureAdapter
from src.features.dns_adapter import DNSFeatureAdapter
from src.detectors.ddos_adapter import RealDDoSAdapter
from src.detectors.c2_adapter import RealC2Adapter
from src.detectors.dga_adapter import RealDGAAdapter
from src.detectors.dns_tunnel_adapter import RealDNSTunnelAdapter
from src.fusion.evidence import EvidenceAggregator
from src.fusion.confidence import ConfidenceEngine
from src.fusion.severity import SeverityEngine
from src.alerts.builder import AlertBuilder
from src.alerts.validator import AlertValidator
from src.alerts.deduplication import AlertDeduplicator
from src.alerts.schema import AlertSchema
from src.storage.sqlite_store import SQLiteStore


class StreamingScheduler:
    """
    Main real-time orchestration engine connecting streaming events, sliding window features,
    detectors, fusion, deduplication, and persistence.
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        alert_callback: Optional[Callable[[AlertSchema], None]] = None
    ):
        self.config = config or {}
        
        # Core components initialization
        self.queue = EventQueue(
            max_size=self.config.get("queue", {}).get("max_size", 10000),
            drop_on_overflow=True
        )
        self.window_manager = WindowManager(
            window_config=self.config.get("windows")
        )
        self.baseline = HostBaseline()
        
        # Feature adapters
        self.ddos_adapter = DDoSFeatureAdapter()
        self.c2_adapter = C2FeatureAdapter()
        self.dns_adapter = DNSFeatureAdapter()
        
        # Detector adapters (pluggable with real models)
        self.ddos_detector = RealDDoSAdapter()
        self.c2_detector = RealC2Adapter()
        self.dga_detector = RealDGAAdapter()
        self.dns_tunnel_detector = RealDNSTunnelAdapter()
        
        # Fusion & alert engines
        fusion_cfg = self.config.get("fusion", {})
        self.confidence_engine = ConfidenceEngine(
            model_weight=fusion_cfg.get("model_weight", 0.5),
            anomaly_weight=fusion_cfg.get("anomaly_weight", 0.3),
            baseline_weight=fusion_cfg.get("baseline_weight", 0.2)
        )
        self.severity_engine = SeverityEngine()
        self.evidence_aggregator = EvidenceAggregator()
        self.alert_builder = AlertBuilder()
        self.alert_validator = AlertValidator()
        self.alert_deduplicator = AlertDeduplicator(
            suppression_window_seconds=self.config.get("deduplication", {}).get("suppression_window_seconds", 30.0)
        )
        
        # Storage
        db_path = self.config.get("storage", {}).get("db_path", "outputs/sih26145.db")
        self.storage = SQLiteStore(db_path=db_path)
        
        self.alert_callback = alert_callback
        self.alerts_generated: int = 0
        self.alerts_emitted: int = 0
        self._running = False

    async def push_event(self, event: NetworkEvent) -> bool:
        """
        Pushes an incoming network event into the queue.
        """
        return await self.queue.put(event)

    def process_event_sync(self, event: NetworkEvent) -> List[AlertSchema]:
        """
        Synchronously processes a single event through windowing and detectors.
        Useful for synchronous benchmark runs or non-async loops.
        """
        self.window_manager.add_event(event)
        try:
            return asyncio.run(self._evaluate_windows_for_host(event.src_ip, event.timestamp))
        except RuntimeError:
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(self._evaluate_windows_for_host(event.src_ip, event.timestamp))

    async def run_loop(self) -> None:
        """
        Asynchronous consumer loop pulling events from queue and processing.
        """
        self._running = True
        while self._running:
            if self.queue.empty():
                await asyncio.sleep(0.01)
                continue

            try:
                event = await self.queue.get()
                self.window_manager.add_event(event)
                alerts = await self._evaluate_windows_for_host(event.src_ip, event.timestamp)

                for alert in alerts:
                    if self.alert_callback:
                        self.alert_callback(alert)
            except Exception as e:
                import logging
                logging.error(f"StreamingScheduler encountered an error processing an event: {e}", exc_info=True)
                # Ensure we don't infinitely spin if something fundamentally breaks
                await asyncio.sleep(0.1)

    def stop(self) -> None:
        self._running = False

    async def _evaluate_windows_for_host(self, host_ip: str, current_ts: float) -> List[AlertSchema]:
        emitted_alerts: List[AlertSchema] = []

        # 1. DDoS Evaluation (5s window)
        ddos_events = self.window_manager.get_ddos_window(host_ip)
        if ddos_events:
            ddos_features = self.ddos_adapter.extract_features(ddos_events, window_seconds=5.0)
            
            # Baseline update vs z-score
            pps_z = self.baseline.get_z_score(host_ip, "pps", ddos_features["pps"])
            self.baseline.update_metric(host_ip, "pps", ddos_features["pps"])

            pred = await asyncio.to_thread(self.ddos_detector.predict, ddos_events)
            if pred["detected"]:
                conf = self.confidence_engine.calculate_confidence(
                    model_score=pred["score"],
                    anomaly_score=min(ddos_features["pps"] / 200.0, 1.0),
                    baseline_z_score=pps_z
                )
                if conf >= 0.4:
                    evidence = self.evidence_aggregator.aggregate(
                        model_evidence=pred["evidence"],
                        baseline_evidence=[f"Baseline PPS deviation Z-score: {pps_z:.2f}"] if pps_z > 2.0 else [],
                        feature_evidence=[]
                    )
                    sev = self.severity_engine.evaluate_severity("DDoS", conf, ddos_features)
                    alert = self.alert_builder.build_alert(
                        threat_type="DDoS",
                        src_ip=host_ip,
                        confidence=conf,
                        severity=sev,
                        evidence=evidence,
                        model_version=pred["model_version"],
                        timestamp=current_ts,
                        raw_features=ddos_features
                    )
                    self.alert_validator.validate(alert)
                    self.alerts_generated += 1

                    # Freeze host baseline to prevent attack contamination
                    if conf >= 0.7:
                        self.baseline.freeze_host(host_ip)

                    should_emit, alert_to_emit = self.alert_deduplicator.process_alert(alert)
                    if should_emit:
                        self.storage.save_alert(alert_to_emit)
                        self.alerts_emitted += 1
                        emitted_alerts.append(alert_to_emit)

        # 2. C2 Evaluation (60s window)
        c2_events = self.window_manager.get_c2_window(host_ip)
        if len(c2_events) >= 3:
            c2_features = self.c2_adapter.extract_features(c2_events, window_seconds=60.0)
            c2_pred = await asyncio.to_thread(self.c2_detector.predict, c2_events)
            if c2_pred["detected"]:
                conf = self.confidence_engine.calculate_confidence(
                    model_score=c2_pred["score"],
                    anomaly_score=c2_features["beacon_regularity_score"],
                    baseline_z_score=0.0
                )
                if conf >= 0.4:
                    evidence = self.evidence_aggregator.aggregate(
                        model_evidence=c2_pred["evidence"],
                        baseline_evidence=[],
                        feature_evidence=[]
                    )
                    sev = self.severity_engine.evaluate_severity("C2", conf, c2_features)
                    alert = self.alert_builder.build_alert(
                        threat_type="C2",
                        src_ip=host_ip,
                        confidence=conf,
                        severity=sev,
                        evidence=evidence,
                        model_version=c2_pred["model_version"],
                        timestamp=current_ts,
                        raw_features=c2_features
                    )
                    self.alert_validator.validate(alert)
                    self.alerts_generated += 1

                    if conf >= 0.7:
                        self.baseline.freeze_host(host_ip)

                    should_emit, alert_to_emit = self.alert_deduplicator.process_alert(alert)
                    if should_emit:
                        self.storage.save_alert(alert_to_emit)
                        self.alerts_emitted += 1
                        emitted_alerts.append(alert_to_emit)

        # 3. DNS/DGA Evaluation (60s window)
        dns_events = self.window_manager.get_dns_window(host_ip)
        if dns_events:
            dns_features = self.dns_adapter.extract_features(dns_events, window_seconds=60.0)
            
            dga_pred = await asyncio.to_thread(self.dga_detector.predict, dns_events)
            if dga_pred["detected"]:
                conf = self.confidence_engine.calculate_confidence(
                    model_score=dga_pred["score"],
                    anomaly_score=min(dns_features["avg_shannon_entropy"] / 4.5, 1.0),
                    baseline_z_score=0.0
                )
                if conf >= 0.4:
                    evidence = self.evidence_aggregator.aggregate(
                        model_evidence=dga_pred["evidence"],
                        baseline_evidence=[],
                        feature_evidence=[]
                    )
                    sev = self.severity_engine.evaluate_severity("DGA", conf, dns_features)
                    alert = self.alert_builder.build_alert(
                        threat_type="DGA",
                        src_ip=host_ip,
                        confidence=conf,
                        severity=sev,
                        evidence=evidence,
                        model_version=dga_pred["model_version"],
                        timestamp=current_ts,
                        raw_features=dns_features
                    )
                    self.alert_validator.validate(alert)
                    self.alerts_generated += 1

                    if conf >= 0.7:
                        self.baseline.freeze_host(host_ip)

                    should_emit, alert_to_emit = self.alert_deduplicator.process_alert(alert)
                    if should_emit:
                        self.storage.save_alert(alert_to_emit)
                        self.alerts_emitted += 1
                        emitted_alerts.append(alert_to_emit)
                        
            dns_tunnel_pred = await asyncio.to_thread(self.dns_tunnel_detector.predict, dns_events)
            if dns_tunnel_pred["detected"]:
                conf = self.confidence_engine.calculate_confidence(
                    model_score=dns_tunnel_pred["score"],
                    anomaly_score=0.0,
                    baseline_z_score=0.0
                )
                if conf >= 0.4:
                    evidence = self.evidence_aggregator.aggregate(
                        model_evidence=dns_tunnel_pred["evidence"],
                        baseline_evidence=[],
                        feature_evidence=[]
                    )
                    sev = self.severity_engine.evaluate_severity("DNS_TUNNEL", conf, dns_features)
                    alert = self.alert_builder.build_alert(
                        threat_type="DNS_TUNNEL",
                        src_ip=host_ip,
                        confidence=conf,
                        severity=sev,
                        evidence=evidence,
                        model_version=dns_tunnel_pred["model_version"],
                        timestamp=current_ts,
                        raw_features=dns_features
                    )
                    self.alert_validator.validate(alert)
                    self.alerts_generated += 1

                    if conf >= 0.7:
                        self.baseline.freeze_host(host_ip)

                    should_emit, alert_to_emit = self.alert_deduplicator.process_alert(alert)
                    if should_emit:
                        self.storage.save_alert(alert_to_emit)
                        self.alerts_emitted += 1
                        emitted_alerts.append(alert_to_emit)

        return emitted_alerts
