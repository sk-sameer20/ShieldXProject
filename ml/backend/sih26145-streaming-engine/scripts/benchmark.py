import os
import sys
import json
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import numpy as np
import psutil
import argparse
from typing import Dict, Any, List

from src.ingestion.parser import NetworkEvent
from src.streaming.scheduler import StreamingScheduler
from src.features.ddos_adapter import DDoSFeatureAdapter
from src.detectors.ddos_adapter import MockDDoSDetector


def generate_benchmark_events(count: int = 5000) -> List[NetworkEvent]:
    events = []
    base_ts = 1727000000.0
    for i in range(count):
        ts = base_ts + (i * 0.005) # 200 events/sec simulation
        is_attack = (1000 <= i <= 3000)
        
        events.append(NetworkEvent(
            timestamp=round(ts, 4),
            src_ip="10.0.0.50" if is_attack else f"10.0.0.{(i % 50) + 1}",
            dst_ip="192.168.1.100",
            src_port=40000 + (i % 5000),
            dst_port=80 if is_attack else (443 if i % 2 == 0 else 53),
            protocol="tcp",
            orig_bytes=64 if is_attack else 500,
            resp_bytes=0 if is_attack else 1200,
            orig_pkts=1 if is_attack else 5,
            resp_pkts=0 if is_attack else 5,
            syn_flag=is_attack
        ))
    return events


def run_benchmark(event_count: int = 5000, output_json: str = "outputs/benchmark_results.json"):
    print("=" * 65)
    print("      SIH26145 Streaming Engine Performance Benchmark")
    print("=" * 65)
    print(f"  Target Event Count : {event_count}")

    process = psutil.Process(os.getpid())
    cpu_before = process.cpu_percent(interval=None)
    mem_before_mb = process.memory_info().rss / (1024 * 1024)

    events = generate_benchmark_events(event_count)

    scheduler = StreamingScheduler(config={
        "queue": {"max_size": 10000},
        "storage": {"db_path": "outputs/benchmark_temp.db"}
    })

    ddos_adapter = DDoSFeatureAdapter()
    ddos_detector = MockDDoSDetector()

    feature_latencies_ms: List[float] = []
    detector_latencies_ms: List[float] = []
    e2e_latencies_ms: List[float] = []

    start_time = time.perf_counter()

    for event in events:
        e2e_start = time.perf_counter()

        # Window addition
        scheduler.window_manager.add_event(event)

        # Feature extraction timing
        f_start = time.perf_counter()
        window_events = scheduler.window_manager.get_ddos_window(event.src_ip)
        features = ddos_adapter.extract_features(window_events, window_seconds=5.0)
        f_end = time.perf_counter()
        feature_latencies_ms.append((f_end - f_start) * 1000.0)

        # Detector timing
        d_start = time.perf_counter()
        pred = ddos_detector.predict(features)
        d_end = time.perf_counter()
        detector_latencies_ms.append((d_end - d_start) * 1000.0)

        # Process complete pipeline logic
        scheduler._evaluate_windows_for_host(event.src_ip, event.timestamp)

        e2e_end = time.perf_counter()
        e2e_latencies_ms.append((e2e_end - e2e_start) * 1000.0)

    end_time = time.perf_counter()
    total_elapsed = end_time - start_time

    cpu_after = process.cpu_percent(interval=None)
    mem_after_mb = process.memory_info().rss / (1024 * 1024)

    throughput = event_count / max(total_elapsed, 0.0001)

    results = {
        "event_count": event_count,
        "total_elapsed_seconds": round(total_elapsed, 4),
        "throughput_events_per_sec": round(throughput, 2),
        "feature_latency_ms": {
            "mean": round(float(np.mean(feature_latencies_ms)), 4),
            "p50": round(float(np.percentile(feature_latencies_ms, 50)), 4),
            "p95": round(float(np.percentile(feature_latencies_ms, 95)), 4),
            "max": round(float(np.max(feature_latencies_ms)), 4)
        },
        "detector_latency_ms": {
            "mean": round(float(np.mean(detector_latencies_ms)), 4),
            "p50": round(float(np.percentile(detector_latencies_ms, 50)), 4),
            "p95": round(float(np.percentile(detector_latencies_ms, 95)), 4),
            "max": round(float(np.max(detector_latencies_ms)), 4)
        },
        "e2e_latency_ms": {
            "mean": round(float(np.mean(e2e_latencies_ms)), 4),
            "p50": round(float(np.percentile(e2e_latencies_ms, 50)), 4),
            "p95": round(float(np.percentile(e2e_latencies_ms, 95)), 4),
            "max": round(float(np.max(e2e_latencies_ms)), 4)
        },
        "queue_stats": scheduler.queue.get_stats(),
        "alerts_generated": scheduler.alerts_generated,
        "alerts_emitted": scheduler.alerts_emitted,
        "resources": {
            "cpu_percent": cpu_after,
            "memory_usage_mb": round(mem_after_mb, 2),
            "memory_delta_mb": round(mem_after_mb - mem_before_mb, 2)
        }
    }

    os.makedirs(os.path.dirname(output_json), exist_ok=True)
    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    # Clean up temp benchmark db
    if os.path.exists("outputs/benchmark_temp.db"):
        try:
            os.remove("outputs/benchmark_temp.db")
        except Exception:
            pass

    print(f"  Total Elapsed Time     : {total_elapsed:.4f} s")
    print(f"  Throughput             : {throughput:.1f} events/sec")
    print(f"  Feature Latency (p50)  : {results['feature_latency_ms']['p50']:.4f} ms")
    print(f"  Feature Latency (p95)  : {results['feature_latency_ms']['p95']:.4f} ms")
    print(f"  Detector Latency (p50) : {results['detector_latency_ms']['p50']:.4f} ms")
    print(f"  Detector Latency (p95) : {results['detector_latency_ms']['p95']:.4f} ms")
    print(f"  E2E Latency (p50)      : {results['e2e_latency_ms']['p50']:.4f} ms")
    print(f"  E2E Latency (p95)      : {results['e2e_latency_ms']['p95']:.4f} ms")
    print(f"  RAM Usage              : {mem_after_mb:.2f} MB")
    print(f"  Alerts Stored          : {scheduler.alerts_emitted}")
    print(f"  Results Saved To       : {output_json}")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Benchmark SIH26145 Streaming Engine")
    parser.add_argument("--count", type=int, default=5000, help="Number of benchmark events to process")
    parser.add_argument("--output", type=str, default="outputs/benchmark_results.json", help="Output benchmark JSON path")
    args = parser.parse_args()
    run_benchmark(event_count=args.count, output_json=args.output)
