import argparse
import asyncio
import os
import time
import yaml
from typing import Dict, Any

from src.ingestion.replay import EventReplayer
from src.streaming.scheduler import StreamingScheduler
from src.alerts.schema import AlertSchema


def load_config(config_path: str) -> Dict[str, Any]:
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


def format_alert_box(alert: AlertSchema) -> str:
    sev_colors = {
        "critical": "\033[91m", # Red
        "high": "\033[93m",     # Yellow
        "medium": "\033[96m",   # Cyan
        "low": "\033[92m",      # Green
    }
    reset = "\033[0m"
    color = sev_colors.get(alert.severity.lower(), reset)

    lines = [
        f"{color}==================== ALERT GENERATED ===================={reset}",
        f"  ID           : {alert.id}",
        f"  Timestamp    : {alert.timestamp:.2f}",
        f"  Threat Type  : {alert.threat_type}",
        f"  Severity     : {color}{alert.severity.upper()}{reset}",
        f"  Confidence   : {alert.confidence:.4f}",
        f"  Source IP    : {alert.src_ip}",
        f"  Model Version: {alert.model_version}",
        f"  Suppression  : {alert.suppressed_count} repeated events grouped",
        f"  Evidence     :"
    ]
    for ev in alert.evidence:
        lines.append(f"    - {ev}")
    lines.append(f"{color}========================================================{reset}")
    return "\n".join(lines)


async def main_async(args):
    scenario_files = {
        "sample": "data/sample/sample_events.jsonl",
        "benign": "data/sample/benign.jsonl",
        "ddos": "data/sample/ddos.jsonl",
        "c2": "data/sample/c2.jsonl",
        "dga": "data/sample/dga.jsonl",
    }

    file_path = scenario_files.get(args.scenario.lower(), args.scenario)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(base_dir, file_path) if not os.path.isabs(file_path) else file_path
    
    if not os.path.exists(file_path):
        print(f"Error: Dataset file '{file_path}' does not exist.")
        return

    config_path = args.config
    if config_path == "config.yaml":
        config_path = os.path.join(base_dir, "config.yaml")
        
    config = load_config(config_path)
    if args.db:
        if "storage" not in config:
            config["storage"] = {}
        config["storage"]["db_path"] = args.db

    print("=" * 65)
    print("  SIH26145 Real-Time Threat Streaming & Orchestration Engine")
    print("=" * 65)
    print(f"  Scenario     : {args.scenario}")
    print(f"  Event File   : {file_path}")
    print(f"  Speed Factor : {args.speed}x")
    print(f"  SQLite DB    : {config.get('storage', {}).get('db_path', 'outputs/sih26145.db')}")
    print("=" * 65 + "\n")

    emitted_alerts = []

    def on_alert(alert: AlertSchema):
        emitted_alerts.append(alert)
        print(format_alert_box(alert))

    scheduler = StreamingScheduler(config=config, alert_callback=on_alert)
    replayer = EventReplayer(speed=args.speed)

    # Start consumer loop task
    consumer_task = asyncio.create_task(scheduler.run_loop())

    start_time = time.time()
    event_count = 0

    print("[*] Replaying event stream...")
    async for event in replayer.replay(file_path):
        event_count += 1
        await scheduler.push_event(event)

    # Allow consumer queue to flush
    while not scheduler.queue.empty():
        await asyncio.sleep(0.05)

    await asyncio.sleep(0.1)
    scheduler.stop()
    consumer_task.cancel()

    elapsed = time.time() - start_time
    stats = scheduler.queue.get_stats()
    db_stats = scheduler.storage.get_stats()

    print("\n" + "=" * 65)
    print("                 PIPELINE EXECUTION SUMMARY")
    print("=" * 65)
    print(f"  Total Events Processed : {stats['events_processed']} / {event_count}")
    print(f"  Events Dropped         : {stats['events_dropped']}")
    print(f"  Execution Time         : {elapsed:.2f} seconds")
    print(f"  Effective Throughput   : {stats['events_processed'] / max(elapsed, 0.001):.1f} events/sec")
    print(f"  Alerts Generated       : {scheduler.alerts_generated}")
    print(f"  Alerts Emitted (Stored): {scheduler.alerts_emitted}")
    print(f"  DB Stored Total Alerts : {db_stats['total_alerts']}")
    print(f"  DB Alerts by Threat    : {db_stats['by_threat_type']}")
    print(f"  DB Alerts by Severity  : {db_stats['by_severity']}")
    print("=" * 65 + "\n")


def main():
    parser = argparse.ArgumentParser(description="SIH26145 Real-Time Threat Streaming Engine Demo")
    parser.add_argument("--scenario", type=str, default="sample", choices=["sample", "benign", "ddos", "c2", "dga"],
                        help="Attack scenario dataset to replay")
    parser.add_argument("--speed", type=float, default=100.0, help="Replay speed multiplier (e.g. 1, 10, 100, 0=instant)")
    parser.add_argument("--config", type=str, default="config.yaml", help="Path to config file")
    parser.add_argument("--db", type=str, default="outputs/sih26145.db", help="Path to SQLite DB output file")

    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
