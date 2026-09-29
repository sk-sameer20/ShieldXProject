import os
import subprocess
import json
import sys

# Need to append the root directory to path to allow script to be run directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from src.parser.zeek_parser import normalize_event
from src.ddos.ddos_detector import detect_ddos
from src.c2.inference import run_c2_detection
from src.dns.inference import run_dns_tunnel_detection
from src.dga.inference import run_dga_detection

def run_zeek(pcap_path: str):
    """Run Zeek on a PCAP file and output JSON logs."""
    if not os.path.exists(pcap_path):
        print(f"Error: PCAP not found at {pcap_path}")
        sys.exit(1)

    print(f"Running Zeek on {pcap_path}...")
    try:
        # Run Zeek with JSON output enabled
        subprocess.run(
            ["zeek", "-C", "-r", pcap_path, "LogAscii::use_json=T"],
            check=True,
            capture_output=True,
            text=True
        )
    except FileNotFoundError:
        print("Error: 'zeek' command not found. Is Zeek installed and in your PATH?")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"Zeek execution failed:\n{e.stderr}")
        sys.exit(1)

def process_logs():
    """Process Zeek JSON logs through the detection pipeline."""
    # Process conn.log
    if os.path.exists("conn.log"):
        print("\nProcessing conn.log...")
        conn_records = []
        with open("conn.log", "r") as f:
            for line in f:
                if line.strip():
                    try:
                        raw = json.loads(line)
                        conn_records.append(normalize_event(raw))
                    except json.JSONDecodeError:
                        continue
        
        print(f"Parsed {len(conn_records)} connection records.")
        
        # Run DDoS
        ddos_alert = detect_ddos(conn_records)
        print("\nDDoS Detection:")
        print(json.dumps(ddos_alert, indent=2))
        
        # Run C2
        # In production this would group by src_ip. For testing, we evaluate the unique IPs.
        src_ips = set(r["src_ip"] for r in conn_records if r.get("src_ip"))
        print(f"\nC2 Detection for {len(src_ips)} unique source IPs:")
        for ip in src_ips:
            ip_records = [r for r in conn_records if r.get("src_ip") == ip]
            c2_alert = run_c2_detection(ip_records, src_ip=ip)
            if c2_alert.detected:
                print(f"  [+] C2 Alert for {ip}: Confidence {c2_alert.confidence:.2f}")
            else:
                print(f"  [-] No C2 beaconing for {ip}.")

    # Process dns.log
    if os.path.exists("dns.log"):
        print("\nProcessing dns.log...")
        dns_records = []
        with open("dns.log", "r") as f:
            for line in f:
                if line.strip():
                    try:
                        raw = json.loads(line)
                        dns_records.append(normalize_event(raw))
                    except json.JSONDecodeError:
                        continue
        
        print(f"Parsed {len(dns_records)} DNS records.")
        
        # Run DGA
        print("\nDGA Detection:")
        for record in dns_records:
            if record.get("query"):
                dga_alert = run_dga_detection(record["query"])
                if dga_alert.detected:
                    print(f"  [+] DGA Alert: '{record['query']}' - Confidence {dga_alert.confidence:.2f} (Expert A: {dga_alert.technical_evidence.get('expert_a_v2_score')}, Expert B: {dga_alert.technical_evidence.get('expert_b_v6_score')})")
        
        # Run DNS Tunneling
        src_ips = set(r["src_ip"] for r in dns_records if r.get("src_ip"))
        print(f"\nDNS Tunneling Detection for {len(src_ips)} unique source IPs:")
        for ip in src_ips:
            ip_records = [r for r in dns_records if r.get("src_ip") == ip]
            tunnel_alert = run_dns_tunnel_detection(ip_records, src_ip=ip)
            if tunnel_alert.detected:
                print(f"  [+] DNS Tunnel Alert for {ip}: Confidence {tunnel_alert.confidence:.2f}")
            else:
                print(f"  [-] No DNS Tunneling for {ip}.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python run_zeek_pipeline.py <sample.pcap>")
        sys.exit(1)
    
    pcap = sys.argv[1]
    run_zeek(pcap)
    process_logs()
    
    print("\nPipeline execution complete.")
