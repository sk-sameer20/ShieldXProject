import json
import sys


def normalize_event(record):
    return {
        "timestamp": record.get("ts"),
        "src_ip": record.get("id.orig_h"),
        "dst_ip": record.get("id.resp_h"),
        "src_port": record.get("id.orig_p"),
        "dst_port": record.get("id.resp_p"),
        "protocol": record.get("proto"),
        "duration": record.get("duration"),
        "orig_bytes": record.get("orig_bytes", 0),
        "resp_bytes": record.get("resp_bytes", 0),
        "orig_pkts": record.get("orig_pkts", 0),
        "resp_pkts": record.get("resp_pkts", 0),
        "conn_state": record.get("conn_state"),
        "query": record.get("query"),
        "qtype": record.get("qtype_name"),
        "rcode": record.get("rcode_name"),
    }


def parse_zeek_log(input_file, output_file):
    with open(input_file, "r", encoding="utf-8") as src, \
         open(output_file, "w", encoding="utf-8") as dst:

        for line in src:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            try:
                record = json.loads(line)
                event = normalize_event(record)
                dst.write(json.dumps(event) + "\n")
            except json.JSONDecodeError:
                continue


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 zeek_parser.py <input.json> <output.json>")
        sys.exit(1)

    parse_zeek_log(sys.argv[1], sys.argv[2])
