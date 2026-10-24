
import os
import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict

from scapy.all import rdpcap, IP, TCP

BASE_DIR = Path(__file__).resolve().parent.parent

PCAP_FILE = Path(
    os.environ.get(
        "PCAP_FILE",
        str(BASE_DIR / "packet_capture" / "sample.pcap")
    )
)

RESULTS_DIR = BASE_DIR / "results"
REPORT_FILE = RESULTS_DIR / "attack_report.json"

PORT_SCAN_THRESHOLD = 5
SYN_FLOOD_THRESHOLD = 20


def detect_attacks():
    if not PCAP_FILE.exists():
        print("ERROR: PCAP file not found:", PCAP_FILE)
        return

    packets = rdpcap(str(PCAP_FILE))

    # Keep packet-level evidence for each source IP.
    source_targets = defaultdict(set)
    source_target_packets = defaultdict(list)
    syn_counts = defaultdict(int)
    syn_packet_numbers = defaultdict(list)

    alerts = []

    for number, packet in enumerate(packets, start=1):
        if IP not in packet or TCP not in packet:
            continue

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        tcp = packet[TCP]
        destination_port = int(tcp.dport)

        target = (destination_ip, destination_port)

        source_targets[source_ip].add(target)
        source_target_packets[source_ip].append({
            "packet_number": number,
            "destination_ip": destination_ip,
            "destination_port": destination_port
        })

        flags = int(tcp.flags)

        # Initial SYN without ACK.
        if (flags & 0x02) and not (flags & 0x10):
            syn_counts[source_ip] += 1
            syn_packet_numbers[source_ip].append(number)

    detected_at = datetime.now().astimezone().isoformat(
        timespec="seconds"
    )

    # Port scan detection.
    for source_ip, targets in source_targets.items():
        if len(targets) >= PORT_SCAN_THRESHOLD:
            evidence = source_target_packets[source_ip]

            alerts.append({
                "time": detected_at,
                "type": "Possible Port Scan",
                "source_ip": source_ip,
                "details": (
                    f"Connections to {len(targets)} unique "
                    "destination IP and port combinations"
                ),
                "severity": "Medium",
                "target_combinations": [
                    {
                        "destination_ip": destination_ip,
                        "destination_port": destination_port
                    }
                    for destination_ip, destination_port in sorted(targets)
                ],
                "evidence_packet_numbers": [
                    item["packet_number"] for item in evidence
                ]
            })

    # SYN flood detection.
    for source_ip, count in syn_counts.items():
        if count >= SYN_FLOOD_THRESHOLD:
            alerts.append({
                "time": detected_at,
                "type": "Possible SYN Flood",
                "source_ip": source_ip,
                "details": f"{count} TCP SYN packets detected",
                "severity": "High",
                "evidence_packet_numbers": syn_packet_numbers[source_ip]
            })

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    report = {
        "packets_analyzed": len(packets),
        "alerts_found": len(alerts),
        "alerts": alerts
    }

    with REPORT_FILE.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print("=" * 45)
    print("NETWORK ATTACK DETECTION")
    print("=" * 45)
    print("Packets analyzed:", len(packets))
    print("Alerts found:", len(alerts))

    for alert in alerts:
        print("\nAlert:", alert["type"])
        print("Source IP:", alert["source_ip"])
        print("Severity:", alert["severity"])
        print("Details:", alert["details"])

    print("\nReport saved to:", REPORT_FILE)


if __name__ == "__main__":
    detect_attacks()
