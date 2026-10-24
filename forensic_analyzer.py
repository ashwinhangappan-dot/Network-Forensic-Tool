
import os
import json
from pathlib import Path
from datetime import datetime

from scapy.all import rdpcap, IP, TCP, UDP, ICMP

BASE_DIR = Path(__file__).resolve().parent.parent

PCAP_FILE = Path(
    os.environ.get(
        "PCAP_FILE",
        str(BASE_DIR / "packet_capture" / "sample.pcap")
    )
)

REPORT_FILE = BASE_DIR / "results" / "attack_report.json"
OUTPUT_FILE = BASE_DIR / "results" / "forensic_timeline.json"


def get_alert_source(alert):
    return (
        alert.get("source_ip")
        or alert.get("src_ip")
        or alert.get("src")
    )


def get_alert_type(alert):
    return str(
        alert.get("attack_type")
        or alert.get("attack")
        or alert.get("type")
        or alert.get("alert_type")
        or alert.get("name")
        or alert.get("description")
        or ""
    ).lower().replace("_", " ").strip()


def get_alert_port(alert):
    port = (
        alert.get("destination_port")
        or alert.get("dst_port")
        or alert.get("dest_port")
        or alert.get("port")
    )

    if port is None:
        return None

    try:
        return int(port)
    except (ValueError, TypeError):
        return None


def matches_alert(packet, event, alert):
    source_ip = get_alert_source(alert)

    # Source IP must match.
    if not source_ip or event["source_ip"] != source_ip:
        return False

    alert_type = get_alert_type(alert)
    alert_port = get_alert_port(alert)

    # Check protocol if the alert specifies one.
    alert_protocol = str(alert.get("protocol") or "").upper()

    if alert_protocol in {"TCP", "UDP", "ICMP"}:
        if event["protocol"] != alert_protocol:
            return False

    # Port scan: require a matching destination port.
    # Source IP alone is insufficient evidence.
    if "port scan" in alert_type or "portscan" in alert_type:
        if TCP not in packet or alert_port is None:
            return False

        return event["destination_port"] == alert_port

    # SYN flood: identify TCP SYN packets without ACK.
    if "syn flood" in alert_type or "synflood" in alert_type:
        if TCP not in packet:
            return False

        flags = int(packet[TCP].flags)

        is_syn = bool(flags & 0x02)
        is_ack = bool(flags & 0x10)

        return is_syn and not is_ack

    # Unknown alert types are not matched automatically.
    return False


def analyze_evidence():
    if not PCAP_FILE.exists():
        print("ERROR: PCAP file not found:", PCAP_FILE)
        return

    print("Reading PCAP:", PCAP_FILE)

    packets = rdpcap(str(PCAP_FILE))

    alerts = []

    if REPORT_FILE.exists():
        try:
            with open(REPORT_FILE, "r", encoding="utf-8") as file:
                report = json.load(file)

            alerts = report.get("alerts", [])

            if not isinstance(alerts, list):
                alerts = []

        except (OSError, json.JSONDecodeError) as error:
            print("WARNING: Could not read attack report:", error)

    timeline = []

    protocol_counts = {
        "TCP": 0,
        "UDP": 0,
        "ICMP": 0,
        "Other": 0
    }

    suspicious_count = 0

    for number, packet in enumerate(packets, start=1):

        try:
            timestamp = datetime.fromtimestamp(
                float(packet.time)
            ).astimezone().isoformat(timespec="seconds")
        except (ValueError, OSError, OverflowError):
            timestamp = None

        event = {
            "packet_number": number,
            "timestamp": timestamp,
            "source_ip": None,
            "destination_ip": None,
            "protocol": "Other",
            "source_port": None,
            "destination_port": None,
            "size_bytes": len(packet),
            "suspicious_source": False,
            "matched_alerts": []
        }

        if IP in packet:
            event["source_ip"] = packet[IP].src
            event["destination_ip"] = packet[IP].dst

        if TCP in packet:
            event["protocol"] = "TCP"
            event["source_port"] = int(packet[TCP].sport)
            event["destination_port"] = int(packet[TCP].dport)

        elif UDP in packet:
            event["protocol"] = "UDP"
            event["source_port"] = int(packet[UDP].sport)
            event["destination_port"] = int(packet[UDP].dport)

        elif ICMP in packet:
            event["protocol"] = "ICMP"

        protocol_counts[event["protocol"]] += 1

        for alert in alerts:
            if matches_alert(packet, event, alert):
                event["matched_alerts"].append({
                    "type": get_alert_type(alert),
                    "source_ip": get_alert_source(alert),
                    "severity": alert.get("severity", "Unknown")
                })

        event["suspicious_source"] = bool(event["matched_alerts"])

        if event["suspicious_source"]:
            suspicious_count += 1

        timeline.append(event)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    result = {
        "total_packets": len(packets),
        "alerts_correlated": len(alerts),
        "suspicious_packets": suspicious_count,
        "normal_packets": len(packets) - suspicious_count,
        "protocol_counts": protocol_counts,
        "timeline": timeline
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(result, file, indent=4)

    print("=" * 45)
    print("FORENSIC EVIDENCE ANALYSIS")
    print("=" * 45)
    print("Packets analyzed:", len(packets))
    print("Alerts correlated:", len(alerts))
    print("Suspicious packets:", suspicious_count)
    print("Normal packets:", len(packets) - suspicious_count)
    print("Protocol counts:", protocol_counts)
    print("Timeline saved to:", OUTPUT_FILE)


if __name__ == "__main__":
    analyze_evidence()
