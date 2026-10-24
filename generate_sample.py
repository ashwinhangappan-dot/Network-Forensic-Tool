
from pathlib import Path
from scapy.all import Ether, IP, TCP, UDP, wrpcap

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_FILE = BASE_DIR / "large_test.pcap"

packets = []

# 1. Normal test traffic: 59,000 packets
for i in range(59000):
    src = f"10.{(i // 65536) % 256}.{(i // 256) % 256}.{(i % 254) + 1}"

    if i % 3 == 0:
        packet = (
            Ether()
            / IP(src=src, dst="192.168.1.20")
            / TCP(
                sport=20000 + (i % 40000),
                dport=443,
                flags="A"
            )
        )

    elif i % 3 == 1:
        packet = (
            Ether()
            / IP(src=src, dst="8.8.8.8")
            / UDP(
                sport=30000 + (i % 30000),
                dport=53
            )
        )

    else:
        packet = (
            Ether()
            / IP(src=src, dst="192.168.1.20")
            / TCP(
                sport=20000 + (i % 40000),
                dport=80,
                flags="PA"
            )
        )

    packets.append(packet)

# 2. Port-scan test traffic: 500 packets
for i in range(500):
    packet = (
        Ether()
        / IP(src="192.168.1.100", dst="192.168.1.20")
        / TCP(
            sport=40000 + i,
            dport=1000 + i,
            flags="S"
        )
    )
    packets.append(packet)

# 3. SYN-flood test traffic: 500 packets
for i in range(500):
    packet = (
        Ether()
        / IP(src="192.168.1.150", dst="192.168.1.20")
        / TCP(
            sport=10000 + i,
            dport=80,
            flags="S"
        )
    )
    packets.append(packet)

# Verify packet count
assert len(packets) == 60000

# Save PCAP file
wrpcap(str(OUTPUT_FILE), packets)

print("PCAP created successfully!")
print("Total packets:", len(packets))
print("Normal test packets: 59000")
print("Port-scan test packets: 500")
print("SYN-flood test packets: 500")
print("File:", OUTPUT_FILE)
