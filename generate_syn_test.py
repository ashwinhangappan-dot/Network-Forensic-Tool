
from scapy.all import Ether, IP, TCP, wrpcap
from pathlib import Path

base_dir = Path(__file__).resolve().parent
output_file = base_dir / "test_syn_flood.pcap"

packets = []

# Generate synthetic SYN packets for offline detector testing
for port in range(20000, 20025):
    packets.append(
        Ether()
        / IP(src="192.168.1.150", dst="192.168.1.20")
        / TCP(sport=port, dport=80, flags="S")
    )

wrpcap(str(output_file), packets)

print("Offline SYN test PCAP created:", output_file)
print("Synthetic packets:", len(packets))
