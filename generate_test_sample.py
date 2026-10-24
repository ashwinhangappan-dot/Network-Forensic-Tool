
from scapy.all import Ether, IP, TCP, wrpcap
from pathlib import Path

# Create a separate test file; preserve the original sample
base_dir = Path(__file__).resolve().parent
output_file = base_dir / "test_port_scan.pcap"

packets = []

# Controlled synthetic traffic for testing the port-scan rule
for port in [21, 22, 23, 25, 53, 80]:
    packets.append(
        Ether()
        / IP(src="192.168.1.100", dst="192.168.1.20")
        / TCP(sport=40000 + port, dport=port, flags="S")
    )

wrpcap(str(output_file), packets)

print("Test PCAP created:", output_file)
print("Synthetic packets:", len(packets))
