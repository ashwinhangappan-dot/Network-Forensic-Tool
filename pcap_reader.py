
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Ether
from pathlib import Path

# Get the sample PCAP file path
BASE_DIR = Path(__file__).resolve().parent
PCAP_FILE = BASE_DIR / "sample.pcap"


def read_pcap():
    if not PCAP_FILE.exists():
        print("Error: sample.pcap file not found!")
        return

    try:
        packets = rdpcap(str(PCAP_FILE))

        print("=" * 50)
        print("NETWORK FORENSIC - PACKET ANALYSIS")
        print("=" * 50)
        print(f"Total packets captured: {len(packets)}\n")

        for i, packet in enumerate(packets, start=1):
            print(f"Packet {i}")
            print("-" * 30)

            if Ether in packet:
                print(f"Source MAC: {packet[Ether].src}")
                print(f"Destination MAC: {packet[Ether].dst}")

            if IP in packet:
                ip = packet[IP]
                print(f"Source IP: {ip.src}")
                print(f"Destination IP: {ip.dst}")
                print(f"Protocol: {ip.proto}")
                print(f"Packet Size: {len(packet)} bytes")

            if TCP in packet:
                print("Protocol Type: TCP")
                print(f"Source Port: {packet[TCP].sport}")
                print(f"Destination Port: {packet[TCP].dport}")

            elif UDP in packet:
                print("Protocol Type: UDP")
                print(f"Source Port: {packet[UDP].sport}")
                print(f"Destination Port: {packet[UDP].dport}")

            elif ICMP in packet:
                print("Protocol Type: ICMP")

            print()

        print("Packet analysis completed successfully!")

    except Exception as error:
        print(f"Error reading PCAP file: {error}")


if __name__ == "__main__":
    read_pcap()
