from scapy.all import sniff
from colorama import Fore, init

from packet_logger import create_csv, save_packet
from packet_analyzer import analyze_packet, print_statistics

init(autoreset=True)

create_csv()

packet_number = 0

print(Fore.GREEN + "=" * 70)
print(Fore.GREEN + "         CODEALPHA BASIC NETWORK SNIFFER")
print(Fore.GREEN + "=" * 70)

print(Fore.CYAN + "\nChoose Packet Filter")
print("1. ALL Packets")
print("2. TCP Packets")
print("3. UDP Packets")
print("4. ICMP Packets")
print("5. DNS Packets")
print("6. HTTPS Packets")

choice = input("\nEnter your choice (1-6): ")

filter_map = {
    "1": "",
    "2": "tcp",
    "3": "udp",
    "4": "icmp",
    "5": "udp port 53",
    "6": "tcp port 443"
}

capture_filter = filter_map.get(choice, "")

print(Fore.YELLOW + "\nCapturing Packets...")
print(Fore.YELLOW + "Press CTRL + C to stop.\n")

def process_packet(packet):
    global packet_number

    packet_number += 1

    src_ip, dst_ip, protocol, src_port, dst_port, length = analyze_packet(packet)

    print(Fore.CYAN + "-" * 70)
    print(Fore.MAGENTA + f"Packet Number : {packet_number}")
    print(Fore.WHITE + f"Source IP      : {src_ip}")
    print(Fore.WHITE + f"Destination IP : {dst_ip}")
    print(Fore.WHITE + f"Protocol       : {protocol}")
    print(Fore.WHITE + f"Source Port    : {src_port}")
    print(Fore.WHITE + f"Destination Port : {dst_port}")
    print(Fore.WHITE + f"Packet Length  : {length} Bytes")

    save_packet(packet_number, src_ip, dst_ip, protocol,
                src_port, dst_port, length)

try:
    sniff(
        prn=process_packet,
        store=False,
        filter=capture_filter
    )

except KeyboardInterrupt:

    print(Fore.RED + "\nPacket Sniffing Stopped Successfully.")
    print(Fore.RED + f"Total Packets Captured : {packet_number}")

    print_statistics(packet_number)