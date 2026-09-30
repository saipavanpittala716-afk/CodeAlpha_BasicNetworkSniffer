from scapy.all import IP, TCP, UDP, ICMP

protocol_count = {
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "HTTP": 0,
    "HTTPS": 0,
    "DNS": 0,
    "mDNS": 0,
    "SSDP": 0,
    "OTHER": 0,
    "NON-IP": 0
}

def analyze_packet(packet):

    src_ip = "-"
    dst_ip = "-"
    protocol = "OTHER"
    src_port = "-"
    dst_port = "-"
    length = len(packet)

    if packet.haslayer(IP):

        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst

        if packet.haslayer(TCP):

            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            if src_port == 443 or dst_port == 443:
                protocol = "HTTPS"
                protocol_count["HTTPS"] += 1

            elif src_port == 80 or dst_port == 80:
                protocol = "HTTP"
                protocol_count["HTTP"] += 1

            else:
                protocol = "TCP"
                protocol_count["TCP"] += 1

        elif packet.haslayer(UDP):

            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

            if src_port == 53 or dst_port == 53:
                protocol = "DNS"
                protocol_count["DNS"] += 1

            elif src_port == 5353 or dst_port == 5353:
                protocol = "mDNS"
                protocol_count["mDNS"] += 1

            elif src_port == 1900 or dst_port == 1900:
                protocol = "SSDP"
                protocol_count["SSDP"] += 1

            else:
                protocol = "UDP"
                protocol_count["UDP"] += 1

        elif packet.haslayer(ICMP):

            protocol = "ICMP"
            protocol_count["ICMP"] += 1

        else:
            protocol_count["OTHER"] += 1

    else:
        protocol = "NON-IP"
        protocol_count["NON-IP"] += 1

    return src_ip, dst_ip, protocol, src_port, dst_port, length

def print_statistics(total_packets):

    print("\n")
    print("=" * 45)
    print("        LIVE PACKET STATISTICS")
    print("=" * 45)
    print(f"Total Packets : {total_packets}")

    for protocol, count in protocol_count.items():
        print(f"{protocol:<10}: {count}")

    print("=" * 45)