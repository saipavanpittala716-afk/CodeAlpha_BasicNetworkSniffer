import csv
import os
from datetime import datetime

CSV_FILE = "packets.csv"

def create_csv():
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, "w", newline="") as file:
            writer = csv.writer(file)

            writer.writerow([
                "Timestamp",
                "Packet Number",
                "Source IP",
                "Destination IP",
                "Protocol",
                "Source Port",
                "Destination Port",
                "Packet Length"
            ])

def save_packet(packet_number, src_ip, dst_ip, protocol,
                src_port, dst_port, length):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(CSV_FILE, "a", newline="") as file:
        writer = csv.writer(file)

        writer.writerow([
            timestamp,
            packet_number,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            length
        ])