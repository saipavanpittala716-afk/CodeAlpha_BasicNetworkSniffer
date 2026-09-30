# CodeAlpha Basic Network Sniffer

## Project Overview

The Basic Network Sniffer is a Python-based cybersecurity tool developed as part of the CodeAlpha Cyber Security Internship. It captures live network packets, analyzes important packet information, displays the results in the terminal, and stores packet details in a CSV file for further analysis.

## Features

* Captures live network traffic using Scapy.
* Displays Source IP and Destination IP addresses.
* Detects TCP, UDP, ICMP, HTTPS, DNS, mDNS, SSDP, and NON-IP packets.
* Displays source and destination port numbers.
* Displays packet length in bytes.
* Saves packet details with timestamps into a CSV file.
* Provides protocol statistics after capture.
* Supports packet filtering (TCP, UDP, ICMP, DNS, HTTPS, or ALL).

## Technologies Used

* Python 3.14.5
* Scapy
* Pandas
* Colorama
* Npcap (Windows)

## Project Structure

CodeAlpha_BasicNetworkSniffer/
│── sniffer.py
│── packet_analyzer.py
│── packet_logger.py
│── packets.csv
│── requirements.txt
│── README.md
│── screenshots/

## Installation

1. Install Python 3.14.5.
2. Install Npcap for Windows.
3. Install required packages.

pip install scapy pandas colorama

4. Run the project.

python sniffer.py

## Output

The program captures packets and displays:

* Source IP
* Destination IP
* Protocol
* Source Port
* Destination Port
* Packet Length

It also stores packet information in `packets.csv`.

## Learning Outcomes

* Network Packet Sniffing
* TCP/IP Packet Analysis
* Cybersecurity Monitoring
* Protocol Identification
* Python-based Network Programming

## Author

Pittala SaiPavan

CodeAlpha Cyber Security Internship Project
