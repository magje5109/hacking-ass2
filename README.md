# ARP and DNS Spoofing Lab

This repository contains scripts and documentation for a controlled network security experiment conducted in an isolated environment. The goal was to demonstrate ARP spoofing, selective DNS spoofing, and traffic interception using Scapy and Python.

## Overview

The experiment simulates a local network with a target system, a gateway, and an attacker performing Man-in-the-Middle techniques. All traffic was confined to a private network, and IP forwarding was enabled only during active spoofing.

## Scripts

- `arp_spoofing.py`: Performs ARP cache poisoning to establish a Man-in-the-Middle position.
- `traffic_sniffer.py`: Captures network traffic and saves it to a PCAP file.
- `pcap_analyzer.py`: Parses PCAP files and extracts DNS queries, visited URLs, protocol usage, and top talkers.
- `dns_spoofing.py`: Intercepts DNS queries and selectively spoofs responses based on a configured domain list.
- `log_webserver.py`: Simple web server that servers a simple HTML page and logs requests to a specified log file.

## Directory Structure

- `pcap_files/`: Contains labeled PCAP captures from the experiments.
- `evidence/`: Includes screenshots, logs, and other supporting materials.
- `requirements.txt`: Lists Python dependencies.
- `spoofed_domains.txt`: Configuration file 
- `README.md`: This file.

## Usage

Each script includes command-line help. For example:

```bash
python3 arp_spoofing.py <victim_ip> <gateway_ip> <interface> [-v]
python3 traffic_sniffer.py -i <interface> -o <base_filename>
python3 pcap_analyzer.py <pcap_file>
python3 log_webserver.py --port <port>
python3 dns_spoofing.py --config <domain_spoofing_whitelist_file> --spoof-ip <attacker_ip>
```