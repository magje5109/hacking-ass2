#!/usr/bin/env python3
# pcap_analyzer.py
#
# Usage:
#   python3 pcap_analyzer.py /path/to/capture.pcap
#
# Outputs:
#   urls.csv, dns.csv, talkers.csv, proto_counts.csv

import sys
import csv
from collections import Counter, defaultdict
from datetime import datetime, UTC

try:
    from scapy.all import rdpcap, TCP, UDP, IP, IPv6, DNS, DNSQR, DNSRR, Raw, ICMP
except Exception as e:
    print("Error: This script requires Scapy. Install with: pip install scapy")
    raise

def http_urls_from_payload(payload_bytes):
    """
    Very lightweight HTTP request parser (GET/POST/HEAD/PUT/DELETE/OPTIONS).
    Returns (method, host, path, ua) or None
    """
    try:
        txt = payload_bytes.decode('iso-8859-1', errors='ignore')
    except Exception:
        return None

    # Split headers
    lines = txt.split("\r\n")
    if not lines or "HTTP/" not in lines[0]:
        # Might be a request line like: GET /path HTTP/1.1
        pass

    # Method + path
    if len(lines) == 0:
        return None
    first = lines[0]
    parts = first.split()
    if len(parts) < 2:
        return None
    method = parts[0]
    # only consider common methods
    if method not in ("GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"):
        return None

    path = parts[1] if len(parts) > 1 else "/"

    host = None
    ua = None
    for line in lines[1:40]:
        if not line:
            break
        low = line.lower()
        if low.startswith("host:"):
            host = line.split(":", 1)[1].strip()
        elif low.startswith("user-agent:"):
            ua = line.split(":", 1)[1].strip()

    if host:
        return (method, host, path, ua)
    return None

def proto_label(pkt):
    """Return a coarse protocol label by ports/layers."""
    try:
        if pkt.haslayer(DNS):
            return "DNS"
        if pkt.haslayer(ICMP):
            return "ICMP"
        if pkt.haslayer(TCP):
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
            ports = {sport, dport}
            if 80 in ports or 8080 in ports:
                return "HTTP"
            if 443 in ports:
                return "HTTPS"
            if 22 in ports:
                return "SSH"
            if 21 in ports:
                return "FTP"
            return "TCP(other)"
        if pkt.haslayer(UDP):
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)
            ports = {sport, dport}
            if 53 in ports:
                return "DNS"
            return "UDP(other)"
        return "OTHER"
    except Exception:
        return "OTHER"

def pkt_ips(pkt):
    """Extract (src, dst) IPv4/IPv6 as strings if present."""
    if IP in pkt:
        return pkt[IP].src, pkt[IP].dst
    if IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst
    return None, None

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 pcap_analyzer.py capture.pcap")
        sys.exit(1)

    pcap_path = sys.argv[1]
    packets = rdpcap(pcap_path)

    # Outputs
    url_rows = []       # time, src, dst, method, url, user_agent
    dns_rows = []       # time, src, dst, qname, qtype, rcode, answers
    talker_bytes = Counter()  # ip -> bytes
    proto_counts = Counter()

    for pkt in packets:
        length = int(len(pkt))
        src, dst = pkt_ips(pkt)
        if src:
            talker_bytes[src] += length

        label = proto_label(pkt)
        proto_counts[label] += 1
        # DNS parse
        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            # Only queries/responses with a question
            qname = None
            qtype = None
            if dns.qd and isinstance(dns.qd[0], DNSQR):
                qname = dns.qd.qname.decode(errors="ignore").rstrip(".")
                qtype = dns.qd.qtype

            rcode = dns.rcode
            answers = []
            if dns.an:
                # Could be multiple answers; iterate a maximum reasonable number
                an = dns.an
                count = 0
                while an and count < dns.ancount:
                    if isinstance(an[0], DNSRR):
                        rrname = an.rrname.decode(errors="ignore").rstrip(".") if isinstance(an.rrname, bytes) else str(an.rrname)
                        rdata = an.rdata
                        if isinstance(rdata, bytes):
                            try:
                                rdata = rdata.decode(errors="ignore")
                            except Exception:
                                rdata = repr(rdata)
                        answers.append(f"{rrname} -> {rdata}")
                        an = an.payload if hasattr(an, "payload") else None
                        count += 1
                    else:
                        break

            ts = getattr(pkt, "time", None)
            tstr = str(datetime.fromtimestamp(int(ts), UTC)) + "Z" if ts else ""
            dns_rows.append([tstr, src or "", dst or "", qname or "", qtype or "", rcode, "; ".join(answers)])

        # HTTP URLs (plaintext only)
        try:
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                sport = int(pkt[TCP].sport)
                dport = int(pkt[TCP].dport)
                if 80 in {sport, dport} or 8080 in {sport, dport}:
                    parsed = http_urls_from_payload(bytes(pkt[Raw]))
                    if parsed:
                        method, host, path, ua = parsed
                        ts = getattr(pkt, "time", None)
                        tstr = str(datetime.fromtimestamp(int(ts), UTC)) + "Z" if ts else ""
                        url = f"http://{host}{path}"
                        url_rows.append([tstr, src or "", dst or "", method, url, ua or ""])
        except Exception:
            # Ignore malformed payloads
            pass

    # Write CSVs
    with open("urls.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["time_utc", "src", "dst", "method", "url", "user_agent"])
        w.writerows(url_rows)

    with open("dns.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["time_utc", "src", "dst", "qname", "qtype", "rcode", "answers"])
        w.writerows(dns_rows)

    with open("talkers.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ip", "bytes"])
        for ip, b in talker_bytes.most_common():
            w.writerow([ip, b])

    with open("proto_counts.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["protocol", "count"])
        for proto, c in proto_counts.most_common():
            w.writerow([proto, c])

    print("✅ Done. Wrote: urls.csv, dns.csv, talkers.csv, proto_counts.csv")
    print("   Hints for your report:")
    print("   - Use Wireshark 'Statistics → Protocol Hierarchy' and 'Conversations'")
    print("   - Annotate two interesting frames (e.g., DNS query/response and an HTTP GET)")

if __name__ == "__main__":
    main()
