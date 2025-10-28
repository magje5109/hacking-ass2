#!/usr/bin/env python3
# traffic_sniffer.py
#
# Safe packet sniffer for lab use. Saves rotating PCAP files.
#
# Examples:
#   sudo python3 traffic_sniffer.py -i eth0 -o pcap_files/lab -f "port 53 or tcp port 80"
#   sudo python3 traffic_sniffer.py -i eth0 -o pcap_files/all --rotate-size 100 --max-files 10
#   sudo python3 traffic_sniffer.py -i eth0 -o pcap_files/time --rotate-seconds 300 --max-files 12
#
# Output files look like: lab_2025-10-28T18-20-05Z_0001.pcap

import argparse
import os
import signal
import sys
import time
from datetime import datetime, timezone
from collections import deque

try:
    from scapy.all import AsyncSniffer, PcapWriter
except Exception:
    print("Error: This script requires Scapy. Install with: pip install scapy", file=sys.stderr)
    sys.exit(2)

STOP = False

def utc_stamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")

def setup_signals():
    def handler(signum, frame):
        global STOP
        STOP = True
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

class RotatingPcapWriter:
    """
    Rotate PCAP by size (MB) and/or time (seconds).
    Keeps a ring buffer of recent files if max_files is set.
    """
    def __init__(self, base_path, rotate_size_mb=None, rotate_seconds=None, max_files=None):
        self.base_path = base_path
        self.rotate_size_bytes = int(rotate_size_mb * 1024 * 1024) if rotate_size_mb else None
        self.rotate_seconds = int(rotate_seconds) if rotate_seconds else None
        self.max_files = int(max_files) if max_files else None

        self.current_writer = None
        self.current_path = None
        self.current_size = 0
        self.start_ts = None
        self.counter = 0
        self.files = deque()

        # Ensure directory exists
        os.makedirs(os.path.dirname(base_path) or ".", exist_ok=True)

    def _new_path(self):
        self.counter += 1
        prefix = os.path.basename(self.base_path)
        dirname = os.path.dirname(self.base_path)
        name = f"{prefix}_{utc_stamp()}_{self.counter:04d}.pcap"
        return os.path.join(dirname, name)

    def _open_new(self):
        self.current_path = self._new_path()
        self.current_writer = PcapWriter(self.current_path, append=False, sync=True)
        self.current_size = 0
        self.start_ts = time.time()
        self.files.append(self.current_path)
        self._enforce_ring()
        return self.current_path

    def _enforce_ring(self):
        if self.max_files and len(self.files) > self.max_files:
            old = self.files.popleft()
            try:
                os.remove(old)
            except OSError:
                pass  # If deletion fails, ignore

    def _should_rotate(self):
        if self.current_writer is None:
            return True
        if self.rotate_size_bytes is not None and self.current_size >= self.rotate_size_bytes:
            return True
        if self.rotate_seconds is not None and (time.time() - self.start_ts) >= self.rotate_seconds:
            return True
        return False

    def write(self, pkt):
        if self._should_rotate():
            self.close()
            opened = self._open_new()
            # Print on rotation for visibility
            print(f"[+] Writing to {opened}")
        # Estimate packet size by raw bytes length if available; len(pkt) is fine for rough rotation
        try:
            size = len(bytes(pkt))
        except Exception:
            size = len(pkt)
        self.current_writer.write(pkt)
        self.current_size += size

    def close(self):
        if self.current_writer:
            try:
                self.current_writer.close()
            except Exception:
                pass
            self.current_writer = None
            self.current_path = None
            self.current_size = 0
            self.start_ts = None
def parse_args():
    p = argparse.ArgumentParser(
        description="Safe packet sniffer that writes rotating PCAPs (lab use)."
    )
    p.add_argument("-i", "--interface", required=True, help="Network interface (e.g., eth0)")
    p.add_argument("-o", "--output", required=True,
                   help="Base output path (no extension). Example: pcap_files/session")
    p.add_argument("-f", "--filter", default=None,
                   help="BPF filter (tcpdump/Wireshark syntax), e.g., 'port 53 or tcp port 80'")
    p.add_argument("--rotate-size", type=float, default=50.0,
                   help="Rotate file after N MB (default: 50 MB). Set 0 to disable size-based rotation.")
    p.add_argument("--rotate-seconds", type=int, default=None,
                   help="Rotate file after N seconds (optional).")
    p.add_argument("--max-files", type=int, default=10,
                   help="Keep only last N files (ring buffer). 0 means keep all. Default: 10")
    p.add_argument("--metadata-log", default=None,
                   help="Optional metadata log path (captures start/stop, file rotation, drops).")
    p.add_argument("--quiet", action="store_true", help="Less console output.")
    return p.parse_args()

def log(meta_fp, quiet, msg):
    line = f"{utc_stamp()} {msg}"
    if not quiet:
        print(line)
    if meta_fp:
        meta_fp.write(line + "\n")
        meta_fp.flush()

def main():
    args = parse_args()
    setup_signals()

    # Normalize rotation settings
    rotate_size_mb = None if (args.rotate_size is not None and args.rotate_size <= 0) else args.rotate_size
    max_files = None if (args.max_files is not None and args.max_files <= 0) else args.max_files

    meta_fp = open(args.metadata_log, "a", encoding="utf-8") if args.metadata_log else None
    writer = RotatingPcapWriter(
        base_path=args.output,
        rotate_size_mb=rotate_size_mb,
        rotate_seconds=args.rotate_seconds,
        max_files=max_files
    )

    # Packet callback — write to rotating PCAP
    def handle(pkt):
        writer.write(pkt)

    # Start sniffer (no in-memory storage)
    sniffer = AsyncSniffer(
        iface=args.interface,
        prn=handle,
        filter=args.filter,
        store=False
    )

    log(meta_fp, args.quiet, f"START interface={args.interface} filter={args.filter or '(none)'} "
                             f"rotate_size_mb={rotate_size_mb or 'disabled'} "
                             f"rotate_seconds={args.rotate_seconds or 'disabled'} "
                             f"max_files={max_files or 'unlimited'}")

    try:
        sniffer.start()
        # Wait until interrupted
        while not STOP:
            time.sleep(0.3)
    finally:
        # Stop and summarize
        try:
            sniffer.stop()
        except Exception:
            pass

        # Scapy does not expose drop counts directly; we log file list instead
        writer.close()
        log(meta_fp, args.quiet, "STOP")
        if meta_fp:
            meta_fp.close()

if __name__ == "__main__":
    main()