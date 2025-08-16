#!/usr/bin/env python3
"""
nids.py - Lightweight Network IDS for PCAP or live sniffing.
Detects:
 - ICMP echo request/reply and ICMP flood-ish behavior
 - TCP SYNs, half-open connections
 - Port scan patterns (many destination ports)
 - NULL/FIN-scan like packets
Usage:
  python nids.py --pcap malicious.pcap
  sudo python nids.py --iface eth0
"""
import argparse
import logging
import time
from collections import defaultdict, deque

from scapy.all import rdpcap, sniff, IP, TCP, ICMP

# ---- Configuration (tweak as needed) ----
DEFAULT_WINDOW = 60.0            # seconds for counting unique ports / rates
ICMP_FLOOD_THRESHOLD = 40        # > this many ICMP echos in WINDOW -> possible flood
SYN_SCAN_PORT_THRESHOLD = 20     # > this many unique dst ports in WINDOW -> port scan
SYN_RATE_THRESHOLD = 100         # SYNs in WINDOW from a single src -> high-rate
SYN_HALF_OPEN_TIMEOUT = 5.0      # seconds to wait for SYN-ACK/ACK before declaring half-open

# ---- Logging / alerting ----
logger = logging.getLogger("nids")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("[%(asctime)s] %(message)s", "%H:%M:%S"))
logger.addHandler(handler)

# Also store alerts in memory (useful for tests / further processing)
class NIDS:
    def __init__(self,
                 window=DEFAULT_WINDOW,
                 icmp_threshold=ICMP_FLOOD_THRESHOLD,
                 syn_port_threshold=SYN_SCAN_PORT_THRESHOLD,
                 syn_rate_threshold=SYN_RATE_THRESHOLD,
                 syn_half_open_timeout=SYN_HALF_OPEN_TIMEOUT):
        self.window = window
        self.icmp_threshold = icmp_threshold
        self.syn_port_threshold = syn_port_threshold
        self.syn_rate_threshold = syn_rate_threshold
        self.syn_half_open_timeout = syn_half_open_timeout

        # Data structures
        self.icmp_times = defaultdict(deque)     # src -> deque(timestamps)
        self.syn_times = defaultdict(deque)      # src -> deque(timestamps)
        self.syn_ports = defaultdict(dict)       # src -> {dst_port: timestamp}
        self.pending_syns = dict()               # (src,dst,srcport,dstport) -> timestamp

        self.alerts = []     # list of alert strings (in order)

    def _alert(self, msg):
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        text = f"[ALERT] {ts} - {msg}"
        logger.info(text)
        self.alerts.append(text)

    def _purge_old(self, now):
        # Purge old ICMP timestamps
        cutoff = now - self.window
        for src, dq in list(self.icmp_times.items()):
            while dq and dq[0] < cutoff:
                dq.popleft()
            if not dq:
                del self.icmp_times[src]

        # Purge old SYN timestamps
        for src, dq in list(self.syn_times.items()):
            while dq and dq[0] < cutoff:
                dq.popleft()
            if not dq:
                del self.syn_times[src]

        # Purge old entries in syn_ports
        for src, pmap in list(self.syn_ports.items()):
            for port, ts in list(pmap.items()):
                if ts < cutoff:
                    del pmap[port]
            if not pmap:
                del self.syn_ports[src]

        # Check pending SYNs for half-open timeout
        for key, ts in list(self.pending_syns.items()):
            if now - ts > self.syn_half_open_timeout:
                src, dst, sport, dport = key
                self._alert(f"Half-open connection suspected (SYN not completed) from {src}:{sport} -> {dst}:{dport} (age {now-ts:.1f}s)")
                del self.pending_syns[key]

    def process_packet(self, pkt):
        # Use scapy timestamps where available
        now = getattr(pkt, "time", time.time())
        if not pkt.haslayer(IP):
            return
        ip = pkt[IP]
        src = ip.src
        dst = ip.dst

        # Purge old entries first (keeps counters accurate)
        self._purge_old(now)

        # ICMP detection
        if pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            # echo request = type 8, echo reply = type 0
            if icmp.type in (8, 0):
                self.icmp_times[src].append(now)
                typ = "Echo Request" if icmp.type == 8 else "Echo Reply"
                self._alert(f"ICMP {typ} observed {src} -> {dst}")
                if len(self.icmp_times[src]) > self.icmp_threshold:
                    self._alert(f"ICMP flood suspected from {src} (count={len(self.icmp_times[src])} in {self.window}s)")

        # TCP detection
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            flags = int(tcp.flags)

            # SYN (initial): SYN set, ACK not set (SYN-only)
            if (flags & 0x02) and not (flags & 0x10):
                # record syn
                self.syn_times[src].append(now)
                self.syn_ports[src][tcp.dport] = now
                key = (src, dst, tcp.sport, tcp.dport)
                self.pending_syns[key] = now
                self._alert(f"TCP SYN detected {src}:{tcp.sport} -> {dst}:{tcp.dport}")

                # port-scan heuristic: many unique destination ports within window
                unique_ports = len(self.syn_ports[src])
                if unique_ports > self.syn_port_threshold:
                    self._alert(f"Port-scan suspected from {src} to {dst} (unique dst ports={unique_ports} in {self.window}s)")

                # high-rate SYN heuristic
                syn_count = len(self.syn_times[src])
                if syn_count > self.syn_rate_threshold:
                    self._alert(f"High-rate SYNs suspected from {src} (SYNs={syn_count} in {self.window}s)")

            # SYN-ACK: flags have both SYN (0x02) and ACK (0x10) -> handshake progressing
            if (flags & 0x12) == 0x12:
                # incoming SYN-ACK likely corresponds to a pending SYN from reverse side
                pending_key = (dst, src, tcp.dport, tcp.sport)
                if pending_key in self.pending_syns:
                    del self.pending_syns[pending_key]
                    # This is normal reply to a SYN; no alert (but we could track established connections)

            # ACK-only (not SYN): may complete handshake
            if (flags & 0x10) and not (flags & 0x02):
                pending_key = (dst, src, tcp.dport, tcp.sport)
                if pending_key in self.pending_syns:
                    del self.pending_syns[pending_key]
                    self._alert(f"Connection established (SYN completed) {dst}:{tcp.dport} -> {src}:{tcp.sport}")

            # NULL scan: no flags set
            if flags == 0:
                self._alert(f"NULL-scan-like TCP packet from {src} -> {dst}:{tcp.dport}")

            # FIN-scan: FIN set, SYN not set
            if (flags & 0x01) and not (flags & 0x02):
                self._alert(f"FIN-scan-like TCP packet from {src} -> {dst}:{tcp.dport}")

    def run_on_pcap(self, path, stop_after=None):
        logger.info(f"Reading PCAP: {path}")
        packets = rdpcap(path)
        count = 0
        for pkt in packets:
            self.process_packet(pkt)
            count += 1
            if stop_after and count >= stop_after:
                break
        logger.info(f"Finished processing {count} packets; alerts={len(self.alerts)}")

    def run_live(self, iface=None, filter_expr=None, count=0):
        logger.info(f"Starting live sniff on iface={iface} filter={filter_expr}")
        sniff(iface=iface, filter=filter_expr, prn=self.process_packet, store=False, count=count)

# ---- CLI ----
def main():
    parser = argparse.ArgumentParser(description="Lightweight NIDS (PCAP or live)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pcap", help="PCAP file to analyze")
    group.add_argument("--iface", help="Interface for live capture (requires root)")
    parser.add_argument("--window", type=float, default=DEFAULT_WINDOW)
    args = parser.parse_args()

    n = NIDS(window=args.window)
    if args.pcap:
        n.run_on_pcap(args.pcap)
    else:
        n.run_live(args.iface)

if __name__ == "__main__":
    main()
