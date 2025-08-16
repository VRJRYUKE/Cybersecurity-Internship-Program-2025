#!/usr/bin/env python3
"""
create_pcaps.py - create two PCAPs for demo:
 - normal.pcap: benign flows (small TCP handshake, small ICMP)
 - malicious.pcap: ICMP flood-ish + SYN scan + NULL & FIN scan packets
"""
import time
from scapy.all import IP, TCP, ICMP, Ether, wrpcap

def make_normal():
    packets = []
    ts = time.time()
    # One small TCP 3-way handshake (client->server)
    p1 = IP(src="10.0.0.2", dst="10.0.0.10")/TCP(sport=12345, dport=80, flags="S")
    p2 = IP(src="10.0.0.10", dst="10.0.0.2")/TCP(sport=80, dport=12345, flags="SA")
    p3 = IP(src="10.0.0.2", dst="10.0.0.10")/TCP(sport=12345, dport=80, flags="A")/"GET / HTTP/1.1"
    for i,p in enumerate([p1,p2,p3]):
        p.time = ts + i*0.01
        packets.append(p)

    # A couple of ICMP pings
    p4 = IP(src="10.0.0.3", dst="10.0.0.10")/ICMP(type=8)
    p4.time = ts + 0.1
    p5 = IP(src="10.0.0.10", dst="10.0.0.3")/ICMP(type=0)
    p5.time = ts + 0.11
    packets.extend([p4,p5])

    wrpcap("normal.pcap", packets)
    print("Wrote normal.pcap")

def make_malicious():
    packets = []
    ts = time.time()

    attacker = "192.168.1.250"
    victim = "10.0.0.10"

    # ICMP flood-ish: many echo requests
    for i in range(60):
        p = IP(src=attacker, dst=victim)/ICMP(type=8)
        p.time = ts + 0.001*i
        packets.append(p)

    # SYN scan: SYNs to many destination ports
    for i,port in enumerate(range(20, 70)):  # lots of ports
        p = IP(src=attacker, dst=victim)/TCP(sport=40000+i, dport=port, flags="S")
        p.time = ts + 0.1 + 0.001*i
        packets.append(p)

    # NULL scan (no flags)
    p_null = IP(src=attacker, dst=victim)/TCP(sport=5000, dport=1234, flags=0)
    p_null.time = ts + 0.2
    packets.append(p_null)

    # FIN scan (FIN only)
    p_fin = IP(src=attacker, dst=victim)/TCP(sport=5001, dport=4321, flags="F")
    p_fin.time = ts + 0.21
    packets.append(p_fin)

    wrpcap("malicious.pcap", packets)
    print("Wrote malicious.pcap")

if __name__ == "__main__":
    make_normal()
    make_malicious()
