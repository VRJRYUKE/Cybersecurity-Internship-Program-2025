import time
from scapy.all import IP, TCP, ICMP
from nids import NIDS

def test_icmp_detection_and_flood():
    n = NIDS(window=10, icmp_threshold=3)  # low threshold for test
    attacker = "1.1.1.1"
    victim = "2.2.2.2"
    ts = time.time()
    # send 4 echo requests quickly
    for i in range(4):
        pkt = IP(src=attacker, dst=victim)/ICMP(type=8)
        pkt.time = ts + i*0.001
        n.process_packet(pkt)
    # Expect at least one flood alert
    assert any("ICMP flood suspected" in a for a in n.alerts)

def test_syn_scan_detection_and_half_open():
    n = NIDS(window=10, syn_port_threshold=3, syn_half_open_timeout=0.01)  # low thresholds/timeouts for test
    attacker = "3.3.3.3"
    victim = "4.4.4.4"
    ts = time.time()
    # SYNs to many ports
    for p in [10,11,12,13]:
        pkt = IP(src=attacker, dst=victim)/TCP(sport=2000+p, dport=p, flags="S")
        pkt.time = ts + 0.001*p
        n.process_packet(pkt)
    # Port-scan alert check
    assert any("Port-scan suspected" in a for a in n.alerts)
    # Wait to force half-open timeout purge
    time.sleep(0.02)
    n._purge_old(time.time())
    # Expect half-open alert
    assert any("Half-open connection suspected" in a for a in n.alerts)
