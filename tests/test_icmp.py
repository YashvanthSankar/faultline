"""Tests for icmp.unreachable / icmp.routing_loop / icmp.redirect."""

from __future__ import annotations

from faultline.capture.reader import CaptureInfo
from faultline.context import AnalysisContext
from faultline.detectors.icmp import IcmpDetector
from faultline.detectors.scan import ScanDetector
from faultline.model import Category, Severity
from tests.factory import Seq, icmp, run_detector, tcp, udp

GW, GW_MAC = "10.0.0.1", "02:00:00:00:00:fe"


def score(f, cat):
    return sum(i.weight for i in f.indicators if i.supports is cat)


def winner(f):
    return max((Category.FAULT, Category.MISCONFIG, Category.ATTACK), key=lambda c: score(f, c))


def run_many(dets, pkts):
    ctx = AnalysisContext(CaptureInfo(name="t"))
    for p in pkts:
        ctx.observe(p)
        for d in dets:
            d.on_packet(p, ctx)
    out = []
    for d in dets:
        out += d.finalize(ctx)
    return out


def gateway_traffic(s, t=0.0):
    """Internet traffic arriving through the gateway MAC, so HostTable infers the gateway."""
    pk = [tcp(s, t + i * 0.01, f"93.184.{i}.10", 443, "10.0.0.20", 50000 + i, "A", eth_src=GW_MAC) for i in range(5)]
    pk.append(udp(s, t, GW, 53, "10.0.0.20", 50000, eth_src=GW_MAC))
    return pk


# --------------------------------------------------------------------------- #
# unreachable
# --------------------------------------------------------------------------- #


def test_port_unreachable_service_down():
    s = Seq()
    pk = []
    for i in range(6):
        pk.append(udp(s, i, "10.0.0.2", 40000 + i, "10.0.0.9", 514))
        pk.append(icmp(s, i + 0.001, "10.0.0.9", "10.0.0.2", 3, 3,
                       inner=dict(src="10.0.0.2", dst="10.0.0.9", proto=17, sport=40000 + i, dport=514)))
    fs = run_detector(IcmpDetector(), pk)
    assert [f.kind for f in fs] == ["icmp.unreachable"]
    f = fs[0]
    assert f.metrics["group"] == "port" and f.category is Category.FAULT
    assert "10.0.0.9 UDP port 514" in f.title
    assert f.severity == Severity.LOW  # one client, one port, few messages
    assert len(f.packets) == 6
    assert Category.MISCONFIG in f.variants


def test_admin_prohibited_is_misconfig():
    s = Seq()
    pk = [icmp(s, i, GW, "10.0.0.2", 3, 13, inner=dict(src="10.0.0.2", dst="203.0.113.5", proto=6, sport=5000 + i,
                                                       dport=25)) for i in range(4)]
    f = run_detector(IcmpDetector(), pk)[0]
    assert f.metrics["group"] == "admin" and f.category is Category.MISCONFIG
    assert winner(f) is Category.MISCONFIG


def test_host_unreachable_many_messages_medium():
    s = Seq()
    pk = [icmp(s, i * 0.5, GW, "10.0.0.2", 3, 1, inner=dict(src="10.0.0.2", dst="10.0.0.77", proto=6, sport=5000 + i,
                                                            dport=445)) for i in range(12)]
    f = run_detector(IcmpDetector(), pk)[0]
    assert f.metrics["group"] == "host" and f.severity == Severity.MEDIUM
    assert "10.0.0.77" in f.title


def test_udp_scan_unreachables_are_not_reported():
    s = Seq()
    pk = []
    for i, port in enumerate(range(100, 160)):
        pk.append(udp(s, i * 0.02, "10.0.0.66", 55555, "10.0.0.5", port, plen=0))
        pk.append(icmp(s, i * 0.02 + 0.001, "10.0.0.5", "10.0.0.66", 3, 3,
                       inner=dict(src="10.0.0.66", dst="10.0.0.5", proto=17, sport=55555, dport=port)))
    fs = run_many([ScanDetector(), IcmpDetector()], pk)
    assert [f.kind for f in fs] == ["scan.port"]
    # even without the scan detector, one prober hitting many closed ports is not a "service down"
    assert run_detector(IcmpDetector(), pk) == []


def test_benign_unreachables_ignored():
    s = Seq()
    pk = [
        # two messages only
        icmp(s, 0, "10.0.0.9", "10.0.0.2", 3, 3, inner=dict(src="10.0.0.2", dst="10.0.0.9", proto=17, sport=1, dport=7)),
        icmp(s, 1, "10.0.0.9", "10.0.0.2", 3, 3, inner=dict(src="10.0.0.2", dst="10.0.0.9", proto=17, sport=1, dport=7)),
    ]
    # late DNS / QUIC answers to closed sockets
    for i in range(10):
        pk.append(icmp(s, 2 + i, "10.0.0.2", "8.8.8.8", 3, 3,
                       inner=dict(src="8.8.8.8", dst="10.0.0.2", proto=17, sport=53, dport=40000 + i)))
    # fragmentation needed belongs to the MTU detector
    for i in range(10):
        pk.append(icmp(s, 20 + i, GW, "10.0.0.2", 3, 4, mtu=1400,
                       inner=dict(src="10.0.0.2", dst="93.184.216.34", proto=6, sport=5000, dport=443)))
    assert run_detector(IcmpDetector(), pk) == []


# --------------------------------------------------------------------------- #
# routing loop / traceroute
# --------------------------------------------------------------------------- #


def test_routing_loop_time_exceeded_from_two_routers():
    s = Seq()
    pk = []
    for i in range(10):
        r = "10.1.1.1" if i % 2 else "10.1.1.2"
        pk.append(tcp(s, i, "10.0.0.2", 40000 + i, "203.0.113.50", 443, "S"))
        pk.append(icmp(s, i + 0.05, r, "10.0.0.2", 11, 0,
                       inner=dict(src="10.0.0.2", dst="203.0.113.50", proto=6, sport=40000 + i, dport=443, ttl=0)))
    fs = run_detector(IcmpDetector(), pk)
    assert [f.kind for f in fs] == ["icmp.routing_loop"]
    f = fs[0]
    assert f.category is Category.FAULT and winner(f) is Category.FAULT
    assert set(f.metrics["routers"]) == {"10.1.1.1", "10.1.1.2"}
    assert f.metrics["destination_prefix"] == "203.0.113.0/24"


def test_routing_loop_same_packet_ttl_decreasing():
    s = Seq()
    pk = []
    for n in range(2):
        for lap in range(8):
            mac = "02:00:00:00:aa:01" if lap % 2 == 0 else "02:00:00:00:aa:02"
            pk.append(udp(s, n + lap * 0.001, "10.0.0.2", 40000 + n, "203.0.113.9", 53, ttl=60 - 2 * lap,
                          ip_id=1000 + n, eth_src=mac))
    fs = run_detector(IcmpDetector(), pk)
    assert [f.kind for f in fs] == ["icmp.routing_loop"]
    f = fs[0]
    assert f.metrics["looping_packets"] == 2 and f.metrics["max_copies"] == 8
    assert any(i.weight >= 3 for i in f.indicators)


def test_two_copies_router_capture_not_loop():
    s = Seq()
    pk = []
    for n in range(50):  # capture on both interfaces of a router: each packet seen twice, TTL -1
        pk.append(udp(s, n * 0.01, "10.0.0.2", 40000, "203.0.113.9", 53, ttl=64, ip_id=n))
        pk.append(udp(s, n * 0.01 + 0.0001, "10.0.0.2", 40000, "203.0.113.9", 53, ttl=63, ip_id=n))
    assert run_detector(IcmpDetector(), pk) == []


def test_udp_traceroute_not_loop_or_unreachable():
    s = Seq()
    pk = []
    port = 33434
    for hop in range(1, 11):
        for probe in range(3):
            pk.append(udp(s, hop + probe * 0.01, "10.0.0.2", 40000, "198.51.100.7", port, ttl=hop))
            inner = dict(src="10.0.0.2", dst="198.51.100.7", proto=17, sport=40000, dport=port)
            if hop < 10:
                pk.append(icmp(s, hop + probe * 0.01 + 0.005, f"172.16.{hop}.1", "10.0.0.2", 11, 0, inner=inner))
            else:
                pk.append(icmp(s, hop + probe * 0.01 + 0.005, "198.51.100.7", "10.0.0.2", 3, 3, inner=inner))
            port += 1
    assert run_detector(IcmpDetector(), pk) == []


def test_icmp_traceroute_windows_not_loop():
    s = Seq()
    pk = []
    for hop in range(1, 9):
        for probe in range(3):
            pk.append(icmp(s, hop + probe * 0.01, "10.0.0.2", "198.51.100.7", 8, 0, ttl=hop, echo_id=1,
                           echo_seq=hop * 3 + probe))
            pk.append(icmp(s, hop + probe * 0.01 + 0.005, f"172.16.{hop}.1" if hop % 2 else "172.16.0.1", "10.0.0.2",
                           11, 0, inner=dict(src="10.0.0.2", dst="198.51.100.7", proto=1)))
    assert run_detector(IcmpDetector(), pk) == []


# --------------------------------------------------------------------------- #
# redirect
# --------------------------------------------------------------------------- #


def test_redirect_from_gateway_is_misconfig():
    s = Seq()
    pk = gateway_traffic(s)
    # a second router on the LAN that also forwards internet traffic
    pk += [tcp(s, 0.5 + i * 0.01, f"198.51.{i}.20", 443, "10.0.0.21", 50000 + i, "A", eth_src="02:00:00:00:00:02")
           for i in range(4)]
    pk.append(udp(s, 0.6, "10.0.0.2", 53, "10.0.0.21", 50000, eth_src="02:00:00:00:00:02"))
    for i in range(4):
        pk.append(icmp(s, 1 + i, GW, "10.0.0.20", 5, 1, gateway="10.0.0.2", eth_src=GW_MAC,
                       inner=dict(src="10.0.0.20", dst="172.20.0.5", proto=6, sport=5000, dport=445)))
    fs = [f for f in run_detector(IcmpDetector(), pk) if f.kind == "icmp.redirect"]
    assert len(fs) == 1
    f = fs[0]
    assert f.category is Category.MISCONFIG and winner(f) is Category.MISCONFIG
    assert f.severity <= Severity.MEDIUM


def test_redirect_from_non_gateway_pointing_to_itself_is_attack():
    s = Seq()
    pk = gateway_traffic(s)
    pk.append(icmp(s, 1, "10.0.0.66", "10.0.0.20", 5, 1, gateway="10.0.0.66",
                   inner=dict(src="10.0.0.20", dst="8.8.8.8", proto=17, sport=5000, dport=53)))
    fs = [f for f in run_detector(IcmpDetector(), pk) if f.kind == "icmp.redirect"]
    assert len(fs) == 1
    f = fs[0]
    assert f.category is Category.ATTACK and winner(f) is Category.ATTACK
    assert f.mitre.startswith("T1557") and f.severity == Severity.HIGH


def test_redirect_forging_gateway_ip_from_other_mac_is_attack():
    s = Seq()
    pk = gateway_traffic(s)
    for i in range(3):
        pk.append(icmp(s, 1 + i, GW, f"10.0.0.{30 + i}", 5, 1, gateway="10.0.0.66", eth_src="02:00:00:00:66:66",
                       inner=dict(src=f"10.0.0.{30 + i}", dst="8.8.8.8", proto=17, sport=5000, dport=53)))
    f = [f for f in run_detector(IcmpDetector(), pk) if f.kind == "icmp.redirect"][0]
    assert winner(f) is Category.ATTACK


def test_none_fields_robust():
    s = Seq()
    p1 = icmp(s, 0, "10.0.0.9", "10.0.0.2", 3, 1)  # no inner
    p2 = icmp(s, 0, "10.0.0.9", "10.0.0.2", 11, 0)
    p3 = icmp(s, 0, "10.0.0.9", "10.0.0.2", 5, 1)  # redirect without gateway
    p4 = udp(s, 0, "10.0.0.2", 1, "10.0.0.3", 2, ttl=None)
    p5 = tcp(s, 0, "10.0.0.2", 1, "10.0.0.3", 2, "S")
    p5.ip_id = None
    run_detector(IcmpDetector(), [p1, p2, p3, p4, p5] * 3)
