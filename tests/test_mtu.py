"""Tests for faultline.detectors.mtu (ICMP frag-needed / PTB, PMTUD black holes)."""

from __future__ import annotations

from faultline.detectors.mtu import MtuDetector
from faultline.model import Category, Severity
from tests.factory import Seq, icmp, run_detector, tcp
from tests.test_tcp import Conv, by_kind, kinds

CLIENT, SERVER, ROUTER = "10.0.0.2", "203.0.113.10", "10.0.0.1"


def _frag_needed(s, t, c: Conv, mtu=1400, router=ROUTER):
    """Router tells the *client* its 1500-byte upload does not fit."""
    return icmp(s, t, router, c.c, 3, 4, mtu=mtu,
                inner=dict(src=c.c, dst=c.srv, proto=6, sport=c.cp, dport=c.sp, ip_id=1, ttl=63))


def upload(s, cport, *, mtu=1400, adapt=True, t0=0.0):
    c = Conv(s, cp=cport)
    t = c.handshake(t0)
    c.cdata(t, 1460, flags="A")  # 1500-byte IP packet
    c._add(_frag_needed(s, t + 0.002, c, mtu))
    for i in range(10):
        c.cdata(t + 0.1 + i * 0.001, 1348 if adapt else 1460, flags="A")
    c.sack_(t + 0.2)
    return c.pkts


def test_frag_needed_senders_adapted():
    s = Seq()
    f = run_detector(MtuDetector(), upload(s, 60000))
    fn = by_kind(f, "mtu.frag_needed")
    assert fn is not None and fn.category == Category.MISCONFIG
    m = fn.metrics
    assert m["router"] == ROUTER and m["mtu"] == 1400
    assert m["flows_adapted"] == 1 and m["flows_not_adapted"] == 0
    assert fn.severity == Severity.LOW  # PMTUD works: informational
    assert m["likely_link"] == "VPN / IPsec"
    assert fn.packets and ROUTER in fn.hosts


def test_frag_needed_senders_did_not_adapt():
    s = Seq()
    pkts = upload(s, 60001, adapt=False) + upload(s, 60002, adapt=False, t0=5)
    fn = by_kind(run_detector(MtuDetector(), pkts), "mtu.frag_needed")
    assert fn is not None and fn.severity == Severity.HIGH
    assert fn.metrics["flows_not_adapted"] == 2


def test_tiny_mtu_is_an_attack_indicator():
    s = Seq()
    fn = by_kind(run_detector(MtuDetector(), upload(s, 60003, mtu=296)), "mtu.frag_needed")
    assert any(i.supports == Category.ATTACK for i in fn.indicators)


def blackholed(s, cport, *, fallback=False, t0=0.0, receiver_alive=True, resends=5):
    """Client GETs; server's 1448-byte answers are never ACKed (no ICMP)."""
    c = Conv(s, cp=cport, sp=443)
    t = c.handshake(t0)
    c.cdata(t, 300)  # small request goes through ...
    c.sack_(t + 0.02)  # ... and is ACKed
    t += 0.03
    first = c.sn
    for i in range(4):
        c.sdata(t + i * 0.0001, 1448)
    rto = 0.2
    for _ in range(resends):
        t += rto
        rto *= 2
        c.sdata(t, 1448, seq=first)
        if receiver_alive:
            c.cack(t + 0.01, ack=first)  # receiver still there, still waiting at `first`
    if fallback:
        t += 0.5
        c.sdata(t, 536, seq=first)  # sender lowers its MSS: small pieces get through
        c.cack(t + 0.02, ack=first + 536)
    return c.pkts


def test_blackhole_with_fallback_is_conclusive():
    s = Seq()
    f = run_detector(MtuDetector(), blackholed(s, 61000, fallback=True))
    bh = by_kind(f, "mtu.blackhole")
    assert bh is not None and bh.category == Category.MISCONFIG
    m = bh.metrics
    assert m["fallback_seen"] and m["max_resends"] == 6
    assert m["negotiated_mss"] == 1460 and m["estimated_path_mtu"] == 576
    assert m["packet_size"] == 1488
    assert "mtu.frag_needed" not in kinds(f)
    assert bh.packets
    assert any(i.weight >= 3 for i in bh.indicators)


def test_blackhole_on_several_connections():
    s = Seq()
    pkts = []
    for i in range(3):
        pkts += blackholed(s, 61100 + i, t0=i * 0.1)
    pkts.sort(key=lambda p: p.ts)
    bh = by_kind(run_detector(MtuDetector(), pkts), "mtu.blackhole")
    assert bh is not None and bh.metrics["flows"] == 3 and bh.severity == Severity.HIGH


def test_single_dead_receiver_is_not_a_blackhole():
    s = Seq()
    pkts = blackholed(s, 61200, receiver_alive=False)
    assert "mtu.blackhole" not in kinds(run_detector(MtuDetector(), pkts))


def test_big_segment_lost_twice_then_acked_is_not_a_blackhole():
    s = Seq()
    c = Conv(s, cp=61300, sp=443)
    t = c.handshake()
    c.cdata(t, 300)
    t += 0.03
    for k in range(20):
        first = c.sn
        c.sdata(t, 1448)
        c.sdata(t + 0.2, 1448, seq=first)
        c.sdata(t + 0.6, 1448, seq=first)
        c.cack(t + 0.62)
        t += 1
    assert "mtu.blackhole" not in kinds(run_detector(MtuDetector(), c.pkts))


def test_icmp_received_means_not_a_blackhole():
    s = Seq()
    pkts = blackholed(s, 61400, fallback=True)
    c = Conv(s, cp=61400, sp=443)
    pkts.insert(8, icmp(s, 0.1, ROUTER, SERVER, 3, 4, mtu=1400,
                        inner=dict(src=SERVER, dst=CLIENT, proto=6, sport=443, dport=61400)))
    f = run_detector(MtuDetector(), pkts)
    assert "mtu.blackhole" not in kinds(f) and "mtu.frag_needed" in kinds(f)
    del c


def test_healthy_bulk_transfer_no_findings():
    s = Seq()
    c = Conv(s, cp=61500)
    t = c.handshake()
    for i in range(500):
        c.sdata(t, 1448)
        if i % 2:
            c.cack(t + 0.001)
        t += 0.001
    assert not run_detector(MtuDetector(), c.pkts)


def test_robust_against_weird_packets():
    s = Seq()
    pkts = blackholed(s, 61600)
    p = icmp(s, 0.5, ROUTER, CLIENT, 3, 4, mtu=None, inner=None)
    pkts.append(p)
    p = icmp(s, 0.5, ROUTER, CLIENT, 3, 4, mtu=0, inner=dict(src=None, dst=None, proto=6))
    pkts.append(p)
    p = icmp(s, -5.0, "fe80::1", "fe80::2", 2, 0, mtu=70000,
             inner=dict(src="fe80::2", dst="2001:db8::1", proto=17, sport=None, dport=None))
    p.icmp.v6 = True
    pkts.append(p)
    p = tcp(s, 1.0, CLIENT, 61600, SERVER, 443, "A", sq=1, plen=1448)
    p.tcp.seq = None
    pkts.append(p)
    p = tcp(s, 1.0, SERVER, 443, CLIENT, 61600, "PA", sq=1, plen=1448)
    p.tcp.hlen = p.tcp.flags = p.tcp.ack = None
    pkts.append(p)
    run_detector(MtuDetector(), pkts)


def test_blackhole_is_size_specific():
    """1233-byte segments get through and are ACKed, 1460-byte ones never do (real VPN case)."""
    s = Seq()
    c = Conv(s, cp=61700, sp=443)
    t = c.handshake()
    c.cdata(t, 265)
    c.sdata(t + 0.04, 1233, flags="PA")  # large, but below the path MTU
    c.cack(t + 0.041)
    c.cdata(t + 0.05, 300)
    t += 0.1
    first = c.sn
    c.sdata(t, 1460)
    c.sdata(t, 1460)
    c.cack(t + 0.001, ack=first)
    rto = 0.21
    for _ in range(5):
        t += rto
        rto *= 2
        c.sdata(t, 1460, seq=first)
    c.rst_from_client(t + 0.5)
    bh = by_kind(run_detector(MtuDetector(), c.pkts), "mtu.blackhole")
    assert bh is not None
    assert bh.metrics["largest_payload_through"] == 1233
    assert bh.metrics["estimated_path_mtu"] == 1273
    assert any("depends on packet size" in i.text for i in bh.indicators)


def test_same_size_acked_elsewhere_in_flow_is_just_loss():
    s = Seq()
    c = Conv(s, cp=61800, sp=443)
    t = c.handshake()
    c.cdata(t, 265)
    c.sdata(t + 0.04, 1460)
    c.cack(t + 0.041)  # a 1460-byte segment got through first time
    first = c.sn
    c.sdata(t + 0.1, 1460)
    for k in range(5):
        c.sdata(t + 0.3 + k * 0.4, 1460, seq=first)
        c.cack(t + 0.31 + k * 0.4, ack=first)
    assert "mtu.blackhole" not in kinds(run_detector(MtuDetector(), c.pkts))
