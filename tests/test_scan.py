"""Tests for scan.port / scan.host_sweep and the scanner_sources helper."""

from __future__ import annotations

import random
import time

from faultline.capture.reader import CaptureInfo
from faultline.context import AnalysisContext
from faultline.detectors.scan import ScanDetector, scanner_sources
from faultline.model import Category, Severity
from tests.factory import Seq, dns_query, dns_response, icmp, run_detector, tcp, udp

SCANNER, TARGET = "10.0.0.66", "10.0.0.5"


def kinds(findings):
    return [f.kind for f in findings]


def score(f, cat):
    return sum(i.weight for i in f.indicators if i.supports is cat)


def handshake(s, t, c, cp, srv, sp, data=True):
    pk = [tcp(s, t, c, cp, srv, sp, "S", sq=1), tcp(s, t + 0.001, srv, sp, c, cp, "SA", sq=9, ack=2),
          tcp(s, t + 0.002, c, cp, srv, sp, "A", sq=2, ack=10)]
    if data:
        pk += [tcp(s, t + 0.003, c, cp, srv, sp, "PA", sq=2, ack=10, plen=300),
               tcp(s, t + 0.004, srv, sp, c, cp, "PA", sq=10, ack=302, plen=1200)]
    return pk


# --------------------------------------------------------------------------- #
# positives
# --------------------------------------------------------------------------- #


def test_syn_scan_half_open():
    s = Seq()
    pk = []
    open_ports = {22, 80, 99}
    for i, port in enumerate(range(1, 101)):
        t = i * 0.01
        pk.append(tcp(s, t, SCANNER, 40000, TARGET, port, "S", sq=1))
        if port in open_ports:
            pk.append(tcp(s, t + 0.001, TARGET, port, SCANNER, 40000, "SA", sq=7, ack=2))
            pk.append(tcp(s, t + 0.002, SCANNER, 40000, TARGET, port, "R", sq=2))
        else:
            pk.append(tcp(s, t + 0.001, TARGET, port, SCANNER, 40000, "RA", ack=2))
    ctx = AnalysisContext(CaptureInfo(name="t"))
    fs = run_detector(ScanDetector(), pk, ctx)
    assert kinds(fs) == ["scan.port"]
    f = fs[0]
    assert f.category is Category.ATTACK and f.severity >= Severity.HIGH
    assert f.metrics["technique"] == "SYN (half-open) scan"
    assert f.metrics["ports_probed"] == 100
    assert set(f.metrics["open_ports"]) == {f"{TARGET}:{p}" for p in open_ports}
    assert f.mitre.startswith("T1046")
    assert f.packets and f.packet_total >= 100
    assert score(f, Category.ATTACK) > score(f, Category.FAULT)
    assert SCANNER in scanner_sources(ctx)
    assert Category.ATTACK in f.variants


def test_connect_scan():
    s = Seq()
    pk = []
    for i, port in enumerate(range(1000, 1040)):
        t = i * 0.05
        pk.append(tcp(s, t, SCANNER, 41000 + i, TARGET, port, "S"))
        if port % 4 == 0:
            pk += [tcp(s, t + 0.001, TARGET, port, SCANNER, 41000 + i, "SA"),
                   tcp(s, t + 0.002, SCANNER, 41000 + i, TARGET, port, "A"),
                   tcp(s, t + 0.003, SCANNER, 41000 + i, TARGET, port, "RA")]
        else:
            pk.append(tcp(s, t + 0.001, TARGET, port, SCANNER, 41000 + i, "RA"))
    fs = run_detector(ScanDetector(), pk)
    assert kinds(fs) == ["scan.port"]
    assert fs[0].metrics["technique"] == "TCP connect scan"
    assert fs[0].metrics["connect_close"] >= 9  # first port is stored lazily (before tracking)


def test_fin_null_xmas_small_count():
    for flags, name in (("F", "FIN"), ("", "NULL"), ("FPU", "Xmas")):
        s = Seq()
        pk = [tcp(s, i * 0.1, SCANNER, 50000, TARGET, p, flags) for i, p in enumerate((21, 22, 23, 80, 443, 3389))]
        ctx = AnalysisContext(CaptureInfo(name="t"))
        fs = run_detector(ScanDetector(), pk, ctx)
        assert kinds(fs) == ["scan.port"], name
        assert fs[0].metrics["technique"] == f"{name} scan"
        assert any(i.weight >= 3 and i.supports is Category.ATTACK for i in fs[0].indicators)
        assert SCANNER in scanner_sources(ctx)


def test_udp_scan_with_port_unreachables():
    s = Seq()
    pk = []
    for i, port in enumerate(range(100, 160)):
        t = i * 0.02
        pk.append(udp(s, t, SCANNER, 55555, TARGET, port, plen=0))
        pk.append(icmp(s, t + 0.001, TARGET, SCANNER, 3, 3,
                       inner=dict(src=SCANNER, dst=TARGET, proto=17, sport=55555, dport=port)))
    fs = run_detector(ScanDetector(), pk)
    assert kinds(fs) == ["scan.port"]
    assert fs[0].metrics["technique"] == "UDP scan"
    assert fs[0].metrics["udp_closed"] >= 59


def test_ping_sweep():
    s = Seq()
    pk = []
    for i in range(1, 61):
        dst = f"10.0.1.{i}"
        pk.append(icmp(s, i * 0.05, SCANNER, dst, 8, 0, echo_id=1, echo_seq=i))
        if i % 10 == 0:
            pk.append(icmp(s, i * 0.05 + 0.001, dst, SCANNER, 0, 0, echo_id=1, echo_seq=i))
    ctx = AnalysisContext(CaptureInfo(name="t"))
    fs = run_detector(ScanDetector(), pk, ctx)
    assert kinds(fs) == ["scan.host_sweep"]
    f = fs[0]
    assert f.metrics["hosts_contacted"] == 60 and f.metrics["answered"] == 6
    assert f.metrics["sequential_ratio"] > 0.9
    assert "T1018" in f.mitre
    assert SCANNER in scanner_sources(ctx)


def test_tcp_port_sweep_smb():
    s = Seq()
    pk = [tcp(s, i * 0.02, SCANNER, 40000 + i, f"10.0.2.{i}", 445, "S") for i in range(1, 41)]
    fs = run_detector(ScanDetector(), pk)
    assert kinds(fs) == ["scan.host_sweep"]
    assert "T1046" in fs[0].mitre


# --------------------------------------------------------------------------- #
# benign look-alikes
# --------------------------------------------------------------------------- #


def test_browser_parallel_connections_no_scan():
    s = Seq()
    pk = []
    for i in range(30):
        pk += handshake(s, i * 0.01, "10.0.0.2", 50000 + i, "93.184.216.34", 443)
    assert run_detector(ScanDetector(), pk) == []


def test_passive_ftp_no_scan():
    s = Seq()
    pk = handshake(s, 0, "10.0.0.2", 50000, "10.0.0.9", 21)
    for i in range(40):
        pk += handshake(s, 1 + i * 0.2, "10.0.0.2", 50100 + i, "10.0.0.9", 40000 + i * 3)
    assert run_detector(ScanDetector(), pk) == []


def test_retrying_failed_service_no_scan():
    s = Seq()
    pk = []
    for i in range(100):
        pk.append(tcp(s, i * 0.5, "10.0.0.2", 50000 + i, "10.0.0.9", 8080, "S"))
        pk.append(tcp(s, i * 0.5 + 0.001, "10.0.0.9", 8080, "10.0.0.2", 50000 + i, "RA"))
    assert run_detector(ScanDetector(), pk) == []


def test_dns_server_replying_to_many_ports_no_scan():
    s = Seq()
    pk = []
    for i in range(80):
        pk.append(dns_query(s, i * 0.1, "10.0.0.2", "10.0.0.53", i, f"h{i}.example.com", sport=40000 + i))
        pk.append(dns_response(s, i * 0.1 + 0.01, "10.0.0.53", "10.0.0.2", i, f"h{i}.example.com", dport=40000 + i))
    # server replies whose queries were not captured (one-sided capture)
    for i in range(80):
        pk.append(udp(s, 10 + i * 0.05, "10.0.0.53", 53, "10.0.0.3", 30000 + i))
    assert run_detector(ScanDetector(), pk) == []


def test_traceroute_udp_ports_no_scan():
    s = Seq()
    pk = [udp(s, i * 0.01, "10.0.0.2", 40000 + i, "198.51.100.7", 33434 + i, ttl=1 + i // 3) for i in range(60)]
    assert run_detector(ScanDetector(), pk) == []


def test_p2p_many_hosts_completed_no_sweep():
    s = Seq()
    pk = []
    rnd = random.Random(1)
    for i in range(50):
        peer = f"{rnd.randint(11, 200)}.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}"
        pk += handshake(s, i * 0.1, "10.0.0.2", 50000 + i, peer, rnd.randint(10000, 60000))
    assert run_detector(ScanDetector(), pk) == []


def test_browsing_many_cdn_ips_dns_resolved_no_sweep():
    s = Seq()
    pk = []
    for i in range(40):
        ip = f"151.101.{i}.{(i * 7) % 250 + 1}"
        pk.append(dns_response(s, i * 0.1, "10.0.0.53", "10.0.0.2", i, f"cdn{i}.example.net", answers=(("A", ip, 60),)))
        # internet down: SYNs unanswered, but the names were looked up first
        pk.append(tcp(s, i * 0.1 + 0.01, "10.0.0.2", 50000 + i, ip, 443, "S"))
    assert run_detector(ScanDetector(), pk) == []


def test_multicast_discovery_no_sweep():
    s = Seq()
    pk = []
    for i in range(50):
        pk.append(udp(s, i * 0.1, "10.0.0.2", 50000 + i, "239.255.255.250", 1900))
        pk.append(udp(s, i * 0.1, "10.0.0.2", 5353, "224.0.0.251", 5353))
        pk.append(icmp(s, i * 0.1, "10.0.0.2", "10.0.0.255", 8, 0))
    assert run_detector(ScanDetector(), pk) == []


def test_monitoring_pings_answered_rounds_no_sweep():
    s = Seq()
    pk = []
    hosts = ["10.0.5.%d" % (i * 9 + 3) for i in range(25)]
    for rnd in range(5):
        for j, h in enumerate(hosts):
            t = rnd * 60 + j * 0.5
            pk.append(icmp(s, t, "10.0.0.10", h, 8, 0, echo_id=7, echo_seq=rnd))
            pk.append(icmp(s, t + 0.001, h, "10.0.0.10", 0, 0, echo_id=7, echo_seq=rnd))
    assert run_detector(ScanDetector(), pk) == []


# --------------------------------------------------------------------------- #
# robustness
# --------------------------------------------------------------------------- #


def test_none_fields_and_backwards_time():
    s = Seq()
    pk = [tcp(s, 5 - i * 0.01, SCANNER, 40000, TARGET, p, "S") for i, p in enumerate(range(1, 40))]
    weird = tcp(s, 1, SCANNER, 1, TARGET, 2, "S")
    weird.tcp.sport = None
    pk.append(weird)
    nul = icmp(s, 1, TARGET, SCANNER, 3, 3)  # unreachable without inner
    pk.append(nul)
    bad = udp(s, 1, "10.0.0.1", 1, "10.0.0.2", 2)
    bad.dst = None
    pk.append(bad)
    fs = run_detector(ScanDetector(), pk)
    assert kinds(fs) == ["scan.port"]


def test_random_source_flood_is_fast_and_bounded():
    s = Seq()
    rnd = random.Random(7)
    pk = [tcp(s, i * 0.00002, f"{rnd.randint(1, 223)}.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}",
              rnd.randint(1024, 65535), TARGET, 80, "S") for i in range(100_000)]
    det = ScanDetector()
    t0 = time.perf_counter()
    fs = run_detector(det, pk)
    assert time.perf_counter() - t0 < 5.0
    assert fs == []
    assert len(det.pairs) <= det.pairs.maxlen and len(det.conns) <= det.conns.maxlen
