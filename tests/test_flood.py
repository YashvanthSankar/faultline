"""Tests for flood.syn / flood.icmp / flood.broadcast."""

from __future__ import annotations

import random
import time

from faultline.detectors.flood import Distinct, FloodDetector
from faultline.model import Category, Severity
from tests.factory import Seq, arp, icmp, run_detector, tcp, udp

VICTIM = "10.0.0.5"


def score(f, cat):
    return sum(i.weight for i in f.indicators if i.supports is cat)


def winner(f):
    return max((Category.FAULT, Category.MISCONFIG, Category.ATTACK), key=lambda c: score(f, c))


def rand_ip(rnd):
    return f"{rnd.randint(1, 223)}.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}"


# --------------------------------------------------------------------------- #
# SYN flood vs flash crowd
# --------------------------------------------------------------------------- #


def test_spoofed_syn_flood_is_attack():
    s, rnd = Seq(), random.Random(3)
    pk = []
    for i in range(3000):
        t = i * 0.0015
        src, sp = rand_ip(rnd), rnd.randint(1024, 65535)
        pk.append(tcp(s, t, src, sp, VICTIM, 80, "S", ttl=57))
        if i % 2 == 0:
            pk.append(tcp(s, t + 0.0001, VICTIM, 80, src, sp, "SA"))
    fs = run_detector(FloodDetector(), pk)
    syn = [f for f in fs if f.kind == "flood.syn"]
    assert len(syn) == 1
    f = syn[0]
    assert f.category is Category.ATTACK and f.severity >= Severity.HIGH
    assert winner(f) is Category.ATTACK
    assert f.metrics["completion_ratio"] == 0
    assert f.metrics["distinct_sources"] > 2500
    assert f.mitre.startswith("T1499.001")
    assert set(f.variants) == {Category.ATTACK, Category.FAULT}
    assert f.packets


def test_single_source_syn_flood():
    s = Seq()
    pk = [tcp(s, i * 0.002, "198.51.100.9", 1024 + i, VICTIM, 443, "S") for i in range(2000)]
    f = [f for f in run_detector(FloodDetector(), pk) if f.kind == "flood.syn"][0]
    assert winner(f) is Category.ATTACK
    assert f.metrics["top_sources"][0].startswith("198.51.100.9")


def test_flash_crowd_overloaded_server_is_fault():
    s, rnd = Seq(), random.Random(5)
    pk = []
    for i in range(400):
        t = i * 0.02
        c, cp = f"10.{rnd.randint(1, 20)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}", 40000 + i
        ttl = rnd.choice([52, 55, 58, 61, 63, 117, 120])
        pk.append(tcp(s, t, c, cp, VICTIM, 80, "S", ttl=ttl))
        if i % 3 == 0:  # slow server: client has to retry
            pk.append(tcp(s, t + 1.0, c, cp, VICTIM, 80, "S", ttl=ttl))
        pk += [tcp(s, t + 1.2, VICTIM, 80, c, cp, "SA"), tcp(s, t + 1.21, c, cp, VICTIM, 80, "A", ttl=ttl),
               tcp(s, t + 1.22, c, cp, VICTIM, 80, "PA", plen=300, ttl=ttl)]
    pk.sort(key=lambda p: p.ts)
    syn = [f for f in run_detector(FloodDetector(), pk) if f.kind == "flood.syn"]
    assert len(syn) == 1
    f = syn[0]
    assert f.category is Category.FAULT and winner(f) is Category.FAULT
    assert f.severity == Severity.MEDIUM
    assert f.metrics["completion_ratio"] > 0.6


def test_busy_healthy_server_no_finding():
    s = Seq()
    pk = []
    for i in range(500):
        t = i * 0.01
        c, cp = f"10.1.{i // 250}.{i % 250 + 1}", 40000 + i
        pk += [tcp(s, t, c, cp, VICTIM, 443, "S"), tcp(s, t + 0.001, VICTIM, 443, c, cp, "SA"),
               tcp(s, t + 0.002, c, cp, VICTIM, 443, "A"), tcp(s, t + 0.003, c, cp, VICTIM, 443, "PA", plen=500)]
    assert [f for f in run_detector(FloodDetector(), pk) if f.kind == "flood.syn"] == []


def test_few_syns_no_finding():
    s = Seq()
    pk = [tcp(s, i * 0.1, "10.0.0.2", 40000 + i, VICTIM, 80, "S") for i in range(50)]
    assert run_detector(FloodDetector(), pk) == []


# --------------------------------------------------------------------------- #
# ICMP
# --------------------------------------------------------------------------- #


def test_icmp_flood_distributed():
    s, rnd = Seq(), random.Random(9)
    srcs = [rand_ip(rnd) for _ in range(50)]
    pk = [icmp(s, i / 250, srcs[i % 50], VICTIM, 8, 0, echo_id=i % 50, echo_seq=i, wirelen=1200) for i in range(1500)]
    for p in pk:
        p.ip_len = 1186
    fs = [f for f in run_detector(FloodDetector(), pk) if f.kind == "flood.icmp"]
    assert len(fs) == 1
    f = fs[0]
    assert f.category is Category.ATTACK and winner(f) is Category.ATTACK
    assert f.metrics["sustained_s"] >= 3 and f.metrics["large_ratio"] == 1.0
    assert f.mitre.startswith("T1498.001")


def test_normal_ping_no_finding():
    s = Seq()
    pk = []
    for i in range(60):
        pk += [icmp(s, i, "10.0.0.2", VICTIM, 8, 0, echo_id=1, echo_seq=i), icmp(s, i + 0.001, VICTIM, "10.0.0.2", 0, 0)]
    assert run_detector(FloodDetector(), pk) == []


def test_ping_f_from_monitoring_has_misconfig_reading():
    s = Seq()
    pk = []
    for i in range(1000):
        pk += [icmp(s, i / 200, "10.0.0.2", VICTIM, 8, 0, echo_id=1, echo_seq=i),
               icmp(s, i / 200 + 0.0001, VICTIM, "10.0.0.2", 0, 0, echo_id=1, echo_seq=i)]
    f = [f for f in run_detector(FloodDetector(), pk) if f.kind == "flood.icmp"][0]
    assert Category.MISCONFIG in f.variants
    assert score(f, Category.MISCONFIG) >= 2
    assert f.metrics["answered_ratio"] > 0.9


def test_smurf_broadcast_ping():
    s = Seq()
    pk = [icmp(s, i * 0.1, VICTIM, "10.0.0.255", 8, 0, eth_dst="ff:ff:ff:ff:ff:ff") for i in range(30)]
    fs = [f for f in run_detector(FloodDetector(), pk) if f.kind == "flood.icmp"]
    assert len(fs) == 1 and fs[0].metrics["pattern"] == "smurf"


def test_ping_of_death_fragment():
    s = Seq()
    p = icmp(s, 0, "198.51.100.1", VICTIM, 8, 0)
    p.icmp = None
    p.mf, p.frag_off, p.ip_len = False, 8100, 1500  # 64,800 + 1,480 bytes > 65,535
    fs = [f for f in run_detector(FloodDetector(), [p]) if f.kind == "flood.icmp"]
    assert fs and fs[0].metrics["pattern"] == "ping_of_death"


# --------------------------------------------------------------------------- #
# broadcast storm
# --------------------------------------------------------------------------- #


def test_switching_loop_identical_frames():
    s = Seq()
    pk = []
    for i in range(400):  # the same ARP request looping, copies 0.2 ms apart
        pk.append(arp(s, 1 + i * 0.0002, 1, "02:00:00:00:00:02", "10.0.0.2", tpa="10.0.0.1"))
    pk += [tcp(s, 1 + i * 0.001, "10.0.0.2", 40000, "10.0.0.9", 80, "A") for i in range(50)]
    pk.sort(key=lambda p: p.ts)
    fs = [f for f in run_detector(FloodDetector(), pk) if f.kind == "flood.broadcast"]
    assert len(fs) == 1
    f = fs[0]
    assert f.category is Category.FAULT and winner(f) is Category.FAULT
    assert f.metrics["max_copies"] >= 300 and f.severity >= Severity.HIGH


def test_broadcast_rate_storm():
    s = Seq()
    pk = []
    for i in range(3000):  # 1000 distinct broadcasts per second for 3 s
        pk.append(arp(s, i / 1000, 1, f"02:00:00:00:{i % 7:02x}:01", f"10.0.0.{i % 7 + 2}", tpa=f"10.0.{i % 250}.{i % 200 + 1}"))
        if i % 3 == 0:
            pk.append(tcp(s, i / 1000, "10.0.0.2", 40000, "10.0.0.9", 80, "A"))
    fs = [f for f in run_detector(FloodDetector(), pk) if f.kind == "flood.broadcast"]
    assert len(fs) == 1 and fs[0].metrics["storm_seconds"] >= 2


def test_normal_discovery_and_iptv_multicast_no_storm():
    s = Seq()
    pk = []
    for i in range(20):
        pk.append(udp(s, i * 0.5, "10.0.0.2", 5353, "224.0.0.251", 5353, eth_dst="01:00:5e:00:00:fb"))
        pk.append(udp(s, i * 0.5 + 0.1, "10.0.0.3", 50000, "239.255.255.250", 1900, eth_dst="01:00:5e:7f:ff:fa"))
    for i in range(5000):  # IPTV multicast stream: 1000 pps, distinct IP IDs
        pk.append(udp(s, i / 1000, "10.0.0.40", 5004, "239.1.1.1", 5004, plen=1316, eth_dst="01:00:5e:01:01:01",
                      ip_id=i & 0xFFFF))
    pk.sort(key=lambda p: p.ts)
    assert [f for f in run_detector(FloodDetector(), pk) if f.kind == "flood.broadcast"] == []


# --------------------------------------------------------------------------- #
# robustness
# --------------------------------------------------------------------------- #


def test_distinct_sketch_accuracy():
    d = Distinct(exact=100)
    for i in range(20000):
        d.add(f"ip{i}")
    assert 18000 < d.count() < 22000


def test_random_sources_fast_and_bounded():
    s, rnd = Seq(), random.Random(11)
    pk = [tcp(s, i * 0.00002, rand_ip(rnd), rnd.randint(1024, 65535), VICTIM, 80, "S") for i in range(100_000)]
    det = FloodDetector()
    t0 = time.perf_counter()
    fs = run_detector(det, pk)
    assert time.perf_counter() - t0 < 5.0
    assert [f.kind for f in fs] == ["flood.syn"]
    assert fs[0].metrics["distinct_sources"] > 80_000


def test_none_fields():
    s = Seq()
    p1 = tcp(s, 0, "10.0.0.1", 1, "10.0.0.2", 2, "S")
    p1.tcp.sport = None
    p2 = icmp(s, 0, "10.0.0.1", "10.0.0.2", 8)
    p2.dst = None
    p3 = arp(s, 0, 1, "02:00:00:00:00:09", "10.0.0.9")
    p3.eth_dst = None
    p4 = tcp(s, 0, "10.0.0.1", 1, "10.0.0.2", 2, "S")
    p4.ttl = None
    p4.tcp.flags = None
    assert run_detector(FloodDetector(), [p1, p2, p3, p4]) == []
