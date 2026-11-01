"""Idle (zombie) scans and ACK scans, plus the look-alikes that must stay quiet."""

from faultline.detectors.stealth import AckScanDetector, IdleScanDetector
from faultline.model import Category
from faultline.verdict import assess
from tests.factory import Seq, tcp

SCANNER, ZOMBIE, TARGET = "10.0.0.66", "10.0.0.24", "10.0.0.20"
SCANNER_MAC = "02:00:0a:00:00:42"


def _idle_scan(s, steady=True, forge=True):
    pk, t, ipid = [], 0.0, 500
    for i in range(8):
        pk.append(tcp(s, t, SCANNER, 50000 + i, ZOMBIE, 80, "SA", sq=1000 + i, win=1024))
        ipid += 1 if steady else 977 * (i + 3)
        pk.append(tcp(s, t + 0.0004, ZOMBIE, 80, SCANNER, 50000 + i, "R", ip_id=ipid & 0xFFFF))
        if forge and i in (2, 4, 6):
            pk.append(tcp(s, t + 0.01, ZOMBIE, 80, TARGET, 440 + i, "S", eth_src=SCANNER_MAC))
        t += 0.05
    return pk


def test_idle_scan_names_the_hidden_scanner():
    [f] = run(IdleScanDetector(), _idle_scan(Seq()))
    assess(f)
    assert f.kind == "scan.idle" and f.category == Category.ATTACK
    assert f.metrics["scanner"] == SCANNER and f.metrics["zombie"] == ZOMBIE
    assert f.metrics["targets"] == [TARGET]
    assert f.metrics["forged_sender_mac"] == SCANNER_MAC
    assert SCANNER in f.title and ZOMBIE in f.title


def test_unsolicited_synack_without_counter_or_forgery_is_quiet():
    assert run(IdleScanDetector(), _idle_scan(Seq(), steady=False, forge=False)) == []


def test_normal_handshakes_are_quiet():
    s, pk = Seq(), []
    for i in range(10):
        pk += [tcp(s, i, ZOMBIE, 40000 + i, TARGET, 443, "S"), tcp(s, i + 0.01, TARGET, 443, ZOMBIE, 40000 + i, "SA"),
               tcp(s, i + 0.02, ZOMBIE, 40000 + i, TARGET, 443, "R", ip_id=100 + i)]
    assert run(IdleScanDetector(), pk) == []


def test_syn_flood_backscatter_is_not_an_idle_scan():
    # a web server under a spoofed SYN flood answers with SYN/ACKs from port 80 to random client ports
    s, pk = Seq(), []
    for i in range(10):
        pk += [tcp(s, i * 0.01, "10.0.0.80", 80, ZOMBIE, 30000 + 7 * i, "SA"),
               tcp(s, i * 0.01 + 0.001, ZOMBIE, 30000 + 7 * i, "10.0.0.80", 80, "R", ip_id=200 + i)]
    assert run(IdleScanDetector(), pk) == []


def _ack(s, t, sport, dport, sq=0, win=1024, src=SCANNER, dst=TARGET):
    return tcp(s, t, src, sport, dst, dport, "A", sq=sq, ack=777, win=win)


def test_ack_scan_of_one_port_with_scanner_fingerprint():
    s = Seq()
    [f] = run(AckScanDetector(), [_ack(s, 0, 47104, 80), _ack(s, 0.1, 47105, 80)])
    assess(f)
    assert f.kind == "scan.ack_probe" and f.category == Category.ATTACK
    assert f.metrics["ports"] == [80] and f.metrics["probes"] == 2


def test_ack_scan_of_many_ports_with_resets():
    s, pk = Seq(), []
    for i, p in enumerate(range(20, 40)):
        pk += [_ack(s, i * 0.01, 45000 + i, p, sq=12345, win=29200),
               tcp(s, i * 0.01 + 0.001, TARGET, p, SCANNER, 45000 + i, "R")]
    [f] = run(AckScanDetector(), pk)
    assert f.metrics["rst_replies"] == 20 and len(f.metrics["ports"]) == 20


def test_capture_starting_mid_connection_is_quiet():
    # long-lived connections that were open before the capture started: first packet is an ACK, then data flows
    s, pk = Seq(), []
    for i in range(5):
        pk += [_ack(s, i, 51000 + i, 443), tcp(s, i + 0.01, TARGET, 443, SCANNER, 51000 + i, "PA", plen=900),
               tcp(s, i + 0.02, SCANNER, 51000 + i, TARGET, 443, "A", sq=99)]
    assert run(AckScanDetector(), pk) == []


def test_two_stray_acks_with_ordinary_headers_are_quiet():
    s = Seq()
    assert run(AckScanDetector(), [_ack(s, 0, 51000, 443, sq=8812, win=501), _ack(s, 1, 51001, 443, sq=9133, win=501)]) == []


def run(detector, packets):
    from tests.factory import run_detector
    return run_detector(detector, packets)
