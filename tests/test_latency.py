"""Tests for faultline.detectors.latency (handshake RTT split, server think time)."""

from __future__ import annotations

from faultline.detectors.latency import LatencyDetector, pct
from faultline.model import Category, Severity
from tests.factory import Seq, http_request, http_response, run_detector, tcp
from tests.test_tcp import Conv, by_kind, kinds

CLIENT, SERVER = "10.0.0.2", "203.0.113.10"


def http_conn(s, cport, t0, *, rtt_s=0.02, rtt_c=0.001, think=0.01, requests=1, srv=SERVER, sp=80,
              retransmit_request=False):
    """Handshake + ``requests`` HTTP exchanges. The capture sits near the client,
    so the server's answer arrives ``rtt_s + think`` after the request."""
    c = Conv(s, cp=cport, srv=srv, sp=sp)
    t = c.handshake(t0, rtt_s=rtt_s, rtt_c=rtt_c)
    for _ in range(requests):
        req = http_request(s, t, CLIENT, cport, srv, sp, sq=c.cn, ack=c.sn)
        c._add(req)
        if retransmit_request:
            c._add(http_request(s, t + 0.3, CLIENT, cport, srv, sp, sq=c.cn, ack=c.sn))
        c.cn += 200
        c.sack_(t + rtt_s)
        resp_t = t + rtt_s + think
        c._add(http_response(s, resp_t, srv, sp, CLIENT, cport, sq=c.sn, ack=c.cn))
        c.sn += 600
        c.cack(resp_t + 0.001)
        t = resp_t + 0.2  # client think time before the next request
    c.fin_close(t + 0.1)
    return c.pkts


def test_percentile():
    assert pct([1, 2, 3, 4, 5], 0.5) == 3
    assert pct([], 0.5) is None
    assert abs(pct([0.0, 10.0], 0.9) - 9.0) < 1e-9


def test_high_rtt_far_side_not_slow_server():
    s = Seq()
    pkts = []
    for i in range(6):
        pkts += http_conn(s, 51000 + i, i * 2.0, rtt_s=0.65 + 0.01 * i, think=0.01)
    f = run_detector(LatencyDetector(), pkts)
    hr = by_kind(f, "latency.high_rtt")
    assert hr is not None and "latency.slow_server" not in kinds(f)
    assert hr.category == Category.FAULT
    assert hr.metrics["delay_side"] == "server"
    assert 650 <= hr.metrics["median_rtt_ms"] <= 700
    assert hr.metrics["capture_to_client_ms"] <= 2
    assert SERVER in hr.hosts and hr.packets
    assert "satellite" in hr.cause  # steady ~650 ms


def test_high_rtt_near_side():
    s = Seq()
    pkts = []
    for i in range(5):
        pkts += http_conn(s, 51100 + i, i * 2.0, rtt_s=0.005, rtt_c=0.4 + 0.05 * i)
    hr = by_kind(run_detector(LatencyDetector(), pkts), "latency.high_rtt")
    assert hr is not None and hr.metrics["delay_side"] == "client"
    assert hr.severity >= Severity.MEDIUM
    assert "Wi-Fi" in hr.cause


def test_jitter_triggers():
    s = Seq()
    pkts = []
    for i, r in enumerate([0.02, 0.02, 0.03, 0.025, 0.02, 0.5, 0.45, 0.6, 0.03, 0.02]):
        pkts += http_conn(s, 51200 + i, i * 2.0, rtt_s=r)
    hr = by_kind(run_detector(LatencyDetector(), pkts), "latency.high_rtt")
    assert hr is not None


def test_one_slow_handshake_is_not_reported():
    s = Seq()
    pkts = []
    for i, r in enumerate([0.02, 0.02, 0.9, 0.03]):
        pkts += http_conn(s, 51300 + i, i * 2.0, rtt_s=r)
    assert "latency.high_rtt" not in kinds(run_detector(LatencyDetector(), pkts))


def test_retransmitted_syn_is_not_an_rtt_sample():
    s = Seq()
    pkts = []
    for i in range(5):
        c = Conv(s, cp=51400 + i)
        c.syn(i * 5.0)
        c.syn(i * 5.0 + 1.0)  # Karn: ambiguous
        c.synack(i * 5.0 + 1.02)
        c.cack(i * 5.0 + 1.021)
        pkts += c.pkts
    assert "latency.high_rtt" not in kinds(run_detector(LatencyDetector(), pkts))


def test_slow_server_with_healthy_network():
    s = Seq()
    pkts = []
    for i in range(4):
        pkts += http_conn(s, 52000 + i, i * 5.0, rtt_s=0.02, think=2.5)
    f = run_detector(LatencyDetector(), pkts)
    ss = by_kind(f, "latency.slow_server")
    assert ss is not None and "latency.high_rtt" not in kinds(f)
    m = ss.metrics
    assert m["slow_requests"] == 4 and m["requests"] == 4
    assert abs(m["server_processing_s"] - 2.5) < 0.01
    assert m["network_rtt_ms"] < 30 and m["blame"] == "server"
    assert "the server is slow" in ss.explanation
    assert len(ss.packets) == 8  # request + response frames


def test_slow_requests_share_rule():
    s = Seq()
    pkts = []
    for i in range(2):
        pkts += http_conn(s, 52100 + i, i * 5.0, think=1.8)
    for i in range(3):
        pkts += http_conn(s, 52200 + i, 20 + i * 5.0, think=0.05)
    assert "latency.slow_server" in kinds(run_detector(LatencyDetector(), pkts))  # 2/5 = 40% >= 30%


def test_fast_server_and_retransmitted_requests_are_not_blamed():
    s = Seq()
    pkts = []
    for i in range(5):
        pkts += http_conn(s, 52300 + i, i * 3.0, think=0.05, requests=3)
    for i in range(4):  # request lost once: waiting time is the network's fault
        pkts += http_conn(s, 52400 + i, 30 + i * 5.0, think=0.05, retransmit_request=True)
    f = run_detector(LatencyDetector(), pkts)
    assert not f


def test_long_poll_on_one_connection_is_ignored():
    """Opaque (non-HTTP) traffic slow on a single persistent connection: push/long-poll, not a slow server."""
    s = Seq()
    c = Conv(s, sp=443)
    t = c.handshake(0.0)
    for _ in range(6):
        c.cdata(t, 120)
        c.sack_(t + 0.02)
        c.sdata(t + 25.0, 300, flags="PA")
        c.cack(t + 25.001)
        t += 25.1
    assert "latency.slow_server" not in kinds(run_detector(LatencyDetector(), c.pkts))


def test_robust_against_weird_packets():
    s = Seq()
    pkts = http_conn(s, 53000, 0.0)
    p = tcp(s, -10.0, SERVER, 80, CLIENT, 53000, "PA", sq=1, ack=1, plen=20)  # time goes backwards
    pkts.insert(3, p)
    p = tcp(s, 1.0, CLIENT, 53000, SERVER, 80, "A", sq=5)
    p.tcp.seq = None
    pkts.insert(4, p)
    p = tcp(s, 1.0, CLIENT, 53000, SERVER, 80, "A", sq=5)
    p.tcp.flags = p.tcp.plen = p.tcp.ack = None
    pkts.insert(5, p)
    p = tcp(s, 1.0, CLIENT, 53001, SERVER, 80, "SA", sq=0xFFFFFFFF, ack=0)  # SYN/ACK without SYN
    pkts.append(p)
    run_detector(LatencyDetector(), pkts)


def test_pooled_high_rtt_over_many_destinations():
    """One or two connections per server, but the shared path is slow for all of them."""
    s = Seq()
    pkts = []
    for i in range(6):
        pkts += http_conn(s, 54000 + i, i * 2.0, rtt_s=0.7, srv=f"198.51.100.{10 + i // 2}")
    hr = by_kind(run_detector(LatencyDetector(), pkts), "latency.high_rtt")
    assert hr is not None and hr.metrics["servers"] == 3
    assert {p["trigger"] for p in hr.metrics["per_server"]} == {"pooled"}


def test_pool_of_near_and_far_servers_is_not_jitter():
    s = Seq()
    pkts = []
    for i in range(8):  # half LAN (2 ms), half far away (250 ms), one connection each
        pkts += http_conn(s, 54100 + i, i * 2.0, rtt_s=0.002 if i % 2 else 0.25, srv=f"198.51.100.{30 + i}")
    assert "latency.high_rtt" not in kinds(run_detector(LatencyDetector(), pkts))
