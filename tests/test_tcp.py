"""Tests for faultline.detectors.tcp: positive cases and benign look-alikes."""

from __future__ import annotations

from faultline.detectors.tcp import TcpDetector, sdiff
from faultline.model import Category, Severity
from tests.factory import Seq, run_detector, tcp

CLIENT, SERVER = "10.0.0.2", "203.0.113.10"


class Conv:
    """Builds one TCP conversation packet by packet (sequence numbers tracked)."""

    def __init__(self, s: Seq, *, c=CLIENT, cp=50000, srv=SERVER, sp=80, cisn=1000, sisn=500_000,
                 ttl_c=64, ttl_s=52, mss=1460, wscale=7):
        self.s, self.c, self.cp, self.srv, self.sp = s, c, cp, srv, sp
        self.cisn, self.sisn = cisn, sisn
        self.cn, self.sn = (cisn + 1) & 0xFFFFFFFF, (sisn + 1) & 0xFFFFFFFF
        self.ttl_c, self.ttl_s, self.mss, self.wscale = ttl_c, ttl_s, mss, wscale
        self.pkts: list = []

    def _add(self, p):
        self.pkts.append(p)
        return p

    def syn(self, t):
        return self._add(tcp(self.s, t, self.c, self.cp, self.srv, self.sp, "S", sq=self.cisn, mss=self.mss,
                             wscale=self.wscale, ttl=self.ttl_c))

    def synack(self, t):
        return self._add(tcp(self.s, t, self.srv, self.sp, self.c, self.cp, "SA", sq=self.sisn, ack=self.cn,
                             mss=self.mss, wscale=self.wscale, ttl=self.ttl_s))

    def handshake(self, t=0.0, rtt_s=0.02, rtt_c=0.001):
        self.syn(t)
        self.synack(t + rtt_s)
        self.cack(t + rtt_s + rtt_c)
        return t + rtt_s + rtt_c

    def cdata(self, t, plen=100, flags="PA", seq=None, **kw):
        sq = self.cn if seq is None else seq
        p = tcp(self.s, t, self.c, self.cp, self.srv, self.sp, flags, sq=sq, ack=self.sn, plen=plen,
                ttl=kw.pop("ttl", self.ttl_c), **kw)
        if seq is None:
            self.cn = (self.cn + plen) & 0xFFFFFFFF
        return self._add(p)

    def sdata(self, t, plen=1448, flags="A", seq=None, **kw):
        sq = self.sn if seq is None else seq
        p = tcp(self.s, t, self.srv, self.sp, self.c, self.cp, flags, sq=sq, ack=self.cn, plen=plen,
                ttl=kw.pop("ttl", self.ttl_s), **kw)
        if seq is None:
            self.sn = (self.sn + plen) & 0xFFFFFFFF
        return self._add(p)

    def cack(self, t, ack=None, win=65535, flags="A"):
        return self._add(tcp(self.s, t, self.c, self.cp, self.srv, self.sp, flags, sq=self.cn,
                             ack=self.sn if ack is None else ack, win=win, ttl=self.ttl_c))

    def sack_(self, t, ack=None, win=65535, flags="A"):
        return self._add(tcp(self.s, t, self.srv, self.sp, self.c, self.cp, flags, sq=self.sn,
                             ack=self.cn if ack is None else ack, win=win, ttl=self.ttl_s))

    def fin_close(self, t):
        self._add(tcp(self.s, t, self.c, self.cp, self.srv, self.sp, "FA", sq=self.cn, ack=self.sn, ttl=self.ttl_c))
        self.cn += 1
        self._add(tcp(self.s, t + 0.01, self.srv, self.sp, self.c, self.cp, "FA", sq=self.sn, ack=self.cn, ttl=self.ttl_s))
        self.sn += 1
        self.cack(t + 0.011)

    def rst_from_server(self, t, ttl=None, seq=None):
        return self._add(tcp(self.s, t, self.srv, self.sp, self.c, self.cp, "RA", sq=self.sn if seq is None else seq,
                             ack=self.cn, ttl=self.ttl_s if ttl is None else ttl))

    def rst_from_client(self, t):
        return self._add(tcp(self.s, t, self.c, self.cp, self.srv, self.sp, "RA", sq=self.cn, ack=self.sn,
                             ttl=self.ttl_c))


def kinds(findings):
    return {f.kind for f in findings}


def by_kind(findings, kind):
    out = [f for f in findings if f.kind == kind]
    return out[0] if out else None


def download(s, n, *, lose=(), lose_upstream=(), cport=50000, t0=0.0, cisn=1000, sisn=500_000, seg_dt=0.001):
    """Server → client bulk transfer of ``n`` segments. Indexes in ``lose`` are
    seen once, then resent 0.3 s later (lost *after* the capture point); in
    ``lose_upstream`` the original is never seen, the resend fills the hole."""
    c = Conv(s, cp=cport, cisn=cisn, sisn=sisn)
    t = c.handshake(t0)
    c.cdata(t + 0.001, 200)
    t += 0.03
    resend = []
    for i in range(n):
        seq = c.sn
        if i in lose_upstream:
            c.sn = (c.sn + 1448) & 0xFFFFFFFF
            resend.append((t + 0.3, seq))
        else:
            c.sdata(t, 1448)
            if i in lose:
                resend.append((t + 0.3, seq))
        t += seg_dt
        if i % 2 == 1 and not resend:
            c.cack(t)
    for rt, seq in resend:
        c.sdata(max(rt, t), 1448, seq=seq)
        t = max(rt, t) + 0.001
    c.cack(t + 0.02)
    c.fin_close(t + 0.05)
    return c.pkts


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def test_sdiff_wraparound():
    assert sdiff(5, 0xFFFFFFF0) == 21
    assert sdiff(0xFFFFFFF0, 5) == -21
    assert sdiff(100, 100) == 0


# --------------------------------------------------------------------------- #
# tcp.retransmissions
# --------------------------------------------------------------------------- #

def test_isolated_retransmissions_are_not_reported():
    s = Seq()
    pkts = download(s, 2000, lose={500, 1500})
    f = run_detector(TcpDetector(), pkts)
    assert "tcp.retransmissions" not in kinds(f)


def test_downstream_loss_is_reported_and_localised():
    s = Seq()
    lost = set(range(10, 400, 10))  # 39 of 400 ≈ 10%
    f = by_kind(run_detector(TcpDetector(), download(s, 400, lose=lost)), "tcp.retransmissions")
    assert f is not None
    assert f.category == Category.FAULT
    assert f.severity >= Severity.HIGH
    m = f.metrics
    assert m["retransmissions"] == len(lost)
    # server data seen by us then resent -> lost between capture point and the client
    assert m["loss_client_side"] == len(lost) and m["loss_server_side"] == 0
    assert m["loss_location"] == "client"
    assert m["worst_flows"] and m["worst_flows"][0]["retransmissions"] == len(lost)
    assert f.packets and f.packet_total == len(lost)
    assert SERVER in f.hosts and CLIENT in f.hosts
    assert f.indicators and f.fix and f.analogy


def test_upstream_loss_is_localised_server_side():
    s = Seq()
    lost = set(range(5, 300, 10))
    f = by_kind(run_detector(TcpDetector(), download(s, 300, lose_upstream=lost)), "tcp.retransmissions")
    assert f is not None
    assert f.metrics["loss_server_side"] == len(lost)
    assert f.metrics["loss_location"] == "server"
    assert "between this capture point and" in f.summary


def test_capture_drops_are_not_blamed_on_the_network():
    """Holes the receiver ACKs without a resend were dropped by the capture tool."""
    s = Seq()
    c = Conv(s)
    t = c.handshake()
    for i in range(400):
        if i % 10 == 5:
            c.sn += 1448  # never captured, never resent
        else:
            c.sdata(t, 1448)
        t += 0.001
        if i % 2:
            c.cack(t)
    det = TcpDetector()
    f = run_detector(det, c.pkts)
    assert "tcp.retransmissions" not in kinds(f)
    assert det.cap_drops >= 30 and det.rx["s"] == 0


def test_out_of_order_is_not_a_retransmission():
    s = Seq()
    c = Conv(s)
    t = c.handshake()
    for i in range(200):
        a = c.sn
        b = (a + 1448) & 0xFFFFFFFF
        c.sn = (b + 1448) & 0xFFFFFFFF
        c.sdata(t, 1448, seq=b)  # later segment first
        c.sdata(t + 0.0002, 1448, seq=a)  # swapped within 0.2 ms
        c.cack(t + 0.0005)
        t += 0.002
    det = TcpDetector()
    assert "tcp.retransmissions" not in kinds(run_detector(det, c.pkts))
    assert det.ooo == 200 and det.rx["s"] == 0


def test_keepalives_and_wraparound_do_not_count():
    s = Seq()
    pkts = download(s, 600, cisn=0xFFFFFF00, sisn=0xFFFF0000)  # both sides wrap 2^32
    c = Conv(s, cp=50001)
    t = c.handshake(10.0)
    for i in range(20):  # keepalive: 1 byte at nxt-1, every 15 s
        c.cdata(t + 15 * (i + 1), 1, flags="A", seq=(c.cn - 1) & 0xFFFFFFFF)
        c.sack_(t + 15 * (i + 1) + 0.02)
    det = TcpDetector()
    f = run_detector(det, pkts + c.pkts)
    assert "tcp.retransmissions" not in kinds(f)
    assert det.rx["c"] == det.rx["s"] == 0 and det.gaps == 0
    assert det.keepalives == 20


def test_fast_retransmission_after_dup_acks():
    s = Seq()
    c = Conv(s)
    t = c.handshake()
    for k in range(12):
        lost = c.sn
        c.sdata(t, 1448)
        for _ in range(4):
            c.sdata(t + 0.001, 1448)
            c.cack(t + 0.002, ack=lost)  # dup ACKs pointing at the lost segment
        c.sdata(t + 0.03, 1448, seq=lost)  # fast retransmission
        c.cack(t + 0.05)
        t += 0.1
    det = TcpDetector()
    f = by_kind(run_detector(det, c.pkts), "tcp.retransmissions")
    assert f is not None
    assert f.metrics["fast_retransmissions"] == 12
    assert f.metrics["dup_acks"] >= 12 * 3


# --------------------------------------------------------------------------- #
# tcp.refused
# --------------------------------------------------------------------------- #

def _refused_attempt(s, cport, t, srv=SERVER, sp=8080, c=CLIENT):
    return [tcp(s, t, c, cport, srv, sp, "S", sq=1000 + cport),
            tcp(s, t + 0.001, srv, sp, c, cport, "RA", sq=0, ack=1001 + cport, ttl=52)]


def test_refused_never_accepted_is_misconfig():
    s = Seq()
    pkts = []
    for i in range(4):
        pkts += _refused_attempt(s, 40000 + i, i * 1.0)
    f = by_kind(run_detector(TcpDetector(), pkts), "tcp.refused")
    assert f is not None
    assert f.category == Category.MISCONFIG
    assert f.metrics["refused"] == 4 and f.metrics["pattern"] == "never_accepted"
    assert Category.FAULT in f.variants and Category.MISCONFIG in f.variants
    assert len(f.packets) == 8  # SYN + RST of each attempt


def test_refused_after_accepting_is_a_crash():
    s = Seq()
    c = Conv(s, sp=8080)
    t = c.handshake(0.0)
    c.cdata(t, 100)
    c.sdata(t + 0.03, 500, flags="PA")
    c.fin_close(t + 0.1)
    pkts = list(c.pkts)
    for i in range(3):
        pkts += _refused_attempt(s, 41000 + i, 10.0 + i)
    f = by_kind(run_detector(TcpDetector(), pkts), "tcp.refused")
    assert f is not None and f.category == Category.FAULT
    assert f.metrics["pattern"] == "stopped" and f.severity == Severity.HIGH


def test_port_scan_refusals_are_excluded():
    s = Seq()
    pkts = []
    for port in range(1, 40):
        pkts += [tcp(s, port * 0.01, "10.0.0.66", 55555, SERVER, port, "S", sq=7),
                 tcp(s, port * 0.01 + 0.001, SERVER, port, "10.0.0.66", 55555, "RA", sq=0, ack=8)]
    for port in (22, 23, 25):  # several refusals on the same port from the scanner
        for k in range(3):
            pkts += [tcp(s, 2 + k, "10.0.0.66", 56000 + k + port, SERVER, port, "S", sq=9),
                     tcp(s, 2 + k + 0.001, SERVER, port, "10.0.0.66", 56000 + k + port, "RA", sq=0, ack=10)]
    assert "tcp.refused" not in kinds(run_detector(TcpDetector(), pkts))


def test_two_refusals_are_below_threshold():
    s = Seq()
    pkts = _refused_attempt(s, 40000, 0) + _refused_attempt(s, 40001, 1)
    assert "tcp.refused" not in kinds(run_detector(TcpDetector(), pkts))


# --------------------------------------------------------------------------- #
# tcp.resets
# --------------------------------------------------------------------------- #

def _aborted(s, cport, t0, *, rst_ttl=None, after=0):
    c = Conv(s, cp=cport)
    t = c.handshake(t0)
    c.cdata(t, 200)
    for i in range(5):
        c.sdata(t + 0.03 + i * 0.001, 1448)
    c.cack(t + 0.035)
    c.sdata(t + 0.04, 1448)  # in flight when the reset comes
    c.rst_from_server(t + 0.041, ttl=rst_ttl)
    for i in range(after):  # the "resetting" server keeps talking
        c.sdata(t + 0.05 + i * 0.001, 1448)
    return c.pkts


def test_mid_transfer_resets_are_reported():
    s = Seq()
    pkts = []
    for i in range(6):
        pkts += _aborted(s, 42000 + i, i * 1.0)
    f = by_kind(run_detector(TcpDetector(), pkts), "tcp.resets")
    assert f is not None and f.category == Category.FAULT
    assert f.metrics["aborted_connections"] == 6
    assert f.metrics["rst_from_server"] == 6
    assert not f.metrics["injection_candidates"]
    assert len(f.packets) == 6


def test_rst_after_fin_is_benign():
    s = Seq()
    pkts = []
    for i in range(10):
        c = Conv(s, cp=43000 + i)
        t = c.handshake(i * 1.0)
        c.cdata(t, 200)
        c.sdata(t + 0.03, 800, flags="PA")
        c._add(tcp(s, t + 0.05, c.srv, c.sp, c.c, c.cp, "FA", sq=c.sn, ack=c.cn))
        c.sn += 1
        c.cack(t + 0.051)
        c.rst_from_client(t + 0.052)  # browser-style RST after the FIN
        pkts += c.pkts
    det = TcpDetector()
    assert "tcp.resets" not in kinds(run_detector(det, pkts))
    assert det.after_fin_rsts == 10


def test_abortive_close_of_idle_connections_is_benign():
    s = Seq()
    pkts = []
    for i in range(10):
        c = Conv(s, cp=44000 + i)
        t = c.handshake(i * 1.0)
        c.cdata(t, 200)
        c.sdata(t + 0.03, 800, flags="PA")
        c.cack(t + 0.031)
        c.rst_from_client(t + 0.2)  # everything acknowledged, SO_LINGER=0 style close
        pkts += c.pkts
    assert "tcp.resets" not in kinds(run_detector(TcpDetector(), pkts))


def test_injected_resets_are_attack():
    s = Seq()
    pkts = []
    for i in range(3):
        pkts += _aborted(s, 45000 + i, i * 1.0, rst_ttl=120, after=3)
    f = by_kind(run_detector(TcpDetector(), pkts), "tcp.resets")
    assert f is not None and f.category == Category.ATTACK
    assert Category.ATTACK in f.variants and f.variants[Category.ATTACK].mitre
    cands = f.metrics["injection_candidates"]
    assert len(cands) == 3 and all(c["ttl_mismatch"] and c["packets_after_rst"] == 3 for c in cands)
    assert sum(i.weight for i in f.indicators if i.supports == Category.ATTACK) > \
        sum(i.weight for i in f.indicators if i.supports == Category.FAULT)


# --------------------------------------------------------------------------- #
# tcp.syn_timeout
# --------------------------------------------------------------------------- #

def _unanswered(s, cport, t0, retries=3, dst="198.51.100.7", dport=443):
    out, t, dt = [], t0, 1.0
    for _ in range(retries + 1):
        out.append(tcp(s, t, CLIENT, cport, dst, dport, "S", sq=77 + cport))
        t += dt
        dt *= 2
    return out


def test_syn_timeout_with_backoff():
    s = Seq()
    pkts = _unanswered(s, 46000, 0.0) + _unanswered(s, 46001, 20.0)
    pkts.append(tcp(s, 60.0, CLIENT, 46002, "198.51.100.99", 80, "S", sq=1))  # unrelated, near end
    f = by_kind(run_detector(TcpDetector(), pkts), "tcp.syn_timeout")
    assert f is not None and f.category == Category.FAULT
    assert f.metrics["attempts"] == 2 and f.metrics["syns"] == 8
    assert f.metrics["syn_retry_intervals_s"] == [1.0, 2.0, 4.0]
    assert any("backoff" in i.text for i in f.indicators)
    assert len(f.packets) == 8


def test_syn_timeout_to_live_host_suggests_firewall():
    s = Seq()
    pkts = _unanswered(s, 46100, 0.0) + _unanswered(s, 46101, 20.0)
    c = Conv(s, srv="198.51.100.7", sp=22, cp=46200)  # same host answers on another port
    c.handshake(30.0)
    f = by_kind(run_detector(TcpDetector(), pkts + c.pkts), "tcp.syn_timeout")
    assert f is not None and f.category == Category.MISCONFIG


def test_answered_or_truncated_syns_are_not_timeouts():
    s = Seq()
    c = Conv(s)
    c.syn(0.0)
    c.syn(1.0)  # one retransmitted SYN, then answered: fine
    c.synack(1.02)
    c.cack(1.03)
    pkts = list(c.pkts)
    pkts.append(tcp(s, 2.0, CLIENT, 47000, "198.51.100.8", 443, "S", sq=5))  # capture ends 0.5 s later
    pkts.append(tcp(s, 2.5, CLIENT, 47001, SERVER, 80, "A", sq=1, ack=1))
    # one-direction capture: client SYN then client ACK/data (SYN/ACK not visible)
    pkts.append(tcp(s, 2.2, CLIENT, 47002, "198.51.100.9", 443, "S", sq=10))
    pkts.append(tcp(s, 2.25, CLIENT, 47002, "198.51.100.9", 443, "A", sq=11, ack=99))
    assert "tcp.syn_timeout" not in kinds(run_detector(TcpDetector(), pkts))


# --------------------------------------------------------------------------- #
# tcp.zero_window
# --------------------------------------------------------------------------- #

def test_zero_window_stall_blames_receiver():
    s = Seq()
    c = Conv(s)
    t = c.handshake()
    c.cdata(t, 200)
    t += 0.03
    for k in range(3):
        for i in range(10):
            c.sdata(t + i * 0.001, 1448)
        c.cack(t + 0.02, win=0)  # receiver's buffer is full
        c.sdata(t + 0.5, 1, flags="A")  # zero-window probe
        c.cack(t + 0.52, win=0)
        c.cack(t + 1.2, win=512)  # window update after 1.18 s
        t += 1.5
    f = by_kind(run_detector(TcpDetector(), c.pkts), "tcp.zero_window")
    assert f is not None and f.category == Category.FAULT
    assert f.metrics["zero_window_events"] == 3
    assert abs(f.metrics["stall_seconds"] - 3 * 1.18) < 0.01
    assert f.metrics["receiver"] == CLIENT and f.hosts[0] == CLIENT
    assert f.severity >= Severity.MEDIUM
    assert f.packets
    assert "tcp.retransmissions" not in kinds(run_detector(TcpDetector(), c.pkts))


def test_no_zero_window_in_healthy_transfer():
    s = Seq()
    assert "tcp.zero_window" not in kinds(run_detector(TcpDetector(), download(s, 300)))


# --------------------------------------------------------------------------- #
# healthy mix + robustness
# --------------------------------------------------------------------------- #

def test_healthy_browser_like_traffic_has_no_medium_findings():
    s = Seq()
    pkts = []
    for i in range(30):  # parallel connections to several hosts, clean FIN close
        pkts += download(s, 40, cport=48000 + i, t0=i * 0.05, sisn=1000 * i)
    pkts.sort(key=lambda p: p.ts)
    f = run_detector(TcpDetector(), pkts)
    assert not [x for x in f if x.severity >= Severity.MEDIUM], [x.kind for x in f]


def test_robust_against_weird_packets():
    s = Seq()
    pkts = download(s, 50)
    odd = []
    p = tcp(s, 1.0, CLIENT, 50000, SERVER, 80, "A", sq=5, ack=7)
    p.tcp.seq = None
    odd.append(p)
    p = tcp(s, 1.0, CLIENT, 50000, SERVER, 80, "A", sq=5, ack=7)
    p.tcp.ack = p.tcp.win = p.tcp.plen = p.tcp.flags = None
    odd.append(p)
    p = tcp(s, -50.0, SERVER, 80, CLIENT, 50000, "PA", sq=123456789, ack=1, plen=10)  # time goes backwards
    odd.append(p)
    p = tcp(s, 2.0, CLIENT, 50000, SERVER, 80, "A", sq=5)
    p.src = None
    odd.append(p)
    p = tcp(s, 2.0, CLIENT, 50000, SERVER, 80, "FSRPAUEC", sq=0xFFFFFFFF, ack=0xFFFFFFFF, plen=3)  # Xmas
    odd.append(p)
    pkts = pkts[:40] + odd + pkts[40:]
    det = TcpDetector()
    run_detector(det, pkts)  # must not raise
    # ts=None is not something the reader produces (the shared context would reject it),
    # but the detector itself must cope
    p = tcp(s, 2.0, CLIENT, 50000, SERVER, 80, "PA", sq=5, plen=4)
    p.ts = None
    p.ttl = None
    det = TcpDetector()
    det.on_packet(p, None)
    det.finalize(type("Ctx", (), {"end_ts": None, "config": type("C", (), {"scale": 1.0})(), "hosts": None})())


def test_flow_table_eviction_keeps_counters():
    s = Seq()
    det = TcpDetector()
    det.flows.maxlen = 5
    pkts = []
    for i in range(20):
        pkts += download(s, 20, lose={3}, cport=49000 + i, t0=i)
    run_detector(det, pkts)
    assert det.rx["s"] == 20 and det.flows_seen == 20


def test_spoofed_syn_flood_reads_as_attack():
    s = Seq()
    pkts = [tcp(s, i * 0.001, f"100.{(i >> 8) & 255}.{i & 255}.7", 1024 + i, "203.0.113.5", 80, "S", sq=i)
            for i in range(300)]
    pkts.append(tcp(s, 30.0, CLIENT, 50000, "198.51.100.1", 53, "S", sq=1))  # extend the capture
    f = by_kind(run_detector(TcpDetector(), pkts), "tcp.syn_timeout")
    assert f is not None and f.category == Category.ATTACK and f.mitre
