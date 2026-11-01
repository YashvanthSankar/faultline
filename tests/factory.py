"""Factories for building decoded ``Packet`` objects directly in unit tests.

Detector tests should use these (no bytes, no capture files needed), e.g.::

    from tests.factory import Seq, tcp, run_detector
    s = Seq()
    pkts = [tcp(s, 0.0, "10.0.0.2", 51000, "10.0.0.9", 80, "S", seq=100), ...]
    findings = run_detector(MyDetector(), pkts)
"""

from __future__ import annotations

from faultline.capture.reader import CaptureInfo
from faultline.context import AnalysisContext
from faultline.model import Arp, Dhcp, Dns, DnsRR, Http, Icmp, IcmpInner, Packet, Tcp, Tls, Udp

FLAGS = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10, "U": 0x20, "E": 0x40, "C": 0x80}
BASE_TS = 1_793_500_000.0  # 2026-10-31 (UTC)


class Seq:
    """Frame-number counter."""

    def __init__(self) -> None:
        self.n = 0

    def __call__(self) -> int:
        self.n += 1
        return self.n


def mac_for(ip: str | None) -> str:
    if not ip:
        return "02:00:00:00:00:01"
    parts = [int(x) for x in ip.split(".")] if "." in ip else [0, 0, 0, hash(ip) & 0xFF]
    return "02:00:%02x:%02x:%02x:%02x" % tuple(parts[-4:])


def base(seq: Seq, t: float, src=None, dst=None, *, eth_src=None, eth_dst=None, ttl=64, ip_id=0,
         df=True, wirelen=60, proto=None) -> Packet:
    p = Packet(seq(), BASE_TS + t, wirelen, wirelen, 1)
    p.eth_src = eth_src or mac_for(src)
    p.eth_dst = eth_dst or mac_for(dst)
    if src is not None:
        p.ethertype = 0x0800 if ":" not in src else 0x86DD
        p.ip_ver = 6 if ":" in src else 4
        p.src, p.dst, p.ttl, p.ip_id, p.df, p.proto = src, dst, ttl, ip_id, df, proto
        p.ip_len = max(20, wirelen - 14)
    return p


def tcp(seq: Seq, t: float, src: str, sport: int, dst: str, dport: int, flags: str = "A", *,
        sq: int = 0, ack: int = 0, win: int = 65535, plen: int = 0, mss=None, wscale=None,
        sack_perm=False, sacks=None, **kw) -> Packet:
    kw.setdefault("wirelen", 54 + plen)
    p = base(seq, t, src, dst, proto=6, **kw)
    fl = 0 if flags in ("", "NULL") else sum(FLAGS[c] for c in flags)
    p.tcp = Tcp(sport, dport, sq & 0xFFFFFFFF, ack & 0xFFFFFFFF, fl, win, 20, plen)
    p.tcp.mss, p.tcp.wscale, p.tcp.sack_perm, p.tcp.sacks = mss, wscale, sack_perm, sacks
    p.payload_len = plen
    return p


def udp(seq: Seq, t: float, src: str, sport: int, dst: str, dport: int, plen: int = 32, **kw) -> Packet:
    kw.setdefault("wirelen", 42 + plen)
    p = base(seq, t, src, dst, proto=17, **kw)
    p.udp = Udp(sport, dport, plen)
    p.payload_len = plen
    return p


def arp(seq: Seq, t: float, op: int, sha: str, spa: str, tha: str = "00:00:00:00:00:00", tpa: str = "0.0.0.0",
        eth_src=None, eth_dst=None) -> Packet:
    p = Packet(seq(), BASE_TS + t, 42, 42, 1)
    p.eth_src = eth_src or sha
    p.eth_dst = eth_dst or ("ff:ff:ff:ff:ff:ff" if op == 1 else tha)
    p.ethertype = 0x0806
    p.arp = Arp(op, sha, spa, tha, tpa)
    return p


def dns_query(seq: Seq, t: float, src: str, dst: str, qid: int, qname: str, qtype: int = 1, sport: int = 53000, **kw) -> Packet:
    p = udp(seq, t, src, sport, dst, 53, plen=17 + len(qname), **kw)
    d = Dns()
    d.id, d.qr, d.rd, d.qname, d.qtype = qid, False, True, qname, qtype
    p.dns = d
    return p


def dns_response(seq: Seq, t: float, src: str, dst: str, qid: int, qname: str, answers=(("A", "93.184.216.34", 300),),
                 rcode: int = 0, qtype: int = 1, dport: int = 53000, **kw) -> Packet:
    p = udp(seq, t, src, 53, dst, dport, plen=40 + len(qname), **kw)
    d = Dns()
    d.id, d.qr, d.rd, d.ra, d.rcode, d.qname, d.qtype = qid, True, True, True, rcode, qname, qtype
    types = {"A": 1, "NS": 2, "CNAME": 5, "TXT": 16, "AAAA": 28}
    d.answers = [DnsRR(qname, types.get(rt, 1), ttl, data) for rt, data, ttl in answers]
    d.ancount = len(d.answers)
    p.dns = d
    return p


def dhcp(seq: Seq, t: float, msg_type: int, xid: int, chaddr: str, src: str = "0.0.0.0", dst: str = "255.255.255.255",
         *, server_id=None, yiaddr="0.0.0.0", routers=(), dns_servers=(), requested_ip=None, hostname=None,
         eth_src=None, eth_dst=None) -> Packet:
    client_side = msg_type in (1, 3, 4, 7, 8)
    p = udp(seq, t, src, 68 if client_side else 67, dst, 67 if client_side else 68, plen=300,
            eth_src=eth_src or (chaddr if client_side else None), eth_dst=eth_dst or "ff:ff:ff:ff:ff:ff")
    d = Dhcp()
    d.op = 1 if client_side else 2
    d.xid, d.chaddr, d.msg_type, d.server_id, d.yiaddr = xid, chaddr, msg_type, server_id, yiaddr
    d.routers, d.dns_servers, d.requested_ip, d.hostname = list(routers), list(dns_servers), requested_ip, hostname
    p.dhcp = d
    return p


def icmp(seq: Seq, t: float, src: str, dst: str, type_: int, code: int = 0, *, mtu=None, gateway=None, inner=None,
         echo_id=None, echo_seq=None, **kw) -> Packet:
    p = base(seq, t, src, dst, proto=1, **kw)
    i = Icmp(False, type_, code)
    i.mtu, i.gateway, i.echo_id, i.echo_seq = mtu, gateway, echo_id, echo_seq
    if inner is not None:
        i.inner = IcmpInner(**inner) if isinstance(inner, dict) else inner
    p.icmp = i
    return p


def http_request(seq: Seq, t: float, src, sport, dst, dport=80, method="GET", host="example.com", path="/", **kw) -> Packet:
    p = tcp(seq, t, src, sport, dst, dport, "PA", plen=200, **kw)
    h = Http()
    h.is_request, h.method, h.host, h.path = True, method, host, path
    p.http = h
    return p


def http_response(seq: Seq, t: float, src, sport, dst, dport, status=200, reason="OK", **kw) -> Packet:
    kw.setdefault("plen", 600)
    p = tcp(seq, t, src, sport, dst, dport, "PA", **kw)
    h = Http()
    h.is_request, h.status, h.reason = False, status, reason
    p.http = h
    return p


def tls_hello(seq: Seq, t: float, src, sport, dst, dport=443, sni="example.com", version=0x0303, **kw) -> Packet:
    p = tcp(seq, t, src, sport, dst, dport, "PA", plen=517, **kw)
    tl = Tls()
    tl.record_version, tl.handshake_types, tl.client_version, tl.sni = 0x0301, [1], version, sni
    tl.supported_versions = [0x0304, 0x0303] if version == 0x0303 else [version]
    p.tls = tl
    return p


def run_detector(detector, packets, ctx: AnalysisContext | None = None):
    """Feed packets through the host table + one detector; return its findings."""
    if ctx is None:
        ctx = AnalysisContext(CaptureInfo(name="test.pcap"))
    for p in packets:
        ctx.observe(p)
        detector.on_packet(p, ctx)
    return detector.finalize(ctx)
