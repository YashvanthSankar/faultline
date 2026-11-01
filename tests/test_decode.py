"""Tests for the hand-written packet decoder (faultline.capture.decode)."""

from __future__ import annotations

import os
import random
import shutil
import socket
import struct
import subprocess
import time

import pytest

from faultline.capture.decode import decode, decode_bytes
from faultline.capture.reader import Frame
from faultline.model import Packet

# --------------------------------------------------------------------------- #
# Frame builders
# --------------------------------------------------------------------------- #

MAC_A = bytes.fromhex("001122334455")
MAC_B = bytes.fromhex("66778899aabb")


def eth(payload: bytes, etype: int = 0x0800, dst=MAC_B, src=MAC_A, vlans=()) -> bytes:
    hdr = dst + src
    for vid in vlans:
        hdr += struct.pack("!HH", 0x8100, vid)
    return hdr + struct.pack("!H", etype) + payload


def ip4(payload: bytes, proto: int, src="10.0.0.1", dst="10.0.0.2", ttl=64, ip_id=0x1234,
        flags=0x4000, frag_off=0, total_len=None, ihl=5) -> bytes:
    opts = b"\x00" * ((ihl - 5) * 4)
    tl = (ihl * 4 + len(payload)) if total_len is None else total_len
    hdr = struct.pack("!BBHHHBBH4s4s", (4 << 4) | ihl, 0, tl, ip_id, flags | (frag_off // 8), ttl, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return hdr + opts + payload


def ip6(payload: bytes, nh: int, src="2001:db8::1", dst="2001:db8::2", hlim=64, plen=None) -> bytes:
    pl = len(payload) if plen is None else plen
    return struct.pack("!IHBB16s16s", 6 << 28, pl, nh, hlim,
                       socket.inet_pton(socket.AF_INET6, src), socket.inet_pton(socket.AF_INET6, dst)) + payload


def tcp(payload: bytes = b"", sport=12345, dport=80, seq=1, ack=0, flags=0x18, win=65535, options=b"") -> bytes:
    options += b"\x00" * (-len(options) % 4)
    doff = 5 + len(options) // 4
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, doff << 4, flags, win, 0, 0) + options + payload


def udp(payload: bytes, sport, dport, ulen=None) -> bytes:
    return struct.pack("!HHHH", sport, dport, (8 + len(payload)) if ulen is None else ulen, 0) + payload


def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"


def dns_query(qname="www.example.com", qtype=1, qid=0xBEEF) -> bytes:
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + dns_name(qname) + struct.pack("!HH", qtype, 1)


def rr(name: bytes, rtype: int, rdata: bytes, ttl=300) -> bytes:
    return name + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata


def tls_record(ctype: int, body: bytes, version=0x0301) -> bytes:
    return struct.pack("!BHH", ctype, version, len(body)) + body


def tls_ext(etype: int, body: bytes) -> bytes:
    return struct.pack("!HH", etype, len(body)) + body


def client_hello(sni="example.com", versions=(0x0304, 0x0303)) -> bytes:
    sni_b = sni.encode()
    sni_ext = tls_ext(0, struct.pack("!HBH", len(sni_b) + 3, 0, len(sni_b)) + sni_b)
    sv = b"".join(struct.pack("!H", v) for v in versions)
    sv_ext = tls_ext(43, bytes([len(sv)]) + sv)
    exts = sni_ext + sv_ext
    body = (struct.pack("!H", 0x0303) + b"\x11" * 32 + b"\x00"  # version, random, sid len
            + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"  # ciphers, compression
            + struct.pack("!H", len(exts)) + exts)
    return b"\x01" + len(body).to_bytes(3, "big") + body


def server_hello(selected=0x0304) -> bytes:
    exts = tls_ext(43, struct.pack("!H", selected))
    body = (struct.pack("!H", 0x0303) + b"\x22" * 32 + b"\x00" + b"\x13\x01" + b"\x00"
            + struct.pack("!H", len(exts)) + exts)
    return b"\x02" + len(body).to_bytes(3, "big") + body


def all_slot_values(pkt: Packet):
    """Yield every stored value (recursively through layer objects) for secret checks."""
    stack = [pkt]
    seen = set()
    while stack:
        obj = stack.pop()
        if id(obj) in seen:
            continue
        seen.add(id(obj))
        for slot in getattr(type(obj), "__slots__", ()):
            v = getattr(obj, slot, None)
            yield v
            if hasattr(type(v), "__slots__"):
                stack.append(v)
            elif isinstance(v, (list, tuple)):
                stack.extend(v)


# --------------------------------------------------------------------------- #
# L2
# --------------------------------------------------------------------------- #


def test_ethernet_vlan_arp():
    arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, MAC_A, socket.inet_aton("10.0.0.1"),
                      b"\x00" * 6, socket.inet_aton("10.0.0.9"))
    pkt = decode_bytes(eth(arp, etype=0x0806, vlans=(100, 200)))
    assert pkt.malformed is None
    assert pkt.eth_src == "00:11:22:33:44:55" and pkt.eth_dst == "66:77:88:99:aa:bb"
    assert pkt.vlan == 100 and pkt.ethertype == 0x0806
    assert pkt.arp and pkt.arp.op == 1 and pkt.arp.spa == "10.0.0.1" and pkt.arp.tpa == "10.0.0.9"
    assert pkt.arp.sha == "00:11:22:33:44:55"
    assert "who-has" in pkt.summary()


def test_too_many_vlans_malformed():
    pkt = decode_bytes(eth(b"\x00" * 30, vlans=(1, 2, 3, 4, 5)))
    assert pkt.malformed and "vlan" in pkt.malformed


def test_unknown_linktype_no_layers():
    pkt = decode_bytes(b"\x01" * 40, linktype=9999)
    assert pkt.malformed is None and pkt.src is None and pkt.eth_src is None


def test_sll_and_null_linktypes():
    seg = tcp(b"", sport=1, dport=2)
    sll = struct.pack("!HHH8sH", 0, 1, 6, MAC_A + b"\x00\x00", 0x0800) + ip4(seg, 6)
    pkt = decode_bytes(sll, linktype=113)
    assert pkt.eth_src == "00:11:22:33:44:55" and pkt.tcp and pkt.tcp.dport == 2
    sll2 = struct.pack("!HHIHBB8s", 0x0800, 0, 1, 1, 0, 6, MAC_A + b"\x00\x00") + ip4(seg, 6)
    pkt = decode_bytes(sll2, linktype=276)
    assert pkt.tcp and pkt.src == "10.0.0.1"
    for af_bytes in (struct.pack("<I", 2), struct.pack(">I", 2)):
        pkt = decode_bytes(af_bytes + ip4(seg, 6), linktype=0)
        assert pkt.tcp and pkt.ip_ver == 4 and pkt.malformed is None
    pkt = decode_bytes(struct.pack("<I", 30) + ip6(seg, 6), linktype=108)
    assert pkt.ip_ver == 6 and pkt.tcp
    pkt = decode_bytes(ip6(seg, 6), linktype=101)
    assert pkt.ip_ver == 6 and pkt.src == "2001:db8::1"


# --------------------------------------------------------------------------- #
# IP / TCP / UDP
# --------------------------------------------------------------------------- #


def test_ipv4_tcp_options():
    opts = (b"\x02\x04\x05\xb4" + b"\x01\x03\x03\x07" + b"\x04\x02"
            + b"\x08\x0a" + struct.pack("!II", 111, 222)
            + b"\x05\x0a" + struct.pack("!II", 1000, 2000))
    seg = tcp(b"hello", sport=40000, dport=443, flags=0x02 | 0x40 | 0x80, options=opts)
    frame = eth(ip4(seg, 6))
    pkt = decode(Frame(7, 1.5, len(frame), 1, frame))
    assert pkt.malformed is None and pkt.no == 7
    assert pkt.src == "10.0.0.1" and pkt.dst == "10.0.0.2" and pkt.ttl == 64 and pkt.ip_id == 0x1234
    assert pkt.df is True and pkt.mf is False and pkt.frag_off == 0 and pkt.proto == 6
    t = pkt.tcp
    assert t.sport == 40000 and t.dport == 443 and t.syn and t.flags & 0xC0 == 0xC0
    assert t.mss == 1460 and t.wscale == 7 and t.sack_perm and t.tsval == 111 and t.tsecr == 222
    assert t.sacks == [(1000, 2000)]
    assert t.hlen == 20 + len(opts) + (-len(opts) % 4) and t.plen == 5 and pkt.payload_len == 5
    assert pkt.ip_len == len(seg)


def test_ipv4_padding_and_fragments():
    seg = tcp(b"ab", dport=80)
    frame = eth(ip4(seg, 6)) + b"\x00" * 20  # Ethernet padding
    pkt = decode_bytes(frame)
    assert pkt.tcp.plen == 2 and pkt.malformed is None
    # later fragment: no L4
    pkt = decode_bytes(eth(ip4(b"\x00" * 16, 6, flags=0x2000, frag_off=8)))
    assert pkt.tcp is None and pkt.mf and pkt.frag_off == 8
    # snapped capture: plen from IP length
    full = eth(ip4(tcp(b"x" * 100), 6))
    pkt = decode_bytes(full[:60])
    assert pkt.tcp and pkt.tcp.plen == 100
    # total_len < IHL*4 -> malformed but src kept
    pkt = decode_bytes(eth(ip4(seg, 6, total_len=10)))
    assert pkt.malformed and pkt.src == "10.0.0.1"


def test_ipv6_ext_header_tcp():
    seg = tcp(b"zz", dport=22)
    hbh = struct.pack("!BB", 6, 0) + b"\x01\x04\x00\x00\x00\x00"  # next=TCP, len 0 (8 bytes)
    pkt = decode_bytes(eth(ip6(hbh + seg, 0), etype=0x86DD))
    assert pkt.malformed is None and pkt.ip_ver == 6 and pkt.proto == 6
    assert pkt.src == "2001:db8::1" and pkt.ttl == 64 and pkt.tcp.dport == 22 and pkt.tcp.plen == 2
    # fragment header with nonzero offset: no L4
    frag = struct.pack("!BBHI", 6, 0, 8 * 100, 0xABCD)
    pkt = decode_bytes(eth(ip6(frag + seg, 44), etype=0x86DD))
    assert pkt.tcp is None and pkt.frag_off == 800 and pkt.ip_id == 0xABCD


def test_udp_length_sanity():
    pkt = decode_bytes(eth(ip4(udp(b"abc", 1000, 2000), 17)))
    assert pkt.udp.plen == 3 and pkt.payload_len == 3 and pkt.malformed is None
    pkt = decode_bytes(eth(ip4(udp(b"abc", 1000, 2000, ulen=500), 17)))
    assert pkt.udp and pkt.malformed and "udp" in pkt.malformed


# --------------------------------------------------------------------------- #
# DNS
# --------------------------------------------------------------------------- #


def test_dns_query():
    pkt = decode_bytes(eth(ip4(udp(dns_query("WWW.Example.COM"), 5555, 53), 17)))
    d = pkt.dns
    assert d and not d.qr and d.rd and d.qname == "www.example.com" and d.qtype == 1 and d.id == 0xBEEF
    assert d.transport == "udp" and pkt.malformed is None


def test_dns_compressed_response():
    q = dns_name("www.example.com")
    hdr = struct.pack("!HHHHHH", 0xBEEF, 0x8180, 1, 3, 0, 0)
    msg = hdr + q + struct.pack("!HH", 1, 1)
    ptr_q = b"\xc0\x0c"  # -> offset 12 (qname)
    msg += rr(ptr_q, 5, b"\x03web" + b"\xc0\x10")  # CNAME web.example.com (pointer to "example.com")
    cname_off = len(hdr) + len(q) + 4 + 2 + 10  # offset of the CNAME rdata
    msg += rr(struct.pack("!H", 0xC000 | cname_off), 1, socket.inet_aton("93.184.216.34"))
    msg += rr(struct.pack("!H", 0xC000 | cname_off), 28, socket.inet_pton(socket.AF_INET6, "2606:2800::1"))
    pkt = decode_bytes(eth(ip4(udp(msg, 53, 5555), 17)))
    d = pkt.dns
    assert d and d.qr and d.ancount == 3 and len(d.answers) == 3 and pkt.malformed is None
    assert d.answers[0].rtype == 5 and d.answers[0].data == "web.example.com" and d.answers[0].name == "www.example.com"
    assert d.answers[1].name == "web.example.com" and d.answers[1].data == "93.184.216.34"
    assert d.answers[2].data == "2606:2800::1" and d.answers[2].ttl == 300
    assert "93.184.216.34" in pkt.summary()


def test_dns_over_tcp():
    msg = dns_query()
    pkt = decode_bytes(eth(ip4(tcp(struct.pack("!H", len(msg)) + msg, dport=53), 6)))
    assert pkt.dns and pkt.dns.transport == "tcp" and pkt.dns.qname == "www.example.com"
    # incomplete message in segment -> not parsed, not malformed
    pkt = decode_bytes(eth(ip4(tcp(struct.pack("!H", len(msg) + 50) + msg, dport=53), 6)))
    assert pkt.dns is None and pkt.tcp and pkt.malformed is None


def test_dns_pointer_loop_and_junk():
    hdr = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    pkt = decode_bytes(eth(ip4(udp(hdr + b"\xc0\x0c" + b"\x00\x01\x00\x01", 1, 53), 17)))
    assert pkt.dns is None and pkt.udp is not None and pkt.malformed.startswith("dns:")
    # forward pointer
    pkt = decode_bytes(eth(ip4(udp(hdr + b"\xc0\x20" + b"\x00" * 40, 1, 53), 17)))
    assert pkt.dns is None and pkt.malformed.startswith("dns:")
    # non-printable label and TXT
    hdr = struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0)
    q = b"\x03a\x00b" + b"\x00" + struct.pack("!HH", 16, 1)
    msg = hdr + q + rr(b"\xc0\x0c", 16, b"\x05hi\x01th")
    pkt = decode_bytes(eth(ip4(udp(msg, 53, 1), 17)))
    assert pkt.dns.qname == "a\\x00b" and pkt.dns.answers[0].data == "hi\\x01th"


# --------------------------------------------------------------------------- #
# DHCP
# --------------------------------------------------------------------------- #


def test_dhcp_offer():
    fixed = struct.pack("!BBBBIHH4s4s4s4s16s", 2, 1, 6, 0, 0xDEADBEEF, 0, 0, b"\x00" * 4,
                        socket.inet_aton("192.168.1.50"), socket.inet_aton("192.168.1.1"), b"\x00" * 4,
                        MAC_A + b"\x00" * 10)
    fixed += b"\x00" * 192 + b"\x63\x82\x53\x63"
    opts = (b"\x35\x01\x02" + b"\x36\x04" + socket.inet_aton("192.168.1.1") + b"\x01\x04" + socket.inet_aton("255.255.255.0")
            + b"\x03\x04" + socket.inet_aton("192.168.1.1") + b"\x06\x08" + socket.inet_aton("8.8.8.8") + socket.inet_aton("1.1.1.1")
            + b"\x33\x04" + struct.pack("!I", 86400) + b"\x0c\x05ho\x01st" + b"\x00" + b"\xff")
    pkt = decode_bytes(eth(ip4(udp(fixed + opts, 67, 68), 17)))
    d = pkt.dhcp
    assert d and pkt.malformed is None and d.op == 2 and d.xid == 0xDEADBEEF and d.msg_type == 2
    assert d.chaddr == "00:11:22:33:44:55" and d.yiaddr == "192.168.1.50" and d.siaddr == "192.168.1.1"
    assert d.server_id == "192.168.1.1" and d.subnet_mask == "255.255.255.0" and d.routers == ["192.168.1.1"]
    assert d.dns_servers == ["8.8.8.8", "1.1.1.1"] and d.lease_time == 86400 and d.hostname == "host"
    assert "OFFER" in pkt.summary()


# --------------------------------------------------------------------------- #
# ICMP
# --------------------------------------------------------------------------- #


def test_icmp_frag_needed_with_inner():
    inner = ip4(struct.pack("!HH", 5555, 443) + b"\x00" * 4, 6, src="10.1.1.1", dst="10.2.2.2", ip_id=77, ttl=3)
    icmp = struct.pack("!BBHHH", 3, 4, 0, 0, 1400) + inner
    pkt = decode_bytes(eth(ip4(icmp, 1, src="10.9.9.9")))
    i = pkt.icmp
    assert i and not i.v6 and i.is_frag_needed and i.mtu == 1400 and pkt.malformed is None
    assert i.inner.src == "10.1.1.1" and i.inner.dst == "10.2.2.2" and i.inner.proto == 6
    assert i.inner.sport == 5555 and i.inner.dport == 443 and i.inner.ip_id == 77 and i.inner.ttl == 3
    assert pkt.tcp is None and pkt.udp is None and pkt.sport is None
    # echo and redirect
    pkt = decode_bytes(eth(ip4(struct.pack("!BBHHH", 8, 0, 0, 42, 7), 1)))
    assert pkt.icmp.is_echo_request and pkt.icmp.echo_id == 42 and pkt.icmp.echo_seq == 7
    pkt = decode_bytes(eth(ip4(struct.pack("!BBH", 5, 1, 0) + socket.inet_aton("10.0.0.254") + inner, 1)))
    assert pkt.icmp.gateway == "10.0.0.254" and pkt.icmp.inner.dport == 443


def test_icmpv6_packet_too_big():
    inner = ip6(struct.pack("!HH", 1, 2) + b"\x00" * 4, 17, src="2001:db8::a", dst="2001:db8::b", hlim=9)
    icmp = struct.pack("!BBHI", 2, 0, 0, 1280) + inner
    pkt = decode_bytes(eth(ip6(icmp, 58), etype=0x86DD))
    i = pkt.icmp
    assert i.v6 and i.is_frag_needed and i.mtu == 1280 and pkt.malformed is None
    assert i.inner.src == "2001:db8::a" and i.inner.proto == 17 and i.inner.sport == 1 and i.inner.ttl == 9


# --------------------------------------------------------------------------- #
# TLS / HTTP / creds
# --------------------------------------------------------------------------- #


def test_tls_client_hello():
    rec = tls_record(22, client_hello("Example.COM", (0x0304, 0x0303)))
    pkt = decode_bytes(eth(ip4(tcp(rec, dport=443), 6)))
    t = pkt.tls
    assert t and pkt.malformed is None and t.record_version == 0x0301 and t.handshake_types == [1]
    assert t.client_version == 0x0303 and t.sni == "Example.COM" and t.supported_versions == [0x0304, 0x0303]
    assert "SNI=Example.COM" in pkt.summary()
    # ServerHello
    pkt = decode_bytes(eth(ip4(tcp(tls_record(22, server_hello(0x0304)), sport=443), 6)))
    assert pkt.tls.handshake_types == [2] and pkt.tls.supported_versions == [0x0304] and pkt.tls.client_version is None
    # partial record: no malformed
    pkt = decode_bytes(eth(ip4(tcp(rec[:40], dport=443), 6)))
    assert pkt.tls and pkt.malformed is None


def test_tls_alert():
    pkt = decode_bytes(eth(ip4(tcp(tls_record(21, b"\x02\x28", 0x0303), sport=443), 6)))
    assert pkt.tls.alerts == [(2, 40)] and pkt.malformed is None
    pkt = decode_bytes(eth(ip4(tcp(tls_record(21, b"\x00" * 26, 0x0303), sport=443), 6)))
    assert pkt.tls.alerts == []  # encrypted alert


def test_http_basic_auth_no_secret():
    secret = "dXNlcjpzM2NyM3Q="
    req = (f"GET /login?user=bob#frag HTTP/1.1\r\nHost: Example.org\r\nUser-Agent: curl/8\r\n"
           f"Authorization: Basic {secret}\r\n\r\n").encode()
    pkt = decode_bytes(eth(ip4(tcp(req, dport=8080), 6)))
    h = pkt.http
    assert h and h.is_request and h.method == "GET" and h.path == "/login" and h.host == "Example.org"
    assert h.user_agent == "curl/8" and pkt.cred == "HTTP Basic" and pkt.malformed is None
    for v in all_slot_values(pkt):
        assert not (isinstance(v, str) and (secret in v or "bob" in v or "user=" in v))
    resp = b"HTTP/1.1 404 Not Found\r\nServer: x\r\n\r\n"
    pkt = decode_bytes(eth(ip4(tcp(resp, sport=80), 6)))
    assert not pkt.http.is_request and pkt.http.status == 404 and pkt.http.reason == "Not Found"
    pkt = decode_bytes(eth(ip4(tcp(b"GET / HTTP/1.1\r\nAuthorization: Digest abc\r\n\r\n", dport=80), 6)))
    assert pkt.cred is None


def test_cleartext_creds():
    cases = [
        (tcp(b"PASS hunter2\r\n", dport=21), "FTP"),
        (tcp(b"PASS hunter2\r\n", dport=110), "POP3"),
        (tcp(b"a001 LOGIN bob hunter2\r\n", dport=143), "IMAP"),
        (tcp(b"AUTH PLAIN AGJvYgBodW50ZXIy\r\n", dport=587), "SMTP AUTH"),
        (tcp(b"\xff\xfd\x01login: ", sport=23, dport=5000), "Telnet"),
        (tcp(b"USER bob\r\n", dport=21), None),
    ]
    for seg, expected in cases:
        pkt = decode_bytes(eth(ip4(seg, 6)))
        assert pkt.cred == expected, expected
        for v in all_slot_values(pkt):
            assert not (isinstance(v, str) and "hunter2" in v)


# --------------------------------------------------------------------------- #
# Robustness
# --------------------------------------------------------------------------- #


def _sample_frames():
    yield eth(ip4(tcp(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", dport=80, options=b"\x02\x04\x05\xb4\x08\x0a" + b"\x00" * 8), 6))
    yield eth(ip4(udp(dns_query(), 5555, 53), 17))
    yield eth(ip4(tcp(tls_record(22, client_hello()), dport=443), 6))
    yield eth(ip6(tcp(b"x"), 6), etype=0x86DD)
    yield eth(ip4(struct.pack("!BBHHH", 3, 4, 0, 0, 1400) + ip4(tcp(), 6), 1))


def test_truncation_never_raises():
    for frame in _sample_frames():
        for i in range(len(frame) + 1):
            pkt = decode_bytes(frame[:i])
            assert isinstance(pkt, Packet)
            assert not (pkt.malformed and pkt.malformed.startswith("internal")), pkt.malformed


def test_random_fuzz_never_raises():
    rng = random.Random(1234)
    templates = list(_sample_frames())
    for n in range(2000):
        if n % 2:
            data = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 200)))
        else:  # mutate a valid frame
            data = bytearray(rng.choice(templates))
            for _ in range(rng.randint(1, 6)):
                data[rng.randrange(len(data))] = rng.getrandbits(8)
            data = bytes(data)
        lt = rng.choice([1, 1, 1, 0, 101, 108, 113, 228, 229, 276, 500])
        pkt = decode_bytes(data, linktype=lt)
        assert isinstance(pkt, Packet)
        assert not (pkt.malformed and pkt.malformed.startswith("internal")), (pkt.malformed, data.hex(), lt)
        pkt.summary()


def test_benchmark_prints_rate():
    frame = eth(ip4(tcp(b"x" * 100, dport=443, flags=0x10), 6))
    f = Frame(1, 0.0, len(frame), 1, frame)
    n = 20000
    t0 = time.perf_counter()
    for _ in range(n):
        decode(f)
    dt = time.perf_counter() - t0
    print(f"\ndecode rate: {n / dt:,.0f} packets/s (simple TCP)")


@pytest.mark.skipif(not shutil.which("tcpdump") and not os.path.exists("/usr/sbin/tcpdump"), reason="no tcpdump")
def test_tcpdump_crosscheck(tmp_path):
    from faultline.capture.writer import PcapWriter

    frames = [eth(ip4(tcp(b"abc", sport=40000, dport=443, seq=100, flags=0x02, options=b"\x02\x04\x05\xb4"), 6)),
              eth(ip4(udp(dns_query("www.example.com"), 5555, 53), 17))]
    path = tmp_path / "x.pcap"
    with PcapWriter(str(path)) as w:
        for i, fr in enumerate(frames):
            w.write(float(i), fr)
    exe = shutil.which("tcpdump") or "/usr/sbin/tcpdump"
    try:
        out = subprocess.run([exe, "-nn", "-r", str(path)], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        pytest.skip("tcpdump not runnable")
    if "10.0.0.1" not in out:
        pytest.skip("tcpdump produced no output (permissions?)")
    pkts = [decode_bytes(fr) for fr in frames]
    assert "10.0.0.1.40000 > 10.0.0.2.443" in out and pkts[0].tcp.sport == 40000 and pkts[0].tcp.dport == 443
    assert "mss 1460" in out and pkts[0].tcp.mss == 1460
    assert "A? www.example.com" in out and pkts[1].dns.qname == "www.example.com"
