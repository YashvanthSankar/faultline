"""Mutation-fuzzing core shared by ``tests/test_fuzz.py`` and ``scripts/fuzz.py``.

* ``seed_captures()`` builds small, valid pcap / pcapng files from hand-made
  frames (Ethernet, VLAN, ARP, IPv4, IPv6, TCP, UDP, DNS, DHCP, ICMP, ICMPv6,
  TLS ClientHello, HTTP with Basic auth, Linux SLL) using only ``struct``.
* ``mutate(data, rng)`` applies seeded random mutations (bit flips, interesting
  byte values, truncation, length-field inflation, chunk duplication / deletion).
* ``run_case(path)`` pushes a file through every pipeline stage that is
  importable right now: reader -> decode -> engine.analyze, and reports timing.

Only ``CaptureError`` may escape the pipeline. Anything else is a crash.
"""

from __future__ import annotations

import gzip
import importlib
import io
import os
import random
import struct
import time
from dataclasses import dataclass, field

from faultline.capture.reader import CaptureError, CaptureReader, Limits
from faultline.capture.writer import PcapNgWriter, PcapWriter

# --------------------------------------------------------------------------- #
# Raw frame builders (byte-exact, standard library only)
# --------------------------------------------------------------------------- #

def mac(s: str) -> bytes:
    return bytes.fromhex(s.replace(":", ""))


def ip4(s: str) -> bytes:
    return bytes(int(x) for x in s.split("."))


def csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def eth(dst: str, src: str, ethertype: int, payload: bytes, vlan: int | None = None) -> bytes:
    hdr = mac(dst) + mac(src)
    if vlan is not None:
        hdr += struct.pack("!HH", 0x8100, vlan)
    return hdr + struct.pack("!H", ethertype) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes, ttl: int = 64, ident: int = 1, flags_frag: int = 0x4000) -> bytes:
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident, flags_frag, ttl, proto, 0, ip4(src), ip4(dst))
    hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
    return hdr + payload


def ipv6(src: bytes, dst: bytes, nxt: int, payload: bytes) -> bytes:
    return struct.pack("!IHBB", 0x60000000, len(payload), nxt, 64) + src + dst + payload


def tcp(sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"", opts: bytes = b"", win: int = 65535) -> bytes:
    opts += b"\x00" * ((4 - len(opts) % 4) % 4)
    doff = 5 + len(opts) // 4
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, doff << 4, flags, win, 0, 0) + opts + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"


def dns_query(qid: int, name: str, qtype: int = 1) -> bytes:
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", qtype, 1)


def dns_response(qid: int, name: str, answer_ip: str, ttl: int = 300) -> bytes:
    q = dns_name(name) + struct.pack("!HH", 1, 1)
    # compressed pointer to the question name at offset 12
    rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + ip4(answer_ip)
    return struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0) + q + rr


def dhcp(msg_type: int, xid: int, chaddr: str, yiaddr: str = "0.0.0.0", opts: bytes = b"") -> bytes:
    op = 1 if msg_type in (1, 3, 4, 7, 8) else 2
    fixed = struct.pack("!BBBBIHH4s4s4s4s", op, 1, 6, 0, xid, 0, 0x8000, ip4("0.0.0.0"), ip4(yiaddr), ip4("0.0.0.0"), ip4("0.0.0.0"))
    fixed += mac(chaddr) + b"\x00" * 10 + b"\x00" * 64 + b"\x00" * 128
    body = fixed + b"\x63\x82\x53\x63" + bytes([53, 1, msg_type]) + opts + b"\xff"
    return body


def icmp(type_: int, code: int, rest: bytes, payload: bytes = b"") -> bytes:
    pkt = struct.pack("!BBH", type_, code, 0) + rest + payload
    return pkt[:2] + struct.pack("!H", csum(pkt)) + pkt[4:]


def tls_client_hello(sni: str) -> bytes:
    ext_sni_name = struct.pack("!BH", 0, len(sni)) + sni.encode()
    ext_sni = struct.pack("!HH", 0, len(ext_sni_name) + 2) + struct.pack("!H", len(ext_sni_name)) + ext_sni_name
    ext_ver = struct.pack("!HHB", 43, 5, 4) + struct.pack("!HH", 0x0304, 0x0303)
    exts = ext_sni + ext_ver
    body = struct.pack("!H", 0x0303) + b"\x11" * 32 + b"\x00" + struct.pack("!H", 4) + b"\x13\x01\xc0\x2f"
    body += b"\x01\x00" + struct.pack("!H", len(exts)) + exts
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return struct.pack("!BHH", 22, 0x0301, len(hs)) + hs


# --------------------------------------------------------------------------- #
# Seeds
# --------------------------------------------------------------------------- #

GW, HOST, HOST2, ATT, INET = "192.168.1.1", "192.168.1.15", "192.168.1.16", "192.168.1.66", "93.184.216.34"
M_GW, M_HOST, M_HOST2, M_ATT, M_BC = "00:11:22:aa:bb:01", "00:11:22:aa:bb:0f", "00:11:22:aa:bb:10", "de:ad:be:ef:00:66", "ff:ff:ff:ff:ff:ff"
V6_HOST = bytes.fromhex("fe80000000000000021122fffeaabb0f")
V6_ALL = bytes.fromhex("ff020000000000000000000000000001")


def seed_frames() -> list[tuple[float, bytes]]:
    """A realistic little conversation; every protocol we decode appears once."""
    t = 1_700_000_000.0
    f: list[tuple[float, bytes]] = []
    # ARP request / reply (+ a spoofed reply)
    f.append((t, eth(M_BC, M_HOST, 0x0806, struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + mac(M_HOST) + ip4(HOST) + mac("00:00:00:00:00:00") + ip4(GW))))
    f.append((t + 0.001, eth(M_HOST, M_GW, 0x0806, struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + mac(M_GW) + ip4(GW) + mac(M_HOST) + ip4(HOST))))
    f.append((t + 0.002, eth(M_HOST, M_ATT, 0x0806, struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + mac(M_ATT) + ip4(GW) + mac(M_HOST) + ip4(HOST))))
    # DHCP discover (broadcast)
    f.append((t + 0.01, eth(M_BC, M_HOST2, 0x0800, ipv4("0.0.0.0", "255.255.255.255", 17, udp(68, 67, dhcp(1, 0x1234, M_HOST2, opts=bytes([12, 4]) + b"host"))))))
    f.append((t + 0.02, eth(M_HOST2, M_GW, 0x0800, ipv4(GW, HOST2, 17, udp(67, 68, dhcp(2, 0x1234, M_HOST2, HOST2, opts=bytes([54, 4]) + ip4(GW) + bytes([3, 4]) + ip4(GW) + bytes([6, 4]) + ip4(GW)))))))
    # DNS query / response
    f.append((t + 0.1, eth(M_GW, M_HOST, 0x0800, ipv4(HOST, GW, 17, udp(53000, 53, dns_query(0xBEEF, "www.example.com"))))))
    f.append((t + 0.12, eth(M_HOST, M_GW, 0x0800, ipv4(GW, HOST, 17, udp(53, 53000, dns_response(0xBEEF, "www.example.com", INET))))))
    # TCP handshake + TLS ClientHello
    f.append((t + 0.2, eth(M_GW, M_HOST, 0x0800, ipv4(HOST, INET, 6, tcp(50000, 443, 1000, 0, 0x02, opts=b"\x02\x04\x05\xb4\x01\x03\x03\x07\x04\x02")))))
    f.append((t + 0.25, eth(M_HOST, M_GW, 0x0800, ipv4(INET, HOST, 6, tcp(443, 50000, 5000, 1001, 0x12, opts=b"\x02\x04\x05\xb4"), ttl=52))))
    f.append((t + 0.251, eth(M_GW, M_HOST, 0x0800, ipv4(HOST, INET, 6, tcp(50000, 443, 1001, 5001, 0x10)))))
    f.append((t + 0.26, eth(M_GW, M_HOST, 0x0800, ipv4(HOST, INET, 6, tcp(50000, 443, 1001, 5001, 0x18, tls_client_hello("www.example.com"))))))
    # HTTP GET with Basic auth (credential detection, never extraction) + 500 response
    http_req = b"GET /login HTTP/1.1\r\nHost: intranet.example.com\r\nAuthorization: Basic YWRtaW46aHVudGVyMg==\r\nUser-Agent: fuzz\r\n\r\n"
    f.append((t + 0.3, eth(M_GW, M_HOST, 0x0800, ipv4(HOST, "10.0.0.5", 6, tcp(50001, 80, 1, 1, 0x18, http_req)))))
    f.append((t + 0.35, eth(M_HOST, M_GW, 0x0800, ipv4("10.0.0.5", HOST, 6, tcp(80, 50001, 1, 1 + len(http_req), 0x18, b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n")))))
    # RST and retransmission
    f.append((t + 0.4, eth(M_GW, M_HOST, 0x0800, ipv4(HOST, INET, 6, tcp(50002, 8080, 1, 0, 0x02)))))
    f.append((t + 0.41, eth(M_HOST, M_GW, 0x0800, ipv4(INET, HOST, 6, tcp(8080, 50002, 0, 2, 0x14)))))
    f.append((t + 0.7, eth(M_GW, M_HOST, 0x0800, ipv4(HOST, INET, 6, tcp(50000, 443, 1001, 5001, 0x18, tls_client_hello("www.example.com"))))))
    # ICMP echo, fragmentation-needed, TTL exceeded (with inner IP header)
    f.append((t + 0.5, eth(M_GW, M_HOST, 0x0800, ipv4(HOST, INET, 1, icmp(8, 0, struct.pack("!HH", 7, 1), b"abcdefgh")))))
    inner = ipv4(HOST, INET, 6, tcp(50000, 443, 1, 0, 0x02))[:28]
    f.append((t + 0.51, eth(M_HOST, M_GW, 0x0800, ipv4(GW, HOST, 1, icmp(3, 4, struct.pack("!HH", 0, 1400), inner)))))
    f.append((t + 0.52, eth(M_HOST, M_GW, 0x0800, ipv4(GW, HOST, 1, icmp(11, 0, b"\x00" * 4, inner)))))
    # fragmented IPv4 datagram
    f.append((t + 0.53, eth(M_GW, M_HOST, 0x0800, ipv4(HOST, INET, 17, b"\x00" * 24, ident=77, flags_frag=0x2000))))
    f.append((t + 0.531, eth(M_GW, M_HOST, 0x0800, ipv4(HOST, INET, 17, b"\x00" * 8, ident=77, flags_frag=0x0003))))
    # IPv6 ICMPv6 router solicitation + UDP DNS over IPv6
    f.append((t + 0.6, eth("33:33:00:00:00:02", M_HOST, 0x86DD, ipv6(V6_HOST, V6_ALL, 58, icmp(133, 0, b"\x00" * 4)))))
    f.append((t + 0.61, eth(M_GW, M_HOST, 0x86DD, ipv6(V6_HOST, bytes.fromhex("20010db8000000000000000000000053"), 17, udp(5353, 53, dns_query(1, "ipv6.example.net", 28))))))
    # VLAN-tagged frame, LLDP-ish unknown ethertype, runt frame
    f.append((t + 0.8, eth(M_GW, M_HOST, 0x0800, ipv4(HOST, GW, 17, udp(1234, 5678, b"hello")), vlan=100)))
    f.append((t + 0.81, eth("01:80:c2:00:00:0e", M_GW, 0x88CC, b"\x02\x07\x04" + mac(M_GW) + b"\x00\x00")))
    f.append((t + 0.82, b"\x00" * 14))
    return f


def sll_frames() -> list[tuple[float, bytes]]:
    """Linux cooked capture (linktype 113) frames carrying IPv4/UDP."""
    t = 1_700_000_100.0
    out = []
    for i in range(4):
        sll = struct.pack("!HHH", 0, 1, 6) + mac(M_HOST) + b"\x00\x00" + struct.pack("!H", 0x0800)
        out.append((t + i * 0.1, sll + ipv4(HOST, GW, 17, udp(53000 + i, 53, dns_query(i, f"h{i}.example.org")))))
    return out


@dataclass
class Seed:
    name: str
    data: bytes


def seed_captures() -> list[Seed]:
    frames = seed_frames()
    seeds: list[Seed] = []

    buf = io.BytesIO()
    with PcapWriter(buf) as w:
        w.write_all(frames)
    seeds.append(Seed("eth.pcap", buf.getvalue()))

    buf = io.BytesIO()
    with PcapWriter(buf, nanos=True) as w:
        w.write_all(frames[:12])
    seeds.append(Seed("eth-ns.pcap", buf.getvalue()))

    buf = io.BytesIO()
    with PcapNgWriter(buf) as w:
        w.write_all(frames)
    seeds.append(Seed("eth.pcapng", buf.getvalue()))

    buf = io.BytesIO()
    with PcapWriter(buf, linktype=113) as w:
        w.write_all(sll_frames())
    seeds.append(Seed("sll.pcap", buf.getvalue()))

    buf = io.BytesIO()
    with PcapWriter(buf, linktype=101) as w:
        for ts, fr in frames:
            if fr[12:14] == b"\x08\x00":
                w.write(ts, fr[14:])
    seeds.append(Seed("raw.pcap", buf.getvalue()))

    seeds.append(Seed("eth.pcap.gz", gzip.compress(seeds[0].data)))
    return seeds


# --------------------------------------------------------------------------- #
# Mutations
# --------------------------------------------------------------------------- #

INTERESTING = (0x00, 0xFF, 0x7F, 0x80, 0x01, 0xFE)
INTERESTING_U16 = (0, 1, 0x7FFF, 0x8000, 0xFFFF, 20, 40, 60, 1500)
INTERESTING_U32 = (0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x10000, 256 * 1024, 16 * 1024 * 1024)

MUTATIONS = ("bitflip", "byte", "u16", "u32", "truncate", "inflate", "dup", "delete", "insert", "multi")


def mutate(data: bytes, rng: random.Random, kind: str | None = None) -> tuple[str, bytes]:
    buf = bytearray(data)
    if not buf:
        return "noop", bytes(buf)
    kind = kind or rng.choice(MUTATIONS)
    n = len(buf)
    if kind == "bitflip":
        for _ in range(rng.randint(1, 8)):
            i = rng.randrange(n)
            buf[i] ^= 1 << rng.randrange(8)
    elif kind == "byte":
        for _ in range(rng.randint(1, 16)):
            buf[rng.randrange(n)] = rng.choice(INTERESTING)
    elif kind == "u16":
        for _ in range(rng.randint(1, 4)):
            i = rng.randrange(max(1, n - 1))
            buf[i : i + 2] = struct.pack(rng.choice("<>") + "H", rng.choice(INTERESTING_U16))
    elif kind == "u32":
        for _ in range(rng.randint(1, 4)):
            i = rng.randrange(max(1, n - 3))
            buf[i : i + 4] = struct.pack(rng.choice("<>") + "I", rng.choice(INTERESTING_U32))
    elif kind == "truncate":
        del buf[rng.randrange(n) :]
    elif kind == "inflate":  # pick a 16/32-bit field and make it huge
        i = rng.randrange(max(1, n - 3))
        width = rng.choice((2, 4))
        val = rng.choice(INTERESTING_U16 if width == 2 else INTERESTING_U32) | rng.choice((0x7F00, 0xFF00, 0x8000))
        buf[i : i + width] = struct.pack(rng.choice("<>") + ("H" if width == 2 else "I"), val & ((1 << (8 * width)) - 1))
    elif kind == "dup":
        a = rng.randrange(n)
        b = min(n, a + rng.randint(1, 128))
        at = rng.randrange(n)
        buf[at:at] = buf[a:b] * rng.randint(1, 3)
    elif kind == "delete":
        a = rng.randrange(n)
        del buf[a : a + rng.randint(1, 64)]
    elif kind == "insert":
        at = rng.randrange(n)
        buf[at:at] = bytes(rng.choice(INTERESTING) for _ in range(rng.randint(1, 64)))
    elif kind == "multi":
        kinds = []
        for _ in range(rng.randint(2, 5)):
            k, b = mutate(bytes(buf), rng, rng.choice(MUTATIONS[:-1]))
            kinds.append(k)
            buf = bytearray(b)
        kind = "multi(" + "+".join(kinds) + ")"
    return kind, bytes(buf)


# --------------------------------------------------------------------------- #
# Pipeline
# --------------------------------------------------------------------------- #

def _optional(module: str, attr: str):
    try:
        return getattr(importlib.import_module(module), attr)
    except Exception:  # module not written yet, or import error in another engineer's WIP
        return None


def stages_available() -> dict[str, bool]:
    return {
        "reader": True,
        "decode": _optional("faultline.capture.decode", "decode") is not None,
        "engine": _optional("faultline.engine", "analyze") is not None,
    }


FUZZ_LIMITS = Limits(max_decompressed_bytes=64 * 1024 * 1024, max_packets=200_000)


@dataclass
class CaseResult:
    name: str
    mutation: str
    size: int
    seconds: float
    packets: int = 0
    decoded: int = 0
    malformed: int = 0
    capture_error: str | None = None
    crash: BaseException | None = None
    stage: str = "reader"
    findings: int | None = None
    extra: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.crash is None


def run_case(path: str, name: str = "", mutation: str = "", run_engine: bool = True) -> CaseResult:
    decode = _optional("faultline.capture.decode", "decode")
    analyze = _optional("faultline.engine", "analyze") if run_engine else None
    options_cls = _optional("faultline.engine", "AnalyzeOptions") if run_engine else None
    res = CaseResult(name=name, mutation=mutation, size=os.path.getsize(path), seconds=0.0)
    t0 = time.perf_counter()
    try:
        reader = CaptureReader(path, FUZZ_LIMITS, display_name="fuzz")
        for frame in reader:
            res.packets += 1
            if decode is not None:
                res.stage = "decode"
                pkt = decode(frame)
                if pkt is not None:
                    res.decoded += 1
                    if getattr(pkt, "malformed", None):
                        res.malformed += 1
                    # exercise the string renderers too (they feed the report)
                    if hasattr(pkt, "summary"):
                        pkt.summary()
        res.stage = "reader" if decode is None else "decode"
        if analyze is not None:
            res.stage = "engine"
            opts = None
            if options_cls is not None:
                try:
                    opts = options_cls()
                except TypeError:
                    opts = None
            report = analyze(path, opts) if opts is not None else analyze(path)
            if hasattr(report, "to_dict"):
                report = report.to_dict()
            if isinstance(report, dict):
                res.findings = len(report.get("findings", []) or [])
                redact = _optional("faultline.report.redact", "redact_report")
                if redact is not None:
                    redact(report)
    except CaptureError as exc:
        res.capture_error = str(exc)
    except BaseException as exc:  # noqa: BLE001 - we want to catch *everything* including RecursionError / MemoryError
        res.crash = exc
    res.seconds = time.perf_counter() - t0
    return res
