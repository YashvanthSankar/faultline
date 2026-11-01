"""Core data model shared by the reader, decoders, detectors and reports.

Packet-level classes use ``__slots__`` because a capture can hold millions of
frames. Payload bytes are deliberately *not* retained: detectors work on
decoded header fields only, which keeps memory bounded and avoids holding
user data (privacy by design).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any


# --------------------------------------------------------------------------- #
# Decoded protocol layers
# --------------------------------------------------------------------------- #


class Arp:
    __slots__ = ("op", "sha", "spa", "tha", "tpa")

    def __init__(self, op: int, sha: str, spa: str, tha: str, tpa: str):
        self.op = op  # 1 = request, 2 = reply
        self.sha = sha
        self.spa = spa
        self.tha = tha
        self.tpa = tpa

    @property
    def is_gratuitous(self) -> bool:
        """Sender announces its own address (spa == tpa)."""
        return self.spa == self.tpa and self.spa != "0.0.0.0"

    @property
    def is_probe(self) -> bool:
        """RFC 5227 address probe (sender IP 0.0.0.0)."""
        return self.op == 1 and self.spa == "0.0.0.0"


class Tcp:
    __slots__ = (
        "sport", "dport", "seq", "ack", "flags", "win", "hlen", "plen",
        "mss", "wscale", "sack_perm", "sacks", "tsval", "tsecr",
    )

    FIN, SYN, RST, PSH, ACK, URG, ECE, CWR = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80

    def __init__(self, sport, dport, seq, ack, flags, win, hlen, plen):
        self.sport = sport
        self.dport = dport
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.win = win  # raw (unscaled) window
        self.hlen = hlen
        self.plen = plen  # payload length
        self.mss = None
        self.wscale = None
        self.sack_perm = False
        self.sacks = None  # list[tuple[int, int]] | None
        self.tsval = None
        self.tsecr = None

    syn = property(lambda s: bool(s.flags & Tcp.SYN))
    fin = property(lambda s: bool(s.flags & Tcp.FIN))
    rst = property(lambda s: bool(s.flags & Tcp.RST))
    psh = property(lambda s: bool(s.flags & Tcp.PSH))
    has_ack = property(lambda s: bool(s.flags & Tcp.ACK))
    urg = property(lambda s: bool(s.flags & Tcp.URG))

    def flag_str(self) -> str:
        names = "FSRPAUEC"
        return "".join(n for i, n in enumerate(names) if self.flags & (1 << i)) or "NULL"


class Udp:
    __slots__ = ("sport", "dport", "plen")

    def __init__(self, sport, dport, plen):
        self.sport = sport
        self.dport = dport
        self.plen = plen


class IcmpInner:
    """The original datagram quoted inside an ICMP error message."""

    __slots__ = ("src", "dst", "proto", "sport", "dport", "ip_id", "ttl")

    def __init__(self, src, dst, proto, sport=None, dport=None, ip_id=None, ttl=None):
        self.src = src
        self.dst = dst
        self.proto = proto
        self.sport = sport
        self.dport = dport
        self.ip_id = ip_id
        self.ttl = ttl


class Icmp:
    __slots__ = ("v6", "type", "code", "mtu", "gateway", "inner", "echo_id", "echo_seq")

    def __init__(self, v6: bool, type_: int, code: int):
        self.v6 = v6
        self.type = type_
        self.code = code
        self.mtu = None  # next-hop MTU (v4 frag-needed / v6 packet-too-big)
        self.gateway = None  # redirect target
        self.inner = None  # IcmpInner | None
        self.echo_id = None
        self.echo_seq = None

    @property
    def is_echo_request(self) -> bool:
        return (self.type == 8) if not self.v6 else (self.type == 128)

    @property
    def is_echo_reply(self) -> bool:
        return (self.type == 0) if not self.v6 else (self.type == 129)

    @property
    def is_unreachable(self) -> bool:
        return (self.type == 3) if not self.v6 else (self.type == 1)

    @property
    def is_frag_needed(self) -> bool:
        return (self.type == 3 and self.code == 4) if not self.v6 else (self.type == 2)

    @property
    def is_time_exceeded(self) -> bool:
        return (self.type == 11) if not self.v6 else (self.type == 3)

    @property
    def is_redirect(self) -> bool:
        return (self.type == 5) if not self.v6 else (self.type == 137)


class DnsRR:
    __slots__ = ("name", "rtype", "ttl", "data")

    def __init__(self, name: str, rtype: int, ttl: int, data: str):
        self.name = name
        self.rtype = rtype
        self.ttl = ttl
        self.data = data  # textual rendering (IP, target name, TXT ...)


class Dns:
    __slots__ = (
        "id", "qr", "opcode", "aa", "tc", "rd", "ra", "rcode",
        "qname", "qtype", "answers", "ancount", "nscount", "arcount", "transport",
    )

    def __init__(self):
        self.id = 0
        self.qr = False  # False = query, True = response
        self.opcode = 0
        self.aa = self.tc = self.rd = self.ra = False
        self.rcode = 0
        self.qname = ""
        self.qtype = 0
        self.answers: list[DnsRR] = []
        self.ancount = self.nscount = self.arcount = 0
        self.transport = "udp"


class Dhcp:
    __slots__ = (
        "op", "xid", "chaddr", "ciaddr", "yiaddr", "siaddr", "msg_type", "server_id",
        "requested_ip", "routers", "dns_servers", "lease_time", "subnet_mask", "hostname",
    )

    DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK, RELEASE, INFORM = 1, 2, 3, 4, 5, 6, 7, 8
    NAMES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}

    def __init__(self):
        self.op = 0
        self.xid = 0
        self.chaddr = ""
        self.ciaddr = self.yiaddr = self.siaddr = "0.0.0.0"
        self.msg_type = 0
        self.server_id = None
        self.requested_ip = None
        self.routers: list[str] = []
        self.dns_servers: list[str] = []
        self.lease_time = None
        self.subnet_mask = None
        self.hostname = None

    @property
    def type_name(self) -> str:
        return self.NAMES.get(self.msg_type, f"TYPE{self.msg_type}")


class Tls:
    __slots__ = ("record_version", "handshake_types", "client_version", "sni", "alerts", "supported_versions")

    def __init__(self):
        self.record_version = 0
        self.handshake_types: list[int] = []
        self.client_version = None
        self.sni = None
        self.alerts: list[tuple[int, int]] = []  # (level, description) - only for cleartext alerts
        self.supported_versions: list[int] = []


class Http:
    __slots__ = ("is_request", "method", "host", "path", "status", "reason", "user_agent")

    def __init__(self):
        self.is_request = True
        self.method = None
        self.host = None
        self.path = None  # query string stripped (privacy)
        self.status = None
        self.reason = None
        self.user_agent = None


class Packet:
    """One decoded frame. ``no`` is the 1-based frame number (matches Wireshark)."""

    __slots__ = (
        "no", "ts", "caplen", "wirelen", "linktype",
        "eth_src", "eth_dst", "ethertype", "vlan", "arp",
        "ip_ver", "src", "dst", "ttl", "ip_id", "df", "mf", "frag_off", "ip_len", "proto",
        "tcp", "udp", "icmp", "dns", "dhcp", "tls", "http", "cred",
        "payload_len", "malformed",
    )

    def __init__(self, no: int, ts: float, caplen: int, wirelen: int, linktype: int):
        self.no = no
        self.ts = ts
        self.caplen = caplen
        self.wirelen = wirelen
        self.linktype = linktype
        self.eth_src = self.eth_dst = None
        self.ethertype = None
        self.vlan = None
        self.arp = None
        self.ip_ver = None
        self.src = self.dst = None
        self.ttl = None
        self.ip_id = None
        self.df = self.mf = False
        self.frag_off = 0
        self.ip_len = 0  # IP payload length (v4: total_len - IHL; v6: upper-layer length)
        self.proto = None
        self.tcp = self.udp = self.icmp = None
        self.dns = self.dhcp = self.tls = self.http = None
        self.cred = None  # e.g. "FTP", "HTTP Basic" - the secret itself is never stored
        self.payload_len = 0
        self.malformed = None  # reason string if any layer failed to decode

    # convenience ---------------------------------------------------------
    @property
    def sport(self):
        l4 = self.tcp or self.udp
        return l4.sport if l4 else None

    @property
    def dport(self):
        l4 = self.tcp or self.udp
        return l4.dport if l4 else None

    def summary(self) -> str:
        """Short one-line description (like a Wireshark Info column)."""
        if self.arp:
            a = self.arp
            if a.op == 1:
                return f"ARP who-has {a.tpa}? tell {a.spa} ({a.sha})"
            return f"ARP {a.spa} is-at {a.sha} (to {a.tpa})"
        if self.src is None:
            return f"L2 frame {self.eth_src} → {self.eth_dst} type 0x{(self.ethertype or 0):04x}"
        base = f"{self.src} → {self.dst}"
        if self.dhcp:
            d = self.dhcp
            extra = f" offer {d.yiaddr}" if d.msg_type in (2, 5) else ""
            return f"DHCP {d.type_name} xid=0x{d.xid:08x} client {d.chaddr}{extra} {base}"
        if self.dns:
            d = self.dns
            if d.qr:
                ans = ", ".join(a.data for a in d.answers[:3])
                rc = DNS_RCODES.get(d.rcode, str(d.rcode))
                return f"DNS response 0x{d.id:04x} {d.qname} {rc}{(' → ' + ans) if ans else ''} ({base})"
            return f"DNS query 0x{d.id:04x} {DNS_TYPES.get(d.qtype, d.qtype)} {d.qname} ({base})"
        if self.tcp:
            t = self.tcp
            s = f"TCP {self.src}:{t.sport} → {self.dst}:{t.dport} [{t.flag_str()}] seq={t.seq} ack={t.ack} win={t.win} len={t.plen}"
            if self.http:
                h = self.http
                s += f" HTTP {h.method} {h.host or ''}{h.path or ''}" if h.is_request else f" HTTP {h.status} {h.reason or ''}"
            elif self.tls and self.tls.sni:
                s += f" TLS ClientHello SNI={self.tls.sni}"
            elif self.tls and self.tls.alerts:
                s += " TLS Alert"
            return s
        if self.icmp:
            i = self.icmp
            s = f"ICMP{'v6' if i.v6 else ''} type={i.type} code={i.code} {base}"
            if i.inner:
                s += f" (about {i.inner.src} → {i.inner.dst})"
            if i.mtu:
                s += f" mtu={i.mtu}"
            return s
        if self.udp:
            return f"UDP {self.src}:{self.udp.sport} → {self.dst}:{self.udp.dport} len={self.udp.plen}"
        return f"IP proto {self.proto} {base}"


DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #


class Category(str, Enum):
    FAULT = "fault"
    MISCONFIG = "misconfig"
    ATTACK = "attack"
    INFO = "info"


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Indicator:
    """A piece of evidence that supports one hypothesis.

    ``weight`` ~ 0.5 (weak hint) .. 3 (near-conclusive).
    """

    text: str
    supports: Category
    weight: float = 1.0

    def to_dict(self) -> dict:
        return {"text": self.text, "supports": self.supports.value, "weight": self.weight}


@dataclass
class Variant:
    """Category-specific wording. A finding may carry one Variant per hypothesis
    (e.g. *Duplicate IP address* vs *ARP spoofing*); the verdict engine picks the
    variant of the winning hypothesis and keeps the others as "why not" context.
    """

    title: str
    summary: str
    explanation: str
    cause: str
    fix: list[str]
    analogy: str = ""
    mitre: str | None = None
    severity: Severity | None = None  # override severity for this reading


@dataclass
class Finding:
    kind: str
    category: Category  # detector's default hypothesis
    severity: Severity
    title: str
    summary: str
    explanation: str
    cause: str
    fix: list[str]
    technical: str = ""
    analogy: str = ""
    mitre: str | None = None
    hosts: list[str] = field(default_factory=list)
    packets: list[int] = field(default_factory=list)
    packet_total: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    metrics: dict[str, Any] = field(default_factory=dict)
    indicators: list[Indicator] = field(default_factory=list)
    variants: dict[Category, Variant] = field(default_factory=dict)
    # filled by the engine
    id: str = ""
    confidence: float = 0.0
    scores: dict[str, float] = field(default_factory=dict)
    alternatives: list[dict] = field(default_factory=list)
    symptom_of: str | None = None
    incident: str | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "category": self.category.value,
            "severity": int(self.severity),
            "severity_name": self.severity.name.lower(),
            "confidence": round(self.confidence, 2),
            "title": self.title,
            "summary": self.summary,
            "explanation": self.explanation,
            "analogy": self.analogy,
            "cause": self.cause,
            "fix": list(self.fix),
            "technical": self.technical,
            "mitre": self.mitre,
            "hosts": list(self.hosts),
            "packets": list(self.packets),
            "packet_total": self.packet_total,
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "metrics": dict(self.metrics),
            "indicators": [i.to_dict() for i in self.indicators],
            "scores": {k: round(v, 2) for k, v in self.scores.items()},
            "alternatives": list(self.alternatives),
            "symptom_of": self.symptom_of,
            "incident": self.incident,
        }


@dataclass
class Incident:
    id: str
    title: str
    category: Category
    severity: Severity
    story: str
    root_cause: str  # finding id
    findings: list[str]
    hosts: list[str]
    first_ts: float | None
    last_ts: float | None
    first_fix: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category.value,
            "severity": int(self.severity),
            "severity_name": self.severity.name.lower(),
            "story": self.story,
            "root_cause": self.root_cause,
            "findings": list(self.findings),
            "hosts": list(self.hosts),
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "first_fix": list(self.first_fix),
        }
