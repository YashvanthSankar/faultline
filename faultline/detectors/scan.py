"""Reconnaissance: port scans (TCP SYN / connect / FIN / NULL / Xmas, UDP) and
host / ping sweeps.

How we tell a scan from ordinary busy traffic
---------------------------------------------
* We count **distinct destination ports per (source, target host)** in a
  sliding 60 s window. A browser opening 30 parallel connections uses 30
  *source* ports but a single *destination* port, so it never counts.
* Only *initiating* packets are probes: a TCP SYN without ACK, a TCP packet
  with a flag combination that never occurs in normal TCP (FIN / NULL / Xmas),
  or a UDP datagram that is not a reply to a flow we already saw. A server
  answering from one port to many client ports is therefore never a probe.
* Every probe's outcome is tracked: SYN/ACK (open), RST (closed), silence
  (filtered), and what the *prober* did next: RST straight after the
  SYN/ACK (half-open "SYN scan"), ACK followed by an immediate close with no
  data ("connect scan"), or a real conversation carrying data (normal use:
  passive FTP data channels, P2P, an app talking to several ports). A source
  whose connections mostly carry data is *not* reported.
* Sweeps count **distinct hosts per (source, service)** and must be mostly
  unanswered or walk sequential addresses; destinations the client just
  looked up in DNS (normal browsing to many CDN IPs) and multicast /
  broadcast destinations (SSDP, mDNS, NetBIOS) are excluded.

``scanner_sources(ctx)`` exposes the IPs found scanning so that other
detectors (TCP resets, ICMP unreachables, ...) can attribute their symptoms
to the scan instead of reporting a fault.

Memory: per-pair state is created lazily (a pair that only ever touched one
port is stored as a tiny tuple), all tables are ``BoundedDict``s, so a SYN
flood with millions of spoofed sources stays bounded.
"""

from __future__ import annotations

import ipaddress
from collections import deque

from ..context import is_multicast_or_broadcast, is_private
from ..model import Tcp
from .base import (
    AnalysisContext, BoundedDict, Category, Detector, Evidence, Finding, Indicator, Packet,
    Severity, Variant, fmt_pct, plural, register,
)

__all__ = ["ScanDetector", "scanner_sources", "is_traceroute_port"]

WINDOW = 60.0  # seconds, sliding window for distinct ports / hosts
PORT_THRESHOLD = 25  # distinct ports on one host within WINDOW
STEALTH_THRESHOLD = 5  # FIN / NULL / Xmas probes
SWEEP_THRESHOLD = 20  # distinct hosts on one service within WINDOW
UDP_OFFSET = 65536  # port keys: tcp = port, udp = UDP_OFFSET + port
ECHO = -1  # sweep service key for ICMP echo

SYN, ACK, RST, FIN, PSH, URG = Tcp.SYN, Tcp.ACK, Tcp.RST, Tcp.FIN, Tcp.PSH, Tcp.URG
XMAS = FIN | PSH | URG

WELL_KNOWN = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC",
    135: "MS-RPC", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    1433: "MS-SQL", 1521: "Oracle", 2049: "NFS", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt", 9200: "Elasticsearch", 27017: "MongoDB",
}


def is_traceroute_port(port: int | None) -> bool:
    """Classic UDP traceroute destination ports (33434 + hops x probes)."""
    return port is not None and 33434 <= port <= 33690


def scanner_sources(ctx: AnalysisContext) -> set[str]:
    """IPs that ``ScanDetector`` identified as scanning (port scan or sweep).

    The set lives on the context as ``ctx.scanners`` (created on first use).
    It is filled *incrementally* during the streaming pass (as soon as a
    source crosses a scan threshold, unless its traffic looks benign so far)
    and replaced by the confirmed set in ``ScanDetector.finalize``. Other
    detectors should consult it from their own ``finalize`` - e.g.
    ``if pkt_src in scanner_sources(ctx): # RSTs / port-unreachables caused by
    the scan, not a fault``.
    """
    s = getattr(ctx, "scanners", None)
    if not isinstance(s, set):
        s = set()
        try:
            setattr(ctx, "scanners", s)
        except AttributeError:  # pragma: no cover - slotted context
            pass
    return s


# --------------------------------------------------------------------------- #
# Small bounded structures
# --------------------------------------------------------------------------- #


class _Window:
    """Distinct keys seen within a sliding time window, plus the peak count."""

    __slots__ = ("last", "dq", "peak", "peak_ts")
    CAP = 4096

    def __init__(self) -> None:
        self.last: dict = {}
        self.dq: deque = deque()
        self.peak = 0
        self.peak_ts: float | None = None

    def add(self, key, t: float, width: float) -> int:
        last = self.last
        prev = last.get(key)
        if prev is None:
            if len(last) < self.CAP:
                last[key] = t
                self.dq.append((t, key))
        elif t - prev >= width * 0.25:  # refresh rarely: keeps the deque small
            last[key] = t
            self.dq.append((t, key))
        lim = t - width
        dq = self.dq
        while dq and dq[0][0] < lim:
            ts0, k0 = dq.popleft()
            if last.get(k0) == ts0:
                del last[k0]
        n = len(last)
        if n > self.peak:
            self.peak = n
            self.peak_ts = t
        return n


def _add_capped(s: set, item, cap: int) -> None:
    if len(s) < cap:
        s.add(item)


class _Pair:
    """Probe statistics for one (prober, target host) pair."""

    __slots__ = (
        "src", "dst", "win", "ports", "order", "probes", "first_ts", "last_ts", "open", "closed",
        "udp_closed", "udp_open", "stealth", "half_open", "completed", "connect_close", "with_data",
        "flagged", "ev", "ftp", "syn_probes", "udp_probes", "rate_peak",
    )

    def __init__(self, src: str, dst: str) -> None:
        self.src, self.dst = src, dst
        self.win = _Window()
        self.ports: set[int] = set()
        self.order: list[int] = []  # first probed port keys, in order (capped)
        self.probes = 0
        self.first_ts = self.last_ts = 0.0
        self.open: set[int] = set()  # TCP ports that answered SYN/ACK
        self.closed = 0  # TCP RSTs from the target
        self.udp_closed: set[int] = set()  # UDP ports answered by ICMP port-unreachable
        self.udp_open: set[int] = set()  # UDP ports that replied
        self.stealth = [0, 0, 0, 0]  # FIN, NULL, Xmas, other odd flags
        self.half_open = 0  # SYN/ACK answered with RST by the prober
        self.completed = 0
        self.connect_close = 0  # completed then closed without data
        self.with_data = 0
        self.flagged = False
        self.ev = Evidence()
        self.ftp = False
        self.syn_probes = 0
        self.udp_probes = 0
        self.rate_peak = 0

    @property
    def tcp_ports(self) -> int:
        return sum(1 for p in self.ports if p < UDP_OFFSET)

    @property
    def udp_ports(self) -> int:
        return sum(1 for p in self.ports if p >= UDP_OFFSET)


class _Sweep:
    """Distinct hosts contacted by one source on one service."""

    __slots__ = ("src", "svc", "win", "dsts", "dset", "answered", "probes", "first_ts", "last_ts", "ev", "flagged")

    def __init__(self, src: str, svc: int) -> None:
        self.src, self.svc = src, svc
        self.win = _Window()
        self.dsts: list[str] = []  # distinct, in first-contact order (capped)
        self.dset: set[str] = set()
        self.answered: set[str] = set()
        self.probes = 0
        self.first_ts = self.last_ts = 0.0
        self.ev = Evidence()
        self.flagged = False


# connection-state bits (tracked only for connections the target accepted)
_C_DONE, _C_HALF, _C_DATA, _C_CLOSED = 1, 2, 4, 8


def _svc_name(svc: int) -> str:
    if svc == ECHO:
        return "ping (ICMP echo)"
    if svc >= UDP_OFFSET:
        p = svc - UDP_OFFSET
        return f"UDP port {p}" + (f" ({WELL_KNOWN[p]})" if p in WELL_KNOWN else "")
    return f"TCP port {svc}" + (f" ({WELL_KNOWN[svc]})" if svc in WELL_KNOWN else "")


def _port_label(key: int) -> str:
    return f"{key - UDP_OFFSET}/udp" if key >= UDP_OFFSET else f"{key}/tcp"


def _v4int(ip: str) -> int | None:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return int(a) if a.version == 4 else None


def _sequential_ratio(ips: list[str]) -> float:
    """Fraction of address gaps <= 2 once sorted (1.0 = walking a range)."""
    nums = sorted({n for n in (_v4int(i) for i in ips) if n is not None})
    if len(nums) < 3:
        return 0.0
    close = sum(1 for a, b in zip(nums, nums[1:]) if b - a <= 2)
    return close / (len(nums) - 1)


def _prefix24(ip: str) -> str:
    if "." in ip:
        return ".".join(ip.split(".")[:3]) + ".0/24"
    return ip


# --------------------------------------------------------------------------- #
# Detector
# --------------------------------------------------------------------------- #


@register
class ScanDetector(Detector):
    name = "scan"

    def __init__(self) -> None:
        self.pairs: BoundedDict = BoundedDict(20_000)  # (src, dst) -> (key, ts, no) | _Pair
        self.flagged: dict = {}  # (src, dst) -> _Pair, survives eviction (bounded)
        self.sweeps: BoundedDict = BoundedDict(20_000)  # (src, svc) -> dst | _Sweep
        self.flagged_sweeps: dict = {}
        self.conns: BoundedDict = BoundedDict(50_000)  # (prober, sport, target, dport) -> [pair, bits]
        self.udp_flows: BoundedDict = BoundedDict(100_000)  # (src, sport, dst, dport) -> None
        self.dns_ips: BoundedDict = BoundedDict(100_000)  # IPs learned from DNS answers
        self.stealth_src: BoundedDict = BoundedDict(5_000)  # src -> [count, set(targets), Evidence]
        self._thr_ports = PORT_THRESHOLD
        self._thr_sweep = SWEEP_THRESHOLD
        self._thr_stealth = STEALTH_THRESHOLD
        self._scaled = False

    # ------------------------------------------------------------------ #
    def _scale(self, ctx: AnalysisContext) -> None:
        sc = ctx.config.scale
        self._thr_ports = max(5, round(PORT_THRESHOLD * sc))
        self._thr_sweep = max(5, round(SWEEP_THRESHOLD * sc))
        self._thr_stealth = max(3, round(STEALTH_THRESHOLD * sc))
        self._scaled = True

    def on_packet(self, pkt: Packet, ctx: AnalysisContext) -> None:
        if not self._scaled:
            self._scale(ctx)
        src, dst = pkt.src, pkt.dst
        if src is None or dst is None or src == dst:
            return
        t = pkt.ts if pkt.ts is not None else 0.0
        if pkt.tcp is not None:
            self._on_tcp(pkt, src, dst, t, ctx)
        elif pkt.udp is not None:
            self._on_udp(pkt, src, dst, t, ctx)
        elif pkt.icmp is not None:
            self._on_icmp(pkt, src, dst, t, ctx)

    # -- TCP ------------------------------------------------------------- #
    def _on_tcp(self, pkt: Packet, src: str, dst: str, t: float, ctx: AnalysisContext) -> None:
        tcp = pkt.tcp
        fl = tcp.flags or 0
        sport, dport = tcp.sport, tcp.dport
        if sport is None or dport is None:
            return
        if fl & SYN and not fl & ACK and not fl & (RST | FIN):
            pair = self._probe(src, dst, dport, t, pkt, ctx)
            if pair is not None:
                pair.syn_probes += 1
                if dport == 21:
                    pair.ftp = True
            self._sweep(src, dst, dport, t, pkt, ctx)
            return
        if not fl & (ACK | SYN | RST) and not pkt.malformed:
            # FIN / NULL / Xmas or other flag soup: never sent by a real TCP stack
            if fl == FIN:
                kind = 0
            elif fl == 0:
                kind = 1
            elif fl & XMAS == XMAS:
                kind = 2
            else:
                kind = 3
            pair = self._probe(src, dst, dport, t, pkt, ctx)
            if pair is not None:
                pair.stealth[kind] += 1
            self._stealth(src, dst, dport, kind, pkt, ctx)
            return
        if fl & SYN and fl & (FIN | RST) and not fl & ACK:
            pair = self._probe(src, dst, dport, t, pkt, ctx)
            if pair is not None:
                pair.stealth[3] += 1
            self._stealth(src, dst, dport, 3, pkt, ctx)
            return
        # responses from a target to a prober
        if fl & SYN and fl & ACK:
            pair = self.pairs.get((dst, src))
            if isinstance(pair, _Pair):
                _add_capped(pair.open, sport, 256)
                key = (dst, dport, src, sport)
                if key not in self.conns:
                    self.conns[key] = [pair, 0]
            self._answered(dst, src, sport, False)
            return
        if fl & RST:
            entry = self.conns.get((src, sport, dst, dport))
            if entry is not None:  # prober resets a connection the target accepted
                bits = entry[1]
                if not bits & (_C_DONE | _C_HALF):
                    entry[1] = bits | _C_HALF
                    entry[0].half_open += 1
                elif bits & _C_DONE and not bits & (_C_DATA | _C_CLOSED):
                    entry[1] = bits | _C_CLOSED
                    entry[0].connect_close += 1
                return
            pair = self.pairs.get((dst, src))
            if isinstance(pair, _Pair) and dport is not None:
                pair.closed += 1
            self._answered(dst, src, sport, False)
            return
        # plain ACK / data / FIN-ACK on a tracked connection
        entry = self.conns.get((src, sport, dst, dport))
        fwd = entry is not None
        if entry is None:
            entry = self.conns.get((dst, dport, src, sport))
        if entry is None:
            return
        bits = entry[1]
        if fwd and not bits & (_C_DONE | _C_HALF):
            entry[1] = bits = bits | _C_DONE
            entry[0].completed += 1
        if (tcp.plen or 0) > 0 and not bits & _C_DATA and bits & _C_DONE:
            entry[1] = bits = bits | _C_DATA
            entry[0].with_data += 1
        elif fwd and fl & FIN and bits & _C_DONE and not bits & (_C_DATA | _C_CLOSED):
            entry[1] = bits | _C_CLOSED
            entry[0].connect_close += 1

    # -- UDP ------------------------------------------------------------- #
    def _on_udp(self, pkt: Packet, src: str, dst: str, t: float, ctx: AnalysisContext) -> None:
        u = pkt.udp
        sport, dport = u.sport, u.dport
        if sport is None or dport is None:
            return
        if pkt.dns is not None and pkt.dns.qr:
            for rr in pkt.dns.answers[:16]:
                if rr.rtype in (1, 28) and rr.data:
                    self.dns_ips[rr.data] = None
        rkey = (dst, dport, src, sport)
        if rkey in self.udp_flows:  # a reply
            pair = self.pairs.get((dst, src))
            if isinstance(pair, _Pair):
                _add_capped(pair.udp_open, sport, 256)
            self._answered(dst, src, UDP_OFFSET + sport, True)
            return
        key = (src, sport, dst, dport)
        if key in self.udp_flows:
            return  # same flow again: not a new probe
        self.udp_flows[key] = None
        if (sport == dport or is_traceroute_port(dport) or is_multicast_or_broadcast(dst)
                or (sport < 1024 <= dport) or pkt.dhcp is not None or (pkt.dns is not None and pkt.dns.qr)):
            return  # symmetric protocols (NTP, NetBIOS), traceroute, discovery, server replies
        pair = self._probe(src, dst, UDP_OFFSET + dport, t, pkt, ctx)
        if pair is not None:
            pair.udp_probes += 1
        self._sweep(src, dst, UDP_OFFSET + dport, t, pkt, ctx)

    # -- ICMP ------------------------------------------------------------ #
    def _on_icmp(self, pkt: Packet, src: str, dst: str, t: float, ctx: AnalysisContext) -> None:
        ic = pkt.icmp
        if ic.is_echo_request:
            if not is_multicast_or_broadcast(dst) and pkt.eth_dst != "ff:ff:ff:ff:ff:ff":
                self._sweep(src, dst, ECHO, t, pkt, ctx)
        elif ic.is_echo_reply:
            self._answered(dst, src, ECHO, False)
        elif ic.is_unreachable and ic.inner is not None:
            inner = ic.inner
            port_unreach = (ic.code == 3) if not ic.v6 else (ic.code == 4)
            if port_unreach and inner.proto == 17 and inner.dport is not None:
                pair = self.pairs.get((inner.src, inner.dst))
                if isinstance(pair, _Pair):
                    _add_capped(pair.udp_closed, inner.dport, 4096)
                    pair.ev.add(pkt)
                self._answered(inner.src, inner.dst, UDP_OFFSET + inner.dport, True)

    # ------------------------------------------------------------------ #
    def _probe(self, src: str, dst: str, key: int, t: float, pkt: Packet, ctx: AnalysisContext) -> _Pair | None:
        """Record one probe of port ``key`` on ``dst``; returns the pair once it has >= 2 ports."""
        pk = (src, dst)
        pair = self.flagged.get(pk) or self.pairs.get(pk)
        if pair is None:
            self.pairs[pk] = (key, t, pkt.no)
            return None
        if not isinstance(pair, _Pair):
            k0, t0, no0 = pair
            if k0 == key:
                return None
            p = _Pair(src, dst)
            p.first_ts = t0
            p.probes = 1
            p.ports.add(k0)
            p.order.append(k0)
            p.win.add(k0, t0, WINDOW)
            p.ev.packets.append(no0)
            p.ev.total = 1
            p.ev.first_ts = p.ev.last_ts = t0
            self.pairs[pk] = pair = p
        else:
            self.pairs.move_to_end(pk)
        pair.probes += 1
        pair.last_ts = max(pair.last_ts, t)
        if key not in pair.ports and len(pair.ports) < 8192:
            pair.ports.add(key)
            if len(pair.order) < 512:
                pair.order.append(key)
        pair.ev.add(pkt)
        n = pair.win.add(key, t, WINDOW)
        if not pair.flagged and n >= self._thr_ports:
            pair.flagged = True
            if len(self.flagged) < 2_000:
                self.flagged[pk] = pair
            if pair.with_data * 2 < max(1, len(pair.ports)):
                scanner_sources(ctx).add(src)
        return pair

    def _stealth(self, src: str, dst: str, dport: int, kind: int, pkt: Packet, ctx: AnalysisContext) -> None:
        st = self.stealth_src.get(src)
        if st is None:
            st = self.stealth_src[src] = [0, set(), Evidence(), [0, 0, 0, 0]]
        st[0] += 1
        st[3][kind] += 1
        _add_capped(st[1], (dst, dport), 1024)
        st[2].add(pkt)
        if st[0] >= self._thr_stealth and len(st[1]) >= 3:
            scanner_sources(ctx).add(src)

    def _sweep(self, src: str, dst: str, svc: int, t: float, pkt: Packet, ctx: AnalysisContext) -> None:
        if is_multicast_or_broadcast(dst):
            return
        sk = (src, svc)
        sw = self.flagged_sweeps.get(sk) or self.sweeps.get(sk)
        if sw is None:
            self.sweeps[sk] = (dst, t, pkt.no)
            return
        if not isinstance(sw, _Sweep):
            d0, t0, no0 = sw
            if d0 == dst:
                return
            s = _Sweep(src, svc)
            s.first_ts = t0
            s.probes = 1
            s.dsts.append(d0)
            s.dset.add(d0)
            s.win.add(d0, t0, WINDOW)
            s.ev.packets.append(no0)
            s.ev.total = 1
            s.ev.first_ts = s.ev.last_ts = t0
            self.sweeps[sk] = sw = s
        else:
            self.sweeps.move_to_end(sk)
        sw.probes += 1
        sw.last_ts = max(sw.last_ts, t)
        n = sw.win.add(dst, t, WINDOW)
        if dst not in sw.dset and len(sw.dsts) < 4096:
            sw.dsts.append(dst)
            sw.dset.add(dst)
        sw.ev.add(pkt)
        if not sw.flagged and n >= self._thr_sweep:
            sw.flagged = True
            if len(self.flagged_sweeps) < 2_000:
                self.flagged_sweeps[sk] = sw

    def _answered(self, prober: str, target: str, svc: int, udp: bool) -> None:
        sw = self.flagged_sweeps.get((prober, svc)) or self.sweeps.get((prober, svc))
        if isinstance(sw, _Sweep) and len(sw.answered) < 4096:
            sw.answered.add(target)

    # ------------------------------------------------------------------ #
    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        if not self._scaled:
            self._scale(ctx)
        confirmed: set[str] = set()
        findings: list[Finding] = []
        # --- port scans, grouped per source ---
        by_src: dict[str, list[_Pair]] = {}
        seen: set[int] = set()
        for pair in list(self.flagged.values()) + [p for p in self.pairs.values() if isinstance(p, _Pair) and p.flagged]:
            if id(pair) in seen:
                continue
            seen.add(id(pair))
            by_src.setdefault(pair.src, []).append(pair)
        stealth_srcs = {s for s, st in self.stealth_src.items() if st[0] >= self._thr_stealth and len(st[1]) >= 3}
        for s in stealth_srcs:
            by_src.setdefault(s, [])
        for src, pairs in by_src.items():
            f = self._port_finding(src, pairs, ctx)
            if f is not None:
                findings.append(f)
                confirmed.add(src)
        # --- sweeps, grouped per source ---
        sweeps_by_src: dict[str, list[_Sweep]] = {}
        seen.clear()
        for sw in list(self.flagged_sweeps.values()) + [s for s in self.sweeps.values() if isinstance(s, _Sweep) and s.flagged]:
            if id(sw) in seen:
                continue
            seen.add(id(sw))
            sweeps_by_src.setdefault(sw.src, []).append(sw)
        for src, sws in sweeps_by_src.items():
            f = self._sweep_finding(src, sws, ctx)
            if f is not None:
                findings.append(f)
                confirmed.add(src)
        sc = scanner_sources(ctx)
        sc.clear()
        sc.update(confirmed)
        return findings

    # ------------------------------------------------------------------ #
    def _port_finding(self, src: str, pairs: list[_Pair], ctx: AnalysisContext) -> Finding | None:
        st = self.stealth_src.get(src)
        stealth = [0, 0, 0, 0]
        if st is not None and st[0] >= self._thr_stealth and len(st[1]) >= 3:
            stealth = list(st[3])
        n_stealth = sum(stealth)
        probes = sum(p.probes for p in pairs)
        ports = sum(len(p.ports) for p in pairs)
        tcp_ports = sum(p.tcp_ports for p in pairs)
        udp_ports = sum(p.udp_ports for p in pairs)
        opened = sum(len(p.open) for p in pairs)
        closed = sum(p.closed for p in pairs)
        half = sum(p.half_open for p in pairs)
        completed = sum(p.completed for p in pairs)
        cclose = sum(p.connect_close for p in pairs)
        data = sum(p.with_data for p in pairs)
        udp_closed = sum(len(p.udp_closed) for p in pairs)
        udp_open = sum(len(p.udp_open) for p in pairs)
        ftp = any(p.ftp for p in pairs)
        peak = max((p.win.peak for p in pairs), default=0)
        data_ratio = data / ports if ports else 0.0

        # ---- benign look-alikes -------------------------------------------------
        if n_stealth == 0:
            if data_ratio >= 0.5:
                return None  # real conversations (passive FTP, P2P, multi-port apps)
            if udp_ports > tcp_ports and udp_closed < 5 and udp_open * 5 > udp_ports:
                return None  # UDP app with many answered ports (VoIP / WebRTC / games)
            if peak < self._thr_ports:
                return None
        ev = Evidence()
        for p in sorted(pairs, key=lambda x: -len(x.ports)):
            ev.merge(p.ev)
        if st is not None and n_stealth:
            ev.merge(st[2])
            probes = max(probes, st[0])
            ports = max(ports, len(st[1]))
            if not pairs:
                tcp_ports = len({p for _, p in st[1]})
        first = min([p.first_ts for p in pairs] + ([st[2].first_ts] if st and st[2].first_ts else []), default=0.0)
        last = max([p.last_ts for p in pairs] + ([st[2].last_ts] if st and st[2].last_ts else []), default=0.0)
        dur = max(0.001, last - first)
        rate = probes / dur if dur > 0.001 else float(probes)

        # ---- technique ----------------------------------------------------------
        if n_stealth >= max(probes - n_stealth, 1) or (n_stealth and tcp_ports == 0 and udp_ports == 0):
            names = ["FIN", "NULL", "Xmas", "odd-flag"]
            technique = names[max(range(4), key=lambda i: stealth[i])] + " scan"
        elif udp_ports > tcp_ports:
            technique = "UDP scan"
        elif half and half >= cclose:
            technique = "SYN (half-open) scan"
        elif cclose:
            technique = "TCP connect scan"
        else:
            technique = "TCP SYN scan"
        targets = sorted(pairs, key=lambda x: -len(x.ports))
        target_ips = [p.dst for p in targets][:10]
        if not target_ips and st is not None:
            target_ips = sorted({d for d, _ in st[1]})[:10]
        n_targets = max(len(pairs), len({d for d, _ in st[1]}) if st else 0)
        open_list = sorted({f"{p.dst}:{o}" for p in targets for o in sorted(p.open)[:20]})[:10]
        if udp_ports > tcp_ports:
            open_list = sorted({f"{p.dst}:{o}/udp" for p in targets for o in sorted(p.udp_open)[:20]})[:10]
        wk = sorted({k for p in pairs for k in p.ports if k < UDP_OFFSET and k in WELL_KNOWN})
        tgt = target_ips[0] if len(target_ips) == 1 else f"{n_targets} hosts"
        thr = self._thr_ports

        # ---- indicators ---------------------------------------------------------
        ind: list[Indicator] = []
        if ports:
            w = 3.0 if peak >= 4 * thr else (2.5 if peak >= 2 * thr else 2.0)
            ind.append(Indicator(
                f"{src} tried {plural(ports, 'different port')} on {tgt} (up to {peak} within {int(WINDOW)} s); "
                "normal programs talk to one or two ports per server", Category.ATTACK, w))
        if n_stealth:
            ind.append(Indicator(
                f"{plural(n_stealth, 'probe')} used TCP flag combinations (FIN/NULL/Xmas) that real "
                "applications never send; they exist only to sneak past firewalls", Category.ATTACK, 3.0))
        if half:
            ind.append(Indicator(
                f"{plural(half, 'connection')} were answered by the server and then immediately reset by {src} "
                "before finishing the handshake (classic half-open 'SYN scan')", Category.ATTACK, 2.0))
        if cclose:
            ind.append(Indicator(
                f"{plural(cclose, 'connection')} were opened and closed again without sending any data "
                "(a 'connect scan' just checking whether the door opens)", Category.ATTACK, 1.5))
        if udp_closed >= 5:
            ind.append(Indicator(
                f"The target answered {plural(udp_closed, 'UDP port')} with 'port unreachable', i.e. "
                f"{src} was checking closed UDP ports one by one", Category.ATTACK, 1.5))
        if rate >= 10 and probes >= thr:
            ind.append(Indicator(f"Probes arrived at {rate:.0f} per second, far faster than a person or "
                                 "normal application opens connections", Category.ATTACK, 1.0))
        if len(wk) >= 5:
            ind.append(Indicator(
                f"The probed ports include {len(wk)} well-known services ({', '.join(WELL_KNOWN[k] for k in wk[:6])}...), "
                "the usual shopping list of a scanner", Category.ATTACK, 1.0))
        unanswered = max(0, ports - opened - closed - udp_closed - udp_open)
        if ports >= thr and unanswered / max(ports, 1) >= 0.7:
            ind.append(Indicator(f"{fmt_pct(unanswered / ports)} of probed ports never answered (filtered or closed)",
                                 Category.ATTACK, 0.5))
        if opened:
            ind.append(Indicator(f"{plural(opened, 'open port')} were discovered ({', '.join(open_list[:5])})",
                                 Category.ATTACK, 0.5))
        if data:
            ind.append(Indicator(
                f"{data} of {ports} connections completed and carried real data, which is what normal use looks like",
                Category.FAULT, round(min(2.5, 5 * data_ratio), 2)))
        if ftp:
            ind.append(Indicator("An FTP control connection exists between these hosts; passive FTP opens a new "
                                 "high port for every file", Category.FAULT, 1.0))
        if not data and not n_stealth:
            ind.append(Indicator("No connection was used to exchange data: nothing here looks like a working "
                                 "application that is merely misconfigured", Category.ATTACK, 0.5))

        sev = Severity.MEDIUM
        if opened or n_stealth or ports >= 100 or (target_ips and is_private(target_ips[0]) and is_private(src)):
            sev = Severity.HIGH
        open_txt = (f" It found {plural(opened, 'open port')}: {', '.join(open_list[:6])}." if opened else
                    " No open ports were confirmed.")
        title = f"Port scan: {src} is checking which services are open on {tgt}"
        summary = (f"{src} probed {plural(max(ports, n_stealth), 'port')} on {tgt} in {dur:.1f} s "
                   f"({rate:.0f} probes/s) using a {technique}.")
        explanation = (
            f"A port is like a numbered door on a computer; each service (web, file sharing, remote login) "
            f"listens behind one. {src} knocked on {plural(max(ports, n_stealth), 'door')} in a short time to "
            f"find out which ones open, which is the usual first step before an attack (reconnaissance).{open_txt}"
        )
        cause = (f"A port-scanning tool (such as nmap or masscan) running on {src}: either a security test, "
                 "a curious user, or malware / an attacker mapping the network.")
        fix = [
            f"Identify the device behind {src}: run `arp -a` (or check the DHCP lease list / switch MAC table) "
            "to find its MAC address and owner.",
            "If it is not an authorised security scan, disconnect it or block it at the firewall "
            f"(e.g. `iptables -I INPUT -s {src} -j DROP`) and check it for malware.",
            f"On the target(s), list what is listening (`netstat -an` / `ss -tlnp`) and close services that are "
            "not needed, especially any port the scan found open.",
            "Review firewall and server logs for logins or exploits from this address after the scan.",
            "If it is your own vulnerability scanner, schedule it and add it to an allow-list so it is expected.",
        ]
        technical = (
            f"{technique} from {src} against {n_targets} host(s) ({', '.join(target_ips[:5])}): {probes} probes, "
            f"{tcp_ports} TCP + {udp_ports} UDP distinct ports, peak {peak} distinct ports/{int(WINDOW)} s "
            f"(threshold {thr}); stealth FIN/NULL/Xmas/other = {stealth[0]}/{stealth[1]}/{stealth[2]}/{stealth[3]}; "
            f"responses: {opened} SYN/ACK (open), {closed} RST (closed), {udp_closed} ICMP port-unreachable, "
            f"{udp_open} UDP replies; prober behaviour: {half} half-open resets, {completed} completed handshakes, "
            f"{cclose} closed without data, {data} carried data. Rate {rate:.1f} probes/s over {dur:.2f} s."
        )
        variants = {
            Category.ATTACK: Variant(
                title=title, summary=summary, explanation=explanation, cause=cause, fix=fix,
                analogy="Like someone walking down a hotel corridor trying every door handle to see which room is unlocked.",
                mitre="T1046 Network Service Discovery", severity=sev),
        }
        if data or ftp:
            variants[Category.FAULT] = Variant(
                title=f"{src} connects to many different ports on {tgt}",
                summary=f"{src} used {plural(ports, 'port')} on {tgt}, and {data} of the connections carried data.",
                explanation=("Some applications legitimately use many ports (passive FTP opens a new port per file, "
                             "media and peer-to-peer apps negotiate ports). The connections here partly look like "
                             "real use, so this may be an application behaving unusually rather than a scan."),
                cause="An application that negotiates dynamic ports (FTP, VoIP, P2P) or a misbehaving client.",
                fix=["Identify the application on " + src + " (`netstat -anp` / Task Manager > Resource Monitor).",
                     "Confirm the ports match what the application documents.",
                     "If unknown, treat it as a scan and follow the security steps."],
                analogy="Like a courier who needs a different loading bay for every parcel.",
                severity=Severity.LOW)
        f = Finding(
            kind="scan.port", category=Category.ATTACK, severity=sev, title=title, summary=summary,
            explanation=explanation, cause=cause, fix=fix, technical=technical,
            analogy=variants[Category.ATTACK].analogy, mitre="T1046 Network Service Discovery",
            hosts=[src] + [t for t in target_ips if t != src][:9],
            metrics={
                "source": src, "technique": technique, "targets": target_ips, "target_count": n_targets,
                "probes": probes, "ports_probed": ports, "tcp_ports": tcp_ports, "udp_ports": udp_ports,
                "peak_ports_per_window": peak, "window_s": WINDOW, "rate_per_s": round(rate, 2),
                "duration_s": round(dur, 3), "open_ports": open_list, "open_count": opened,
                "closed": closed, "udp_closed": udp_closed, "half_open": half, "connect_close": cclose,
                "with_data": data, "stealth": {"fin": stealth[0], "null": stealth[1], "xmas": stealth[2], "other": stealth[3]},
                "sample_ports": [_port_label(k) for p in targets[:1] for k in p.order[:10]],
            },
            indicators=ind, variants=variants,
        )
        return ev.apply(f)

    # ------------------------------------------------------------------ #
    def _sweep_finding(self, src: str, sws: list[_Sweep], ctx: AnalysisContext) -> Finding | None:
        gw_ips = ctx.hosts.gateway()[0]
        roles = ctx.hosts.hosts.get(src).roles if src in ctx.hosts.hosts else set()
        kept = []
        for sw in sws:
            dsts = sw.dsts
            n = max(len(dsts), sw.win.peak)
            if n < self._thr_sweep:
                continue
            ans = len(sw.answered)
            unans = max(0.0, 1 - ans / max(len(dsts), 1))
            seq = _sequential_ratio(dsts)
            dns = sum(1 for d in dsts if d in self.dns_ips) / max(len(dsts), 1)
            repeat = sw.probes / max(len(dsts), 1)
            if dns >= 0.5 and seq < 0.5:
                continue  # names the client looked up: normal browsing / app traffic
            if not (seq >= 0.5 or unans >= 0.6):
                continue  # scattered, answered destinations: P2P, CDNs, monitoring
            if sw.svc == ECHO and unans < 0.2 and repeat >= 3:
                continue  # repeated rounds of answered pings: a monitoring system
            kept.append((sw, n, ans, unans, seq, dns, repeat))
        if not kept:
            return None
        kept.sort(key=lambda x: -x[1])
        sw0, n0, ans0, unans0, seq0, dns0, rep0 = kept[0]
        services = [_svc_name(k[0].svc) for k in kept]
        total_hosts = sum(k[1] for k in kept)
        probes = sum(k[0].probes for k in kept)
        first = min(k[0].first_ts for k in kept)
        last = max(k[0].last_ts for k in kept)
        dur = max(0.001, last - first)
        rate = probes / dur
        ping = any(k[0].svc == ECHO for k in kept)
        prefixes = sorted({_prefix24(d) for k in kept for d in k[0].dsts})[:10]
        live = sorted({a for k in kept for a in k[0].answered})[:10]
        ev = Evidence()
        for k in kept:
            ev.merge(k[0].ev)
        ind = [Indicator(
            f"{src} contacted {plural(n0, 'different host')} on {services[0]} within {int(WINDOW)} s",
            Category.ATTACK, 2.5 if n0 >= 3 * self._thr_sweep else 2.0)]
        if seq0 >= 0.5:
            ind.append(Indicator(f"The addresses were walked in order ({fmt_pct(seq0)} consecutive), like "
                                 "counting through a list of house numbers", Category.ATTACK, 1.5))
        if unans0 >= 0.6:
            ind.append(Indicator(f"{fmt_pct(unans0)} of the contacted addresses never answered: the source "
                                 "was guessing which addresses are in use", Category.ATTACK, 1.0))
        if dns0 < 0.1:
            ind.append(Indicator("None of the addresses came from a DNS lookup, so no user or app asked for "
                                 "these specific hosts", Category.ATTACK, 0.5))
        if dns0 >= 0.1:
            ind.append(Indicator(f"{fmt_pct(dns0)} of the addresses were looked up in DNS first, which normal "
                                 "applications do", Category.FAULT, 1.0))
        if src in gw_ips or "dhcp-server" in roles:
            ind.append(Indicator(f"{src} is the router / DHCP server, which sometimes checks addresses "
                                 "before handing them out", Category.FAULT, 1.5))
        if unans0 < 0.3:
            ind.append(Indicator(f"Most hosts ({ans0}) answered, which fits an inventory or monitoring tool too",
                                 Category.FAULT, 0.5))
        web = sw0.svc in (80, 443, UDP_OFFSET + 443)
        public = sum(1 for d in sw0.dsts if not is_private(d)) / max(len(sw0.dsts), 1)
        if web and seq0 < 0.3 and public >= 0.8:
            ind.append(Indicator("The targets are scattered internet addresses on web ports, which is also what an "
                                 "app retrying while the internet connection is down looks like", Category.FAULT, 1.5))
        sev = Severity.MEDIUM
        if n0 >= 3 * self._thr_sweep and public < 0.5 and seq0 >= 0.5:
            sev = Severity.HIGH
        if src in gw_ips or "dhcp-server" in roles or (web and seq0 < 0.3 and public >= 0.8):
            sev = Severity.LOW
        what = "pinged" if ping and len(kept) == 1 else "contacted"
        title = f"Host sweep: {src} is looking for which computers exist on the network"
        if ping and len(kept) == 1:
            title = f"Ping sweep: {src} is checking which addresses are alive"
        summary = (f"{src} {what} {plural(total_hosts, 'address', 'es')} in {dur:.1f} s on {', '.join(services[:3])}; "
                   f"{len(live)} answered.")
        explanation = (
            f"Instead of talking to a few known servers, {src} went through {plural(total_hosts, 'address', 'es')} "
            f"one after another ({', '.join(prefixes[:3])}) to see which ones respond. Mapping which devices exist "
            "is how an attacker (or a worm) picks its next target; an IT inventory tool does the same, so check "
            "whether this is expected."
        )
        cause = (f"A network-discovery or scanning tool on {src} (nmap -sn, a worm spreading, or an inventory / "
                 "monitoring scanner).")
        fix = [
            f"Find the device behind {src} (`arp -a`, DHCP leases, switch MAC table) and ask who owns it.",
            "If the sweep is not an authorised inventory/monitoring job, isolate the device and scan it for malware.",
            f"Block or rate-limit it at the firewall (e.g. `iptables -I FORWARD -s {src} -j DROP`).",
            "Check the hosts that answered for follow-up connections from this source.",
        ]
        mitre = "T1018 Remote System Discovery" + ("" if ping and len(kept) == 1 else "; T1046 Network Service Discovery")
        technical = (
            f"Sweep from {src}: services {', '.join(services[:5])}; {total_hosts} distinct destinations "
            f"(peak {n0}/{int(WINDOW)} s, threshold {self._thr_sweep}), {probes} probes at {rate:.1f}/s over {dur:.2f} s; "
            f"answered {ans0} ({fmt_pct(1 - unans0)}), sequential gaps {fmt_pct(seq0)}, DNS-resolved {fmt_pct(dns0)}, "
            f"probes/host {rep0:.1f}; prefixes {', '.join(prefixes[:5])}."
        )
        analogy = "Like someone ringing every doorbell on the street to see who is home."
        f = Finding(
            kind="scan.host_sweep", category=Category.ATTACK, severity=sev, title=title, summary=summary,
            explanation=explanation, cause=cause, fix=fix, technical=technical, analogy=analogy, mitre=mitre,
            hosts=[src] + live[:9],
            metrics={
                "source": src, "services": services[:10], "hosts_contacted": total_hosts, "peak_hosts_per_window": n0,
                "answered": ans0, "answered_hosts": live, "unanswered_ratio": round(unans0, 3),
                "sequential_ratio": round(seq0, 3), "dns_resolved_ratio": round(dns0, 3), "probes": probes,
                "rate_per_s": round(rate, 2), "duration_s": round(dur, 3), "prefixes": prefixes,
                "sample_targets": sw0.dsts[:10],
            },
            indicators=ind,
            variants={Category.ATTACK: Variant(title=title, summary=summary, explanation=explanation, cause=cause,
                                               fix=fix, analogy=analogy, mitre=mitre, severity=sev)},
        )
        if any(i.supports is Category.FAULT for i in ind):
            f.variants[Category.FAULT] = Variant(
                title=f"{src} is checking many addresses (possibly an inventory or monitoring tool)",
                summary=f"{src} contacted {plural(total_hosts, 'address', 'es')}; part of it looks like routine checks.",
                explanation=("Routers, DHCP servers and monitoring systems sometimes check many addresses to see "
                             "which are free or alive. That is harmless if it is expected on this network."),
                cause="Address-conflict checks by a DHCP server, or an IT monitoring / inventory tool.",
                fix=["Confirm with the network owner that the tool on " + src + " is expected.",
                     "If it is, document it so future alerts can be ignored; if not, follow the security steps."],
                analogy="Like a postman checking every letterbox on the route.", severity=Severity.LOW)
        return ev.apply(f)
