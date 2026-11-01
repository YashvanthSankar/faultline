"""Volume attacks and storms: SYN flood (vs. flash crowd), ICMP flood / Smurf /
ping of death, broadcast storm (switching loop).

Everything here is built to survive the very traffic it detects: a SYN flood
with millions of forged source addresses. Per-packet work is O(1) and state
is bounded:

* per victim service a ring of 1-second buckets (10 s window);
* handshake completion via a fixed-size hashed bitmap (no per-connection
  objects);
* distinct sources via an exact set that degrades into a linear-counting
  bitmap sketch; top talkers via a space-saving heavy-hitter table;
* TTL distribution as a 256-bin counter.

Discriminators
--------------
SYN flood (attack) vs. flash crowd / overloaded server (fault):
  real clients *complete* the handshake and send requests, retry SYNs when the
  server is slow, and arrive with varied TTLs (different distances). Forged
  floods do not complete, use one SYN per source address, and show either one
  TTL (all from the same machine) or random TTLs.
Broadcast storm: the same frame repeated within milliseconds (L2 loop
  copies are bit-identical, IP ID and TTL included) is a loop; a single MAC
  emitting distinct frames at a high rate is a faulty NIC or a flood tool.
"""

from __future__ import annotations

import math
from collections import Counter

from ..context import is_mac_multicast
from ..model import Tcp
from .base import (
    AnalysisContext, BoundedDict, Category, Detector, Evidence, Finding, Indicator, Packet,
    Severity, Variant, fmt_pct, plural, register,
)

SYN, ACK, RST, FIN = Tcp.SYN, Tcp.ACK, Tcp.RST, Tcp.FIN

SYN_WINDOW = 10  # seconds
SYN_THRESHOLD = 200  # SYNs per SYN_WINDOW to one service
LOW_COMPLETION = 0.2
ICMP_RATE = 100  # echo requests per second to one target
ICMP_SUSTAIN = 3  # consecutive seconds
SMURF_THRESHOLD = 10  # echo requests to a broadcast address within 10 s
BCAST_RATE = 500  # broadcast frames per second
BCAST_FRACTION = 0.30
LOOP_COPIES = 20  # identical broadcast frames in one burst
LOOP_GAP = 0.02  # average gap between copies (s)

_BITS = 1 << 20
_MASK = _BITS - 1
BROADCAST = "ff:ff:ff:ff:ff:ff"


# --------------------------------------------------------------------------- #
# Sketches
# --------------------------------------------------------------------------- #


class Distinct:
    """Approximate distinct counter: exact up to ``exact`` items, then linear counting."""

    __slots__ = ("items", "bits", "exact")
    M = 1 << 16

    def __init__(self, exact: int = 2048) -> None:
        self.items: set | None = set()
        self.bits: bytearray | None = None
        self.exact = exact

    def add(self, x) -> None:
        if self.items is not None:
            self.items.add(x)
            if len(self.items) > self.exact:
                self.bits = bytearray(self.M >> 3)
                for y in self.items:
                    self._set(y)
                self.items = None
            return
        self._set(x)

    def _set(self, x) -> None:
        h = hash(x) & (self.M - 1)
        self.bits[h >> 3] |= 1 << (h & 7)

    def count(self) -> int:
        if self.items is not None:
            return len(self.items)
        zeros = self.M - sum(bin(b).count("1") for b in self.bits)
        if zeros == 0:
            return self.M * 10  # saturated: "very many"
        return int(round(-self.M * math.log(zeros / self.M)))

    def sample(self, n: int = 10) -> list:
        return sorted(self.items)[:n] if self.items is not None else []


class TopK:
    """Space-saving heavy hitters (k counters; counts are upper bounds)."""

    __slots__ = ("k", "c")

    def __init__(self, k: int = 8) -> None:
        self.k = k
        self.c: dict = {}

    def add(self, x, n: int = 1) -> None:
        c = self.c
        if x in c:
            c[x] += n
        elif len(c) < self.k:
            c[x] = n
        else:
            m = min(c, key=c.get)
            v = c.pop(m)
            c[x] = v + n

    def top(self, n: int = 5) -> list[tuple]:
        return sorted(self.c.items(), key=lambda kv: -kv[1])[:n]


def fast_private(ip: str) -> bool:
    """Cheap RFC1918 / loopback / link-local / CGNAT check for IPv4 strings (hot path)."""
    if ip.startswith(("10.", "192.168.", "127.", "169.254.")):
        return True
    if ip.startswith("172."):
        try:
            return 16 <= int(ip.split(".", 2)[1]) <= 31
        except ValueError:
            return False
    if ip.startswith("100."):
        try:
            return 64 <= int(ip.split(".", 2)[1]) <= 127
        except ValueError:
            return False
    return ip.startswith(("fe80:", "fc", "fd", "::1"))


def _bogon(ip: str) -> bool:
    """Source addresses that can never legitimately appear on the wire."""
    if ip.startswith(("0.", "127.")) or ip == "255.255.255.255":
        return True
    try:
        first = int(ip.split(".", 1)[0]) if "." in ip and ":" not in ip else 0
    except ValueError:
        return False
    return first >= 224


# --------------------------------------------------------------------------- #
# SYN flood state
# --------------------------------------------------------------------------- #


class _Episode:
    __slots__ = ("start", "end", "syn", "synack", "completed", "data", "retrans", "srcs", "ttl", "top",
                 "private", "bogon", "land", "ev", "peak_sec", "peak_win", "confirmed")

    def __init__(self, t: float) -> None:
        self.start = self.end = t
        self.syn = self.synack = self.completed = self.data = self.retrans = 0
        self.srcs = Distinct()
        self.ttl: Counter = Counter()
        self.top = TopK(8)
        self.private = self.bogon = self.land = 0
        self.ev = Evidence()
        self.peak_sec = 0
        self.peak_win = 0
        self.confirmed = False


class _Victim:
    __slots__ = ("sec", "ring", "wsum", "ep", "best")

    def __init__(self) -> None:
        self.sec = -1
        self.ring = [0] * SYN_WINDOW
        self.wsum = 0
        self.ep: _Episode | None = None
        self.best: _Episode | None = None  # the largest finished confirmed episode


class _IcmpTarget:
    __slots__ = ("sec", "cur", "run", "best_run", "peak", "req", "replies", "large", "bytes", "srcs", "top",
                 "ev", "first", "last", "echo_ids", "flood_secs", "rsec", "rcur", "rrun", "rbest", "rpeak",
                 "unsol", "rsrcs", "rev", "sent_req", "ttl")

    def __init__(self) -> None:
        self.sec = -1
        self.cur = self.run = self.best_run = self.peak = 0
        self.req = self.replies = self.large = self.bytes = 0
        self.srcs = Distinct(512)
        self.top = TopK(6)
        self.ev = Evidence()
        self.first = self.last = None
        self.echo_ids: set = set()
        self.flood_secs = 0
        self.rsec = -1
        self.rcur = self.rrun = self.rbest = self.rpeak = 0
        self.unsol = 0
        self.rsrcs = Distinct(512)
        self.rev = Evidence()
        self.sent_req = 0
        self.ttl: Counter = Counter()


def _label(p: Packet) -> str:
    if p.arp is not None:
        return "ARP"
    if p.dhcp is not None:
        return "DHCP"
    u = p.udp
    if u is not None:
        port = u.dport
        return {5353: "mDNS", 1900: "SSDP", 137: "NetBIOS", 138: "NetBIOS", 5355: "LLMNR", 3702: "WS-Discovery",
                67: "DHCP", 68: "DHCP"}.get(port, "UDP")
    if p.icmp is not None:
        return "ICMPv6" if p.icmp.v6 else "ICMP"
    if p.ip_ver is None:
        return "L2 0x%04x" % (p.ethertype or 0)
    return "IP"


def _control_multicast(p: Packet) -> bool:
    """Broadcast or link-local control multicast (not multicast data streams such as IPTV)."""
    d = p.eth_dst
    if d == BROADCAST:
        return True
    if not is_mac_multicast(d):
        return False
    ip = p.dst
    if ip is None:
        return True  # L2 control protocols (STP, LLDP, CDP ...)
    return ip.startswith(("224.0.0.", "ff02:", "239.255.255.250", "ff05::c")) or ip.endswith(".255")


# --------------------------------------------------------------------------- #
# Detector
# --------------------------------------------------------------------------- #


@register
class FloodDetector(Detector):
    name = "flood"

    def __init__(self) -> None:
        self.victims: BoundedDict = BoundedDict(20_000)
        self.bits = bytearray(_BITS)  # per-connection handshake state: 1 = SYN, 2 = completed, 3 = data
        self.icmp: BoundedDict = BoundedDict(20_000)
        self.smurf: BoundedDict = BoundedDict(2_000)  # src -> [count, first, last, Evidence, dsts]
        self.pod = Evidence()  # oversized ICMP fragments (ping of death)
        self.pod_hosts: Counter = Counter()
        # broadcast storm
        self.b_sec = -1
        self.b_tot = self.b_bc = 0
        self.b_storm_secs = 0
        self.b_storm_frames = 0
        self.b_storm_total = 0
        self.b_peak = 0
        self.b_all = 0
        self.b_frames = 0
        self.b_top = TopK(8)
        self.b_labels: Counter = Counter()
        self.b_ev = Evidence()
        self.sigs: BoundedDict = BoundedDict(20_000)  # signature -> [burst, start, last]
        self.loop_sigs = 0
        self.loop_dups = 0
        self.loop_best = 0
        self.loop_macs: Counter = Counter()
        self.loop_ev = Evidence()
        self.loop_labels: Counter = Counter()
        self.finished: list[tuple[tuple, _Episode]] = []
        self._scaled = False
        self.thr_syn = SYN_THRESHOLD
        self.thr_icmp = ICMP_RATE
        self.thr_smurf = SMURF_THRESHOLD
        self.thr_bc = BCAST_RATE
        self.thr_loop = LOOP_COPIES

    def _scale(self, ctx: AnalysisContext) -> None:
        sc = ctx.config.scale
        self.thr_syn = max(20, round(SYN_THRESHOLD * sc))
        self.thr_icmp = max(10, round(ICMP_RATE * sc))
        self.thr_smurf = max(3, round(SMURF_THRESHOLD * sc))
        self.thr_bc = max(50, round(BCAST_RATE * sc))
        self.thr_loop = max(5, round(LOOP_COPIES * sc))
        self._scaled = True

    # ------------------------------------------------------------------ #
    def on_packet(self, pkt: Packet, ctx: AnalysisContext) -> None:
        if not self._scaled:
            self._scale(ctx)
        t = pkt.ts or 0.0
        self._broadcast(pkt, t)
        if pkt.src is None or pkt.dst is None:
            return
        if pkt.tcp is not None:
            self._tcp(pkt, t)
        elif pkt.icmp is not None or pkt.proto == 1 or pkt.proto == 58:
            self._icmp(pkt, t)

    # -- SYN flood ------------------------------------------------------- #
    def _roll(self, v: _Victim, key: tuple, s: int) -> None:
        if v.sec < 0:
            v.sec = s
            return
        if s <= v.sec:
            return
        steps = min(s - v.sec, SYN_WINDOW)
        for i in range(1, steps + 1):
            idx = (v.sec + i) % SYN_WINDOW
            v.wsum -= v.ring[idx]
            v.ring[idx] = 0
        v.sec = s
        ep = v.ep
        if ep is not None:
            if ep.confirmed and v.wsum < self.thr_syn / 8:
                self._close(v, key)
            elif not ep.confirmed and v.wsum < self.thr_syn / 8:
                v.ep = None

    def _close(self, v: _Victim, key: tuple) -> None:
        ep = v.ep
        v.ep = None
        if ep is None or not ep.confirmed:
            return
        if v.best is None or ep.syn > v.best.syn:
            if v.best is None and len(self.finished) < 256:
                self.finished.append((key, v))
            v.best = ep

    def _tcp(self, pkt: Packet, t: float) -> None:
        tcp = pkt.tcp
        fl = tcp.flags or 0
        sport, dport = tcp.sport, tcp.dport
        if sport is None or dport is None:
            return
        src, dst = pkt.src, pkt.dst
        if fl & SYN and not fl & (ACK | RST):
            key = (dst, dport)
            v = self.victims.get(key)
            if v is None:
                v = self.victims[key] = _Victim()
            s = int(t)
            self._roll(v, key, s)
            v.ring[v.sec % SYN_WINDOW] += 1
            v.wsum += 1
            h = hash((src, sport, dst, dport)) & _MASK
            prev = self.bits[h]
            self.bits[h] = 1
            ep = v.ep
            if ep is not None and not ep.confirmed and t - ep.start > 3 * SYN_WINDOW:
                ep = v.ep = None  # a long, merely busy period: restart so old healthy stats don't dilute a flood
            if ep is None and v.wsum >= self.thr_syn / 4:
                ep = v.ep = _Episode(t)
            if ep is not None:
                self.victims.move_to_end(key)
                ep.syn += 1
                ep.end = max(ep.end, t)
                if prev == 1:
                    ep.retrans += 1
                ep.srcs.add(src)
                ep.top.add(src)
                if pkt.ttl is not None:
                    ep.ttl[pkt.ttl] += 1
                if fast_private(src):
                    ep.private += 1
                if src == dst:
                    ep.land += 1
                elif _bogon(src):
                    ep.bogon += 1
                ep.ev.add(pkt)
                cur = v.ring[v.sec % SYN_WINDOW]
                if cur > ep.peak_sec:
                    ep.peak_sec = cur
                if v.wsum > ep.peak_win:
                    ep.peak_win = v.wsum
                if not ep.confirmed and v.wsum >= self.thr_syn:
                    ep.confirmed = True
            return
        if fl & SYN and fl & ACK:
            v = self.victims.get((src, sport))
            if v is not None and v.ep is not None:
                v.ep.synack += 1
            return
        if fl & ACK and not fl & (SYN | RST):
            v = self.victims.get((dst, dport))
            if v is None or v.ep is None:
                return
            h = hash((src, sport, dst, dport)) & _MASK
            b = self.bits[h]
            if b == 1:
                self.bits[h] = 2
                v.ep.completed += 1
                b = 2
            if b == 2 and (tcp.plen or 0) > 0:
                self.bits[h] = 3
                v.ep.data += 1

    # -- ICMP ------------------------------------------------------------ #
    def _icmp(self, pkt: Packet, t: float) -> None:
        src, dst = pkt.src, pkt.dst
        ic = pkt.icmp
        # ping of death: a fragment whose end lies beyond the 65,535-byte IP maximum
        if pkt.proto == 1 and (pkt.mf or pkt.frag_off):
            end = (pkt.frag_off or 0) + max(0, pkt.ip_len or 0)  # decoder: frag_off in bytes, ip_len = IP payload length
            if end > 65535:
                self.pod.add(pkt)
                self.pod_hosts[(src, dst)] += 1
        if ic is None:
            return
        s = int(t)
        if ic.is_echo_request:
            if dst.endswith(".255") or dst == "255.255.255.255" or pkt.eth_dst == BROADCAST:
                sm = self.smurf.get(src)
                if sm is None:
                    sm = self.smurf[src] = [0, t, t, Evidence(), set()]
                sm[0] += 1
                sm[2] = max(sm[2], t)
                sm[3].add(pkt)
                if len(sm[4]) < 16:
                    sm[4].add(dst)
                return
            tg = self.icmp.get(dst)
            if tg is None:
                tg = self.icmp[dst] = _IcmpTarget()
            if tg.sec != s:
                self._icmp_roll(tg, s)
            tg.cur += 1
            tg.req += 1
            tg.bytes += pkt.wirelen or 0
            if (pkt.ip_len or 0) >= 1000:
                tg.large += 1
            tg.first = t if tg.first is None else min(tg.first, t)
            tg.last = t if tg.last is None else max(tg.last, t)
            tg.srcs.add(src)
            tg.top.add(src)
            if pkt.ttl is not None:
                tg.ttl[pkt.ttl] += 1
            if len(tg.echo_ids) < 64 and ic.echo_id is not None:
                tg.echo_ids.add(ic.echo_id)
            if tg.cur >= self.thr_icmp or tg.run:
                tg.ev.add(pkt)
            st = self.icmp.get(src)
            if st is not None:
                st.sent_req += 1
        elif ic.is_echo_reply:
            st = self.icmp.get(src)  # the pinged target answering
            if st is not None:
                st.replies += 1
            tg = self.icmp.get(dst)
            if tg is None:
                tg = self.icmp[dst] = _IcmpTarget()
            if tg.rsec != s:
                self._icmp_rroll(tg, s)
            tg.rcur += 1
            tg.unsol += 1
            tg.rsrcs.add(src)
            if tg.rcur >= self.thr_icmp or tg.rrun:
                tg.rev.add(pkt)

    def _icmp_roll(self, tg: _IcmpTarget, s: int) -> None:
        """Close the current 1-s bucket of echo requests and track sustained runs."""
        if tg.sec < 0:
            tg.sec = s
            return
        if s <= tg.sec:
            return  # same second, or the timestamp went backwards: keep counting
        if tg.cur >= self.thr_icmp:
            tg.run += 1
            tg.flood_secs += 1
        else:
            tg.run = 0
        tg.best_run = max(tg.best_run, tg.run)
        tg.peak = max(tg.peak, tg.cur)
        if s > tg.sec + 1:
            tg.run = 0  # an empty second breaks the run
        tg.cur = 0
        tg.sec = s

    def _icmp_rroll(self, tg: _IcmpTarget, s: int) -> None:
        """Same as ``_icmp_roll`` for echo replies *received* by the host (reflection)."""
        if tg.rsec < 0:
            tg.rsec = s
            return
        if s <= tg.rsec:
            return
        tg.rrun = tg.rrun + 1 if tg.rcur >= self.thr_icmp else 0
        tg.rbest = max(tg.rbest, tg.rrun)
        tg.rpeak = max(tg.rpeak, tg.rcur)
        if s > tg.rsec + 1:
            tg.rrun = 0
        tg.rcur = 0
        tg.rsec = s

    # -- broadcast storm ------------------------------------------------- #
    def _broadcast(self, pkt: Packet, t: float) -> None:
        s = int(t)
        if s > self.b_sec:
            self._b_roll(s)
        self.b_tot += 1
        d = pkt.eth_dst
        if d is None or not (d == BROADCAST or is_mac_multicast(d)):
            return
        self.b_all += 1
        # loop signature: identical copies of one broadcast / multicast frame
        if pkt.arp is not None:
            a = pkt.arp
            sig = ("A", pkt.eth_src, a.op, a.spa, a.tpa, a.sha)
        elif pkt.src is not None:
            sig = ("I", pkt.eth_src, pkt.src, pkt.dst, pkt.ip_id, pkt.ttl, pkt.proto, pkt.sport, pkt.dport, pkt.ip_len)
        else:
            sig = ("L", pkt.eth_src, pkt.ethertype, pkt.wirelen)
        e = self.sigs.get(sig)
        if e is None:
            self.sigs[sig] = [1, t, t, False]
        else:
            if t - e[2] > 0.5:
                e[0], e[1], e[3] = 1, t, False
            else:
                e[0] += 1
            e[2] = max(e[2], t)
            n = e[0]
            if n >= 3 and (e[2] - e[1]) / (n - 1) < LOOP_GAP:
                if n >= self.thr_loop:
                    if not e[3]:
                        e[3] = True
                        self.loop_sigs += 1
                        self.loop_dups += n - 1
                        self.loop_labels[_label(pkt)] += 1
                    else:
                        self.loop_dups += 1
                    self.loop_best = max(self.loop_best, n)
                    self.loop_macs[pkt.eth_src] += 1
                    self.loop_ev.add(pkt)
        if not _control_multicast(pkt):
            return
        self.b_bc += 1
        self.b_frames += 1
        self.b_top.add(pkt.eth_src)
        lab = _label(pkt)
        if len(self.b_labels) < 32 or lab in self.b_labels:
            self.b_labels[lab] += 1
        if self.b_bc >= self.thr_bc / 2:
            self.b_ev.add(pkt)

    def _b_roll(self, s: int) -> None:
        if self.b_sec >= 0 and self.b_bc >= self.thr_bc and self.b_tot and self.b_bc / self.b_tot >= BCAST_FRACTION:
            self.b_storm_secs += 1
            self.b_storm_frames += self.b_bc
            self.b_storm_total += self.b_tot
        self.b_peak = max(self.b_peak, self.b_bc)
        self.b_sec = s
        self.b_tot = self.b_bc = 0

    # ------------------------------------------------------------------ #
    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        if not self._scaled:
            self._scale(ctx)
        out: list[Finding] = []
        # close open episodes
        for key, v in list(self.victims.items()):
            if v.ep is not None and v.ep.confirmed:
                self._close(v, key)
        seen = set()
        for key, v in self.finished:
            if id(v) in seen or v.best is None:
                continue
            seen.add(id(v))
            f = self._syn_finding(key, v.best, ctx)
            if f is not None:
                out.append(f)
        # ICMP
        for dst, tg in list(self.icmp.items()):
            self._icmp_roll(tg, tg.sec + 1)
            self._icmp_rroll(tg, tg.rsec + 1)
            f = self._icmp_finding(dst, tg, ctx)
            if f is not None:
                out.append(f)
        for src, sm in self.smurf.items():
            f = self._smurf_finding(src, sm)
            if f is not None:
                out.append(f)
        if self.pod.total:
            out.append(self._pod_finding())
        self._b_roll(self.b_sec + 1)
        f = self._storm_finding(ctx)
        if f is not None:
            out.append(f)
        return out

    # -- SYN finding ----------------------------------------------------- #
    def _syn_finding(self, key: tuple, ep: _Episode, ctx: AnalysisContext) -> Finding | None:
        victim, port = key
        syn = max(ep.syn, 1)
        comp = min(1.0, ep.completed / syn)
        synack = min(1.0, ep.synack / syn)
        retr = ep.retrans / syn
        distinct = ep.srcs.count()
        per_src = syn / max(distinct, 1)
        dur = max(1.0, ep.end - ep.start)
        rate = ep.syn / dur
        top = ep.top.top(5)
        top_share = top[0][1] / syn if top else 0.0
        ttl_distinct = len(ep.ttl)
        ttl_top_share = (ep.ttl.most_common(1)[0][1] / max(sum(ep.ttl.values()), 1)) if ep.ttl else 0.0
        stressed = retr >= 0.05 or synack < 0.9 or comp < 0.8
        if comp >= LOW_COMPLETION and not stressed:
            return None  # busy but healthy server: everybody gets in
        attack_like = comp < LOW_COMPLETION
        svc = f"{victim}:{port}"
        ind: list[Indicator] = []
        ind.append(Indicator(f"{plural(ep.syn, 'connection request')} (SYN) hit {svc} within {dur:.0f} s "
                             f"(peak {ep.peak_win} per {SYN_WINDOW} s, {rate:.0f}/s)",
                             Category.ATTACK, 1.0 if not attack_like else 1.5))
        if comp < LOW_COMPLETION:
            ind.append(Indicator(f"Only {fmt_pct(comp)} of these connection attempts were ever completed by the "
                                 "client; real users finish the handshake, a flood never does", Category.ATTACK, 2.5))
        elif comp < 0.5:
            ind.append(Indicator(f"Just {fmt_pct(comp)} of handshakes completed", Category.ATTACK, 1.0))
        if distinct >= 100 and per_src <= 2:
            ind.append(Indicator(f"About {distinct:,} different source addresses, most sending a single SYN and "
                                 "never coming back: typical of forged (spoofed) addresses", Category.ATTACK, 2.0))
        if distinct >= 50 and ttl_top_share >= 0.8 and per_src <= 3:
            ind.append(Indicator(f"Thousands of 'different' senders all arrive with the same TTL "
                                 f"({ep.ttl.most_common(1)[0][0]}), i.e. from the same distance: one machine forging addresses",
                                 Category.ATTACK, 1.5))
        if ttl_distinct >= 64:
            ind.append(Indicator(f"TTL values are spread over {ttl_distinct} different values, like randomly "
                                 "generated packets rather than real operating systems", Category.ATTACK, 1.5))
        if ep.bogon or ep.land:
            ind.append(Indicator(f"{ep.bogon + ep.land} SYNs came from impossible addresses "
                                 f"({'the victim itself (LAND attack)' if ep.land else 'reserved/multicast ranges'})",
                                 Category.ATTACK, 2.0))
        if top and top_share >= 0.8 and rate >= 20 and comp < 0.5:
            ind.append(Indicator(f"One source, {top[0][0]}, sent {top[0][1]:,} SYNs ({fmt_pct(top_share)}) "
                                 "without completing the handshakes", Category.ATTACK, 2.0))
        if comp >= 0.5:
            ind.append(Indicator(f"{fmt_pct(comp)} of connections completed and {ep.data:,} carried a request: "
                                 "these are real clients", Category.FAULT, 2.5))
        elif comp >= LOW_COMPLETION:
            ind.append(Indicator(f"{fmt_pct(comp)} of connections completed, so many clients are real",
                                 Category.FAULT, 1.5))
        if ep.data and ep.data >= 0.3 * syn:
            ind.append(Indicator(f"{ep.data:,} connections sent application data (requests)", Category.FAULT, 1.0))
        if retr >= 0.05 and comp >= LOW_COMPLETION:
            ind.append(Indicator(f"{fmt_pct(retr)} of SYNs were retries: clients waited and tried again because "
                                 "the server answered slowly (overload)", Category.FAULT, 1.5))
        if 3 <= ttl_distinct <= 40 and ttl_top_share < 0.7 and per_src >= 1.5:
            ind.append(Indicator("Clients arrive with varied TTLs (different distances) and reconnect, like real "
                                 "users on different networks", Category.FAULT, 1.0))
        if synack < 0.9:
            ind.append(Indicator(f"The server answered only {fmt_pct(synack)} of SYNs: it is overwhelmed (or the "
                                 "replies take another path)", Category.FAULT, 0.5))
        top_list = [f"{ip} ({n:,})" for ip, n in top]
        crit = rate >= 1000 and synack < 0.5
        sev_att = Severity.CRITICAL if crit else Severity.HIGH
        title_a = f"SYN flood: {svc} is being bombarded with fake connection requests"
        sum_a = (f"{ep.syn:,} SYNs in {dur:.0f} s ({rate:.0f}/s) from ~{distinct:,} sources hit {svc}; only "
                 f"{fmt_pct(comp)} completed.")
        expl_a = (
            "Every TCP connection starts with a three-step 'handshake' (SYN, SYN/ACK, ACK). A SYN flood sends the "
            "first step over and over and never finishes it, so the server keeps a half-open slot reserved for each "
            "request until its table is full and real users cannot connect. This is a denial-of-service attack."
        )
        cause_a = ("A denial-of-service tool sending SYNs " +
                   ("from forged random addresses" if distinct >= 100 and per_src <= 2 else
                    f"from {top[0][0] if top else 'a few hosts'}") + ".")
        fix_a = [
            "Enable SYN cookies on the server (Linux: `sysctl -w net.ipv4.tcp_syncookies=1`) so half-open "
            "connections no longer use memory.",
            "Rate-limit new connections per source at the firewall (e.g. `iptables -A INPUT -p tcp --syn -m limit "
            "--limit 50/s -j ACCEPT`) and raise the backlog (`net.ipv4.tcp_max_syn_backlog`).",
            ("Block the top sources: " + ", ".join(ip for ip, _ in top[:3]) + ".") if top_share >= 0.5 else
            "Source addresses are forged, so blocking them one by one will not help; ask your ISP / DDoS "
            "protection provider to filter upstream.",
            "Check router/firewall logs for when it started and whether other services are targeted.",
        ]
        mitre = "T1499.001 Endpoint Denial of Service: OS Exhaustion Flood"
        title_f = f"Server overloaded: {svc} cannot keep up with a surge of real clients"
        sum_f = (f"{ep.syn:,} connection attempts in {dur:.0f} s from ~{distinct:,} clients; {fmt_pct(comp)} completed "
                 f"and {fmt_pct(retr)} had to retry.")
        expl_f = (
            "Lots of real devices are trying to connect at once (a 'flash crowd', e.g. a popular page or all "
            "clients reconnecting after an outage). They do finish the connection handshake and send requests, so "
            "this is not an attack, but the server answers slowly and some clients have to retry."
        )
        cause_f = "More legitimate demand than the server (or its connection backlog) can handle."
        fix_f = [
            "Check the server's CPU, memory and connection backlog (`ss -s`, `netstat -an | grep SYN_RECV | wc -l`).",
            "Increase the listen backlog / worker count (`net.ipv4.tcp_max_syn_backlog`, web server workers).",
            "Add capacity: a cache/CDN, a load balancer, or more servers.",
            "Find out what triggered the surge (a campaign, an update push, clients reconnecting after an outage).",
        ]
        cat = Category.ATTACK if attack_like else Category.FAULT
        title, summ, expl, cause, fix = (title_a, sum_a, expl_a, cause_a, fix_a) if attack_like else \
            (title_f, sum_f, expl_f, cause_f, fix_f)
        technical = (
            f"Victim {svc}: {ep.syn} SYN, {ep.synack} SYN/ACK ({fmt_pct(synack)}), {ep.completed} completed "
            f"handshakes ({fmt_pct(comp)}), {ep.data} with data, {ep.retrans} SYN retransmissions ({fmt_pct(retr)}); "
            f"~{distinct} distinct sources ({per_src:.2f} SYN/source, {fmt_pct(ep.private / syn)} private, "
            f"{ep.bogon} bogon, {ep.land} LAND); peak {ep.peak_sec}/s and {ep.peak_win}/{SYN_WINDOW} s "
            f"(threshold {self.thr_syn}); {ttl_distinct} distinct TTLs, top TTL share {fmt_pct(ttl_top_share)}; "
            f"episode {dur:.1f} s. Top sources: {', '.join(top_list)}."
        )
        f = Finding(
            kind="flood.syn", category=cat, severity=sev_att if attack_like else Severity.MEDIUM, title=title,
            summary=summ, explanation=expl, cause=cause, fix=fix, technical=technical,
            analogy=("Like prank callers ringing a pizza shop thousands of times and hanging up, so real customers "
                     "hear only the busy tone." if attack_like else
                     "Like a shop on sale day: the queue is real customers, there just aren't enough tills."),
            mitre=mitre if attack_like else None,
            hosts=[victim] + [ip for ip, _ in top[:5]],
            metrics={
                "victim": svc, "syn": ep.syn, "syn_rate_per_s": round(rate, 1), "peak_per_s": ep.peak_sec,
                "peak_per_window": ep.peak_win, "window_s": SYN_WINDOW, "completion_ratio": round(comp, 3),
                "synack_ratio": round(synack, 3), "retransmit_ratio": round(retr, 3), "with_data": ep.data,
                "distinct_sources": distinct, "syn_per_source": round(per_src, 2), "top_sources": top_list,
                "private_source_ratio": round(ep.private / syn, 3), "bogon_sources": ep.bogon, "land": ep.land,
                "distinct_ttls": ttl_distinct, "top_ttls": [k for k, _ in ep.ttl.most_common(5)],
                "duration_s": round(dur, 2),
            },
            indicators=ind,
            variants={
                Category.ATTACK: Variant(title_a, sum_a, expl_a, cause_a, fix_a,
                                         analogy="Like prank callers ringing a pizza shop thousands of times and "
                                                 "hanging up, so real customers hear only the busy tone.",
                                         mitre=mitre, severity=sev_att),
                Category.FAULT: Variant(title_f, sum_f, expl_f, cause_f, fix_f,
                                        analogy="Like a shop on sale day: the queue is real customers, there just "
                                                "aren't enough tills.", severity=Severity.MEDIUM),
            },
        )
        return ep.ev.apply(f)

    # -- ICMP findings --------------------------------------------------- #
    def _icmp_finding(self, dst: str, tg: _IcmpTarget, ctx: AnalysisContext) -> Finding | None:
        req_flood = tg.best_run >= ICMP_SUSTAIN
        refl = tg.rbest >= ICMP_SUSTAIN and tg.unsol and tg.sent_req * 10 < tg.unsol
        if not req_flood and not refl:
            return None
        if req_flood:
            n, peak, srcs, ev, secs = tg.req, tg.peak, tg.srcs, tg.ev, tg.best_run
        else:
            n, peak, srcs, ev, secs = tg.unsol, tg.rpeak, tg.rsrcs, tg.rev, tg.rbest
        distinct = srcs.count()
        top = tg.top.top(5) if req_flood else []
        top_list = [f"{ip} ({c:,})" for ip, c in top]
        answered = min(1.0, tg.replies / max(tg.req, 1))
        large = tg.large / max(tg.req, 1)
        ind: list[Indicator] = []
        if req_flood:
            ind.append(Indicator(f"{dst} received ping (echo) requests at up to {peak:,}/s for {secs} seconds in a row "
                                 f"(threshold {self.thr_icmp}/s for {ICMP_SUSTAIN} s)", Category.ATTACK, 2.0))
        else:
            ind.append(Indicator(f"{dst} received {tg.unsol:,} ping replies (up to {peak:,}/s) from {distinct:,} hosts "
                                 "although it sent almost no pings: someone pinged in its name (reflection/Smurf)",
                                 Category.ATTACK, 2.5))
        if distinct >= 20:
            ind.append(Indicator(f"The traffic comes from ~{distinct:,} different sources at once (distributed)",
                                 Category.ATTACK, 1.5))
        if req_flood and large >= 0.5:
            ind.append(Indicator(f"{fmt_pct(large)} of the pings are oversized (>= 1000 bytes), meant to use up "
                                 "bandwidth rather than to test reachability", Category.ATTACK, 1.5))
        if req_flood and answered < 0.5:
            ind.append(Indicator(f"{dst} answered only {fmt_pct(answered)} of them: it is overwhelmed or the link is full",
                                 Category.ATTACK, 0.5))
        if req_flood and distinct == 1 and top and fast_private(top[0][0]) and answered >= 0.9 and large < 0.5:
            ind.append(Indicator(f"A single local machine ({top[0][0]}) sends normal-sized pings that are all "
                                 "answered: this is what an over-eager monitoring tool or a 'ping -f' test looks like",
                                 Category.MISCONFIG, 2.0))
            if len(tg.echo_ids) <= 2:
                ind.append(Indicator("All pings belong to one or two ping sessions (same identifier)",
                                     Category.MISCONFIG, 0.5))
        rate = n / max(1.0, (tg.last or 0) - (tg.first or 0)) if req_flood else float(peak)
        mbps = tg.bytes * 8 / max(1.0, (tg.last or 0) - (tg.first or 0)) / 1e6
        title_a = f"Ping flood: {dst} is being flooded with ICMP traffic"
        sum_a = (f"{dst} got {n:,} ICMP {'echo requests' if req_flood else 'echo replies'} at up to {peak:,}/s "
                 f"from ~{distinct:,} sources.")
        expl_a = ("'Ping' (ICMP echo) is a small 'are you there?' message. Sending it thousands of times per second "
                  "fills the victim's network link and keeps its CPU busy answering, so real traffic slows down or "
                  "stops. " + ("Here the replies come from many hosts that were tricked into answering on the "
                               "victim's behalf (Smurf / reflection)." if not req_flood else ""))
        cause_a = "A denial-of-service tool (e.g. hping3 / ping flood) or a botnet targeting " + dst + "."
        fix_a = [
            f"Rate-limit ICMP towards {dst} on the router/firewall (e.g. `iptables -A INPUT -p icmp --icmp-type "
            "echo-request -m limit --limit 10/s -j ACCEPT` then drop the rest).",
            ("Block the top sources: " + ", ".join(ip for ip, _ in top[:3]) + ".") if top else
            "Disable directed-broadcast replies on routers (`no ip directed-broadcast`) so they cannot be used as amplifiers.",
            "If the flood saturates your internet link, ask your ISP to filter it upstream.",
            "Check whether the source devices are compromised (if they are inside your network).",
        ]
        title_m = f"Too many pings: a tool on {top[0][0] if top else 'one host'} is pinging {dst} non-stop"
        sum_m = f"{dst} answered {n:,} pings at up to {peak:,}/s from a single local machine."
        expl_m = ("Monitoring systems and diagnostic commands ('ping -f') send pings to check that a device is up. "
                  "Configured too aggressively they waste bandwidth and CPU, but they are not an attack.")
        fix_m = ["Find the tool on " + (top[0][0] if top else "the source") + " (monitoring server, script, `ping -f`).",
                 "Reduce its polling rate to one ping every few seconds.",
                 "If nobody recognises it, treat it as an attack and block it."]
        mitre = "T1498.001 Network Denial of Service: Direct Network Flood"
        technical = (
            f"Target {dst}: {tg.req} echo requests (peak {tg.peak}/s, longest run {tg.best_run} s >= {self.thr_icmp}/s, "
            f"{tg.flood_secs} flood seconds), {tg.replies} replies from target ({fmt_pct(answered)}), {tg.large} large "
            f"(>= 1000 B, {fmt_pct(large)}), ~{mbps:.2f} Mbit/s; unsolicited echo replies to target {tg.unsol} "
            f"(peak {tg.rpeak}/s, run {tg.rbest} s) while it sent {tg.sent_req} requests; ~{distinct} distinct sources; "
            f"echo ids {len(tg.echo_ids)}; top {', '.join(top_list) or 'n/a'}."
        )
        sev = Severity.HIGH if (distinct >= 20 or peak >= 5 * self.thr_icmp or large >= 0.5 or not req_flood) else Severity.MEDIUM
        f = Finding(
            kind="flood.icmp", category=Category.ATTACK, severity=sev, title=title_a, summary=sum_a,
            explanation=expl_a, cause=cause_a, fix=fix_a, technical=technical,
            analogy="Like thousands of people shouting 'are you there?' at one person so nobody else can be heard.",
            mitre=mitre, hosts=[dst] + [ip for ip, _ in top[:5]],
            metrics={"target": dst, "echo_requests": tg.req, "peak_per_s": tg.peak, "sustained_s": tg.best_run,
                     "avg_rate_per_s": round(rate, 1), "mbit_per_s": round(mbps, 3), "answered_ratio": round(answered, 3),
                     "large_ratio": round(large, 3), "distinct_sources": distinct, "top_sources": top_list,
                     "unsolicited_replies": tg.unsol, "reply_peak_per_s": tg.rpeak, "reflection": bool(refl and not req_flood)},
            indicators=ind,
            variants={Category.ATTACK: Variant(title_a, sum_a, expl_a, cause_a, fix_a, mitre=mitre, severity=sev,
                                               analogy="Like thousands of people shouting 'are you there?' at one "
                                                       "person so nobody else can be heard.")},
        )
        if any(i.supports is Category.MISCONFIG for i in ind):
            f.variants[Category.MISCONFIG] = Variant(
                title_m, sum_m, expl_m, "A monitoring or diagnostic tool configured with a far too short interval.",
                fix_m, analogy="Like a parent texting 'are you OK?' every second.", severity=Severity.LOW)
        return ev.apply(f)

    def _smurf_finding(self, src: str, sm: list) -> Finding | None:
        count, first, last, ev, dsts = sm
        if count < self.thr_smurf:
            return None
        dur = max(0.001, last - first)
        if count / max(dur, 10.0) * 10 < self.thr_smurf and count < 5 * self.thr_smurf:
            return None  # occasional broadcast pings (discovery tools), not a burst
        ind = [Indicator(f"{plural(count, 'ping')} were sent to the broadcast address ({', '.join(sorted(dsts)[:3])}) "
                         f"in {dur:.1f} s, so every device on the subnet must answer", Category.ATTACK, 2.0),
               Indicator(f"Each broadcast ping makes every host reply to {src}; if {src} is forged, the victim "
                         "drowns in replies (Smurf amplification)", Category.ATTACK, 1.0),
               Indicator("Some discovery tools ping the broadcast address, but only a few times", Category.MISCONFIG, 0.5)]
        title = f"Smurf attack pattern: pings sent to a whole subnet in the name of {src}"
        summary = f"{count:,} echo requests to a broadcast address claiming to come from {src} in {dur:.1f} s."
        expl = ("A ping sent to a 'broadcast' address is delivered to every device on that network, and they all "
                "reply to the sender. Attackers forge the victim's address as the sender, so one small ping turns "
                "into dozens of replies hitting the victim (amplification).")
        cause = f"A flood tool forging {src} as the source, or a misconfigured script pinging the broadcast address."
        fix = ["Disable replies to broadcast pings on all hosts (Linux: `sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1`).",
               "Disable directed broadcasts on routers (`no ip directed-broadcast`).",
               f"Find the real sender: look up the MAC address of these frames in the switch MAC table (it may not be {src}).",
               "Rate-limit ICMP at the network edge."]
        mitre = "T1498.002 Network Denial of Service: Reflection Amplification"
        f = Finding(kind="flood.icmp", category=Category.ATTACK, severity=Severity.HIGH, title=title, summary=summary,
                    explanation=expl, cause=cause, fix=fix, mitre=mitre, hosts=[src] + sorted(dsts)[:5],
                    analogy="Like ordering pizzas to someone else's house from every pizzeria in town.",
                    technical=(f"{count} ICMP echo requests from {src} to broadcast {sorted(dsts)} over {dur:.2f} s "
                               f"(threshold {self.thr_smurf}/10 s)."),
                    metrics={"source": src, "broadcast_targets": sorted(dsts)[:10], "echo_requests": count,
                             "duration_s": round(dur, 3), "pattern": "smurf"},
                    indicators=ind,
                    variants={Category.ATTACK: Variant(title, summary, expl, cause, fix, mitre=mitre,
                                                       severity=Severity.HIGH)})
        return ev.apply(f)

    def _pod_finding(self) -> Finding:
        pairs = self.pod_hosts.most_common(5)
        srcs = sorted({s for (s, _), _ in pairs})
        dsts = sorted({d for (_, d), _ in pairs})
        title = "Ping of death: oversized ICMP packets that can crash old systems"
        summary = f"{plural(self.pod.total, 'ICMP fragment')} would reassemble into a packet larger than 65,535 bytes."
        expl = ("An IP packet can be at most 65,535 bytes. These ping fragments add up to more than that, which "
                "has no legitimate use: it is a classic trick to crash or freeze devices whose software does not "
                "check the size when putting the pieces back together.")
        cause = "A crafted attack packet (ping of death), sent by " + ", ".join(srcs[:3]) + "."
        fix = ["Make sure the targets run patched operating systems / firmware.",
               "Drop fragmented ICMP at the firewall (`iptables -A INPUT -p icmp -f -j DROP`).",
               "Block the sending addresses and check where they came from (switch MAC table / router logs)."]
        mitre = "T1499.004 Endpoint Denial of Service: Application or System Exploitation"
        f = Finding(kind="flood.icmp", category=Category.ATTACK, severity=Severity.HIGH, title=title, summary=summary,
                    explanation=expl, cause=cause, fix=fix, mitre=mitre, hosts=srcs[:5] + dsts[:5],
                    analogy="Like posting a parcel in pieces that, once assembled, is bigger than the letterbox.",
                    technical=(f"{self.pod.total} IPv4 ICMP fragments with offset*8 + payload > 65535 (fragment "
                               f"offset taken in 8-byte units); pairs: {', '.join(f'{s}->{d} ({n})' for (s, d), n in pairs)}."),
                    metrics={"fragments": self.pod.total, "sources": srcs[:10], "targets": dsts[:10], "pattern": "ping_of_death"},
                    indicators=[Indicator("ICMP fragments reassemble beyond the 65,535-byte IP maximum: impossible for "
                                          "a normal ping", Category.ATTACK, 3.0)],
                    variants={Category.ATTACK: Variant(title, summary, expl, cause, fix, mitre=mitre, severity=Severity.HIGH)})
        return self.pod.apply(f)

    # -- broadcast storm finding ----------------------------------------- #
    def _storm_finding(self, ctx: AnalysisContext) -> Finding | None:
        loop = self.loop_sigs > 0 and self.loop_dups >= self.thr_loop
        storm = self.b_storm_secs >= 1
        if not loop and not storm:
            return None
        frac = self.b_storm_frames / max(self.b_storm_total, 1) if storm else self.b_frames / max(ctx.packet_count, 1)
        top = self.b_top.top(5)
        top_share = top[0][1] / max(self.b_frames, 1) if top else 0.0
        labels = [f"{k} ({v:,})" for k, v in self.b_labels.most_common(5)]
        loop_macs = [m for m, _ in self.loop_macs.most_common(5)]
        ind: list[Indicator] = []
        if storm:
            ind.append(Indicator(f"Broadcast/multicast frames reached {self.b_peak:,}/s and made up {fmt_pct(frac)} of "
                                 f"all traffic for {plural(self.b_storm_secs, 'second')}", Category.FAULT, 2.0))
        if loop:
            ind.append(Indicator(f"The same broadcast frame was seen up to {self.loop_best:,} times, copies arriving "
                                 f"milliseconds apart with identical IP ID and TTL: frames are going round in a loop "
                                 "between switches", Category.FAULT, 3.0))
            if len(loop_macs) >= 2:
                ind.append(Indicator(f"Looping copies come from {len(loop_macs)} different devices, so the network "
                                     "itself is duplicating frames, not one device", Category.FAULT, 1.0))
        if storm and not loop and top and top_share >= 0.8:
            ind.append(Indicator(f"{fmt_pct(top_share)} of the broadcasts come from one device ({top[0][0]}) and they "
                                 "are not repeated copies: a faulty network card or a flooding program", Category.ATTACK, 1.0))
            ind.append(Indicator(f"A single misbehaving device ({top[0][0]}) can also be a broken NIC or driver",
                                 Category.FAULT, 1.0))
        sev = Severity.HIGH if (loop or self.b_peak >= 4 * self.thr_bc) else Severity.MEDIUM
        title = "Broadcast storm: the network is flooded with copies of the same messages"
        summary = (f"Broadcast traffic peaked at {self.b_peak:,} frames/s ({fmt_pct(frac)} of traffic)"
                   + (f"; one frame was copied {self.loop_best:,} times, the signature of a switching loop." if loop else "."))
        expl = ("Broadcast messages are delivered to every device on the network (like 'who has this address?'). "
                "When two switch ports are connected in a circle, each broadcast is forwarded round and round "
                "forever and multiplies, until the network is so busy that nothing else gets through; every computer "
                "slows down because it must look at every copy.")
        cause = ("A switching loop: a cable connecting two ports of the same switch (or two switches twice) while "
                 "Spanning Tree Protocol (STP) is disabled." if loop or not top_share >= 0.8 else
                 f"One device ({top[0][0]}) is sending broadcasts non-stop: a faulty network card, driver or program.")
        fix = [
            "Look for a recently plugged cable that connects two wall/switch ports together (a loop), and unplug it.",
            "Watch the switch port LEDs: the looped ports blink constantly; on managed switches check per-port "
            "broadcast counters / `show interfaces counters`.",
            "Enable Spanning Tree (STP/RSTP) and BPDU guard / loop protection on all access ports.",
            "Turn on storm control (broadcast rate limit) on switch ports.",
            ("Find the port of the top sender " + top[0][0] + " in the switch MAC table and disconnect it.") if top else
            "Find the busiest sender in the switch MAC table and disconnect it.",
        ]
        title_a = f"Broadcast flood from {top[0][0] if top else 'one device'}"
        f = Finding(
            kind="flood.broadcast", category=Category.FAULT, severity=sev, title=title, summary=summary,
            explanation=expl, cause=cause, fix=fix,
            analogy="Like an echo in a canyon that never fades: every shout comes back louder until nobody can talk.",
            technical=(f"Peak {self.b_peak} broadcast/control-multicast frames/s (threshold {self.thr_bc}/s and "
                       f">= {fmt_pct(BCAST_FRACTION)}); storm seconds {self.b_storm_secs}, storm share {fmt_pct(frac)}; "
                       f"loop signatures {self.loop_sigs}, duplicate copies {self.loop_dups}, max burst {self.loop_best} "
                       f"(>= {self.thr_loop} copies, mean gap < {LOOP_GAP * 1000:.0f} ms); protocols {', '.join(labels)}; "
                       f"top MACs {', '.join(f'{m} ({n:,})' for m, n in top)}."),
            hosts=loop_macs or [m for m, _ in top],
            metrics={"peak_per_s": self.b_peak, "storm_seconds": self.b_storm_secs, "broadcast_share": round(frac, 3),
                     "loop_signatures": self.loop_sigs, "duplicate_copies": self.loop_dups, "max_copies": self.loop_best,
                     "protocols": labels, "top_macs": [f"{m} ({n:,})" for m, n in top], "loop_macs": loop_macs},
            indicators=ind,
            variants={Category.FAULT: Variant(title, summary, expl, cause, fix, severity=sev,
                                              analogy="Like an echo in a canyon that never fades: every shout comes "
                                                      "back louder until nobody can talk.")},
        )
        if any(i.supports is Category.ATTACK for i in ind):
            f.variants[Category.ATTACK] = Variant(
                title_a, f"{fmt_pct(top_share)} of {self.b_frames:,} broadcast frames come from {top[0][0]}.",
                "A single device is deliberately flooding the network with broadcast frames, which every other device "
                "has to process. This can be a denial-of-service tool or malware.",
                "A flooding tool or malware on the device with MAC " + top[0][0] + ".",
                ["Find the switch port of " + top[0][0] + " (MAC table) and disconnect it.",
                 "Enable storm control on switch ports.", "Inspect the device for malware or a broken driver."],
                mitre="T1498.001 Network Denial of Service: Direct Network Flood", severity=Severity.HIGH)
        ev = Evidence()
        ev.merge(self.loop_ev)
        ev.merge(self.b_ev)
        return ev.apply(f)
