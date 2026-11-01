"""ARP detectors: IP conflict vs. ARP spoofing, ARP scans, unanswered ARP, ARP storms.

Kinds
-----
``arp.duplicate_ip``  one IPv4 address claimed by two or more MACs. A single
                      finding with two readings (MISCONFIG "IP conflict" and
                      ATTACK "ARP spoofing / MITM"); indicators decide.
``arp.scan``          one MAC asks for many distinct addresses in a short window.
``arp.unanswered``    repeated who-has for an address nobody answers.
``arp.storm``         sustained, obviously abnormal ARP rate.

This module also hosts small helpers (``clip``, ``clock``, ``make_finding``,
``evidence_of``) shared by the DHCP and DNS detectors.
"""

from __future__ import annotations

import math
import time
from array import array
from collections import Counter

from ..context import is_mac_multicast, is_multicast_or_broadcast, is_private
from .base import (
    AnalysisContext,
    BoundedDict,
    Category,
    Detector,
    Evidence,
    Finding,
    Indicator,
    Packet,
    Severity,
    Variant,
    plural,
    register,
)

ZERO_MAC = "00:00:00:00:00:00"
BCAST_MAC = "ff:ff:ff:ff:ff:ff"

# First-hop redundancy virtual MACs: VRRP (v4/v6), HSRPv1, HSRPv2, HSRP IPv6, GLBP.
VIRTUAL_MAC_PREFIXES = (
    "00:00:5e:00:01:", "00:00:5e:00:02:", "00:00:0c:07:ac:", "00:00:0c:9f:f",
    "00:05:73:a0:0", "00:07:b4:00:",
)


# --------------------------------------------------------------------------- #
# Shared helpers (also imported by dhcp.py / dns.py)
# --------------------------------------------------------------------------- #


def clip(s, n: int = 100) -> str:
    """Untrusted capture text -> short printable plain text."""
    if s is None:
        return ""
    s = str(s)
    if len(s) > n * 4:
        s = s[: n * 4]
    s = "".join(ch if ch.isprintable() else "?" for ch in s)
    return s if len(s) <= n else s[: n - 1] + "…"


def clock(ts: float | None) -> str:
    if ts is None:
        return "?"
    try:
        return time.strftime("%H:%M:%S", time.localtime(ts))
    except (OverflowError, OSError, ValueError):
        return "?"


def ip4_int(ip: str | None) -> int | None:
    if not ip:
        return None
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    try:
        a, b, c, d = (int(x) for x in parts)
    except ValueError:
        return None
    if not (0 <= a < 256 and 0 <= b < 256 and 0 <= c < 256 and 0 <= d < 256):
        return None
    return (a << 24) | (b << 16) | (c << 8) | d


def int_ip4(n: int) -> str:
    return f"{(n >> 24) & 255}.{(n >> 16) & 255}.{(n >> 8) & 255}.{n & 255}"


def valid_mac(mac: str | None) -> bool:
    return bool(mac) and mac != ZERO_MAC and mac != BCAST_MAC and not is_mac_multicast(mac)


def is_virtual_mac(mac: str | None) -> bool:
    return bool(mac) and mac.startswith(VIRTUAL_MAC_PREFIXES)


def evidence_of(frames, total: int | None = None, first_ts=None, last_ts=None) -> Evidence:
    ev = Evidence()
    seen = set()
    for no in frames:
        if no in seen:
            continue
        seen.add(no)
        if len(ev.packets) >= Evidence.CAP:
            break
        ev.packets.append(no)
    ev.total = max(total or 0, len(ev.packets))
    ev.first_ts, ev.last_ts = first_ts, last_ts
    return ev


def scores_of(indicators: list[Indicator]) -> dict[Category, float]:
    out: dict[Category, float] = {}
    for ind in indicators:
        out[ind.supports] = out.get(ind.supports, 0.0) + ind.weight
    return out


def make_finding(kind: str, variants: dict[Category, Variant], indicators: list[Indicator], *,
                 technical: str, hosts, metrics: dict, evidence: Evidence | None = None,
                 default: Category | None = None) -> Finding:
    """Build a Finding whose top-level wording is the variant with the highest
    summed indicator weight (the verdict engine may re-decide; we just keep the
    hint consistent with our own evidence)."""
    sc = scores_of(indicators)
    default = default or next(iter(variants))
    best = max(variants, key=lambda c: (round(sc.get(c, 0.0), 3), c == default))
    v = variants[best]
    hl: list[str] = []
    for h in hosts:
        if h and h not in hl:
            hl.append(h)
    f = Finding(
        kind=kind, category=best, severity=v.severity if v.severity is not None else Severity.MEDIUM,
        title=v.title, summary=v.summary, explanation=v.explanation, cause=v.cause, fix=list(v.fix),
        technical=technical, analogy=v.analogy, mitre=v.mitre, hosts=hl[:20], metrics=metrics,
        indicators=list(indicators), variants=dict(variants),
    )
    if evidence is not None:
        evidence.apply(f)
    return f


def shannon(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


# --------------------------------------------------------------------------- #
# Per-key state
# --------------------------------------------------------------------------- #


class _Claim:
    """One MAC asserting one IP via ARP sender fields."""

    __slots__ = ("n", "req", "rep", "solicited", "unprompted", "grat", "first_ts", "last_ts", "first_no",
                 "frames", "last_unp", "iv_n", "iv_sum", "iv_sq")

    def __init__(self, ts: float, no: int) -> None:
        self.n = self.req = self.rep = self.solicited = self.unprompted = self.grat = 0
        self.first_ts = self.last_ts = ts
        self.first_no = no
        self.frames: list[int] = []
        self.last_unp: float | None = None
        self.iv_n = 0
        self.iv_sum = 0.0
        self.iv_sq = 0.0


class _IpState:
    __slots__ = ("claims", "last_mac", "transitions", "probers", "probe_frames", "dual")

    def __init__(self) -> None:
        self.claims: dict[str, _Claim] = {}
        self.last_mac: str | None = None
        self.transitions = 0
        self.probers: set[str] = set()
        self.probe_frames: list[int] = []
        self.dual = 0  # requests answered by two different MACs


class _Mac:
    __slots__ = ("first_ts", "last_ts", "l3_srcs", "pub_src", "pub_dst", "pub_dst_first", "pub_dst_frames",
                 "pub_dst_victims", "pub_src_frames")

    def __init__(self, ts: float) -> None:
        self.first_ts = self.last_ts = ts
        self.l3_srcs: set[str] = set()
        self.pub_src = 0
        self.pub_dst = 0
        self.pub_dst_first: float | None = None
        self.pub_dst_frames: list[int] = []
        self.pub_dst_victims: set[str] = set()
        self.pub_src_frames: list[int] = []


class _Scan:
    __slots__ = ("spa", "spas", "ts", "tgt", "seen", "requests", "frames")

    def __init__(self, spa: str) -> None:
        self.spa = spa
        self.spas: set[str] = {spa}  # every sender address this MAC used (a router speaks for several subnets)
        self.ts = array("d")
        self.tgt = array("L")
        self.seen: set[int] = set()
        self.requests = 0
        self.frames: list[int] = []


class _Target:
    __slots__ = ("total", "requesters", "req_macs", "s_n", "s_first", "s_last", "s_frames",
                 "best", "alive_last", "ever_alive")

    def __init__(self) -> None:
        self.total = 0
        self.requesters: set[str] = set()
        self.req_macs: set[str] = set()
        self.s_n = 0
        self.s_first = self.s_last = 0.0
        self.s_frames: list[int] = []
        self.best: tuple | None = None  # (n, first, last, frames)
        self.alive_last: float | None = None
        self.ever_alive = False


# --------------------------------------------------------------------------- #
# Detector
# --------------------------------------------------------------------------- #


@register
class ArpDetector(Detector):
    name = "arp"

    SOLICIT_WINDOW = 5.0
    SCAN_WINDOW = 60.0
    SCAN_MIN = 30
    UNANSWERED_MIN = 3
    UNANSWERED_SPAN = 2.0
    STORM_RATE = 200
    STORM_SECONDS = 3

    def __init__(self) -> None:
        self.ips: BoundedDict = BoundedDict(65_536)          # ip -> _IpState
        self.mac_claims: BoundedDict = BoundedDict(65_536)   # mac -> set(ip) claimed in ARP
        self.l3: BoundedDict = BoundedDict(65_536)           # private ip -> {mac: [n, first, last]}
        self.macs: BoundedDict = BoundedDict(50_000)         # mac -> _Mac
        self.recent_req: BoundedDict = BoundedDict(100_000)  # (requester ip, target ip) -> ts
        self.last_req: BoundedDict = BoundedDict(20_000)     # target ip -> [ts, set(reply macs), counted]
        self.scans: BoundedDict = BoundedDict(2_048)         # mac -> _Scan
        self.targets: BoundedDict = BoundedDict(50_000)      # target ip -> _Target
        self.offered: BoundedDict = BoundedDict(20_000)      # yiaddr offered via DHCP -> ts (conflict checks)
        self.arp_total = 0
        # storm accounting
        self.sec = None
        self.sec_n = 0
        self.sec_keys: set = set()
        self.run = 0
        self.max_run = 0
        self.heavy_secs = 0
        self.peak_rate = 0
        self.storm_senders: Counter = Counter()
        self.storm_frames: list[int] = []
        self.storm_first: float | None = None
        self.storm_last: float | None = None
        self.storm_uniq = 0
        self.storm_pkts = 0
        self.storm_thr = None

    # ------------------------------------------------------------------ #
    def _mac(self, mac: str, ts: float) -> _Mac:
        m = self.macs.get(mac)
        if m is None:
            m = _Mac(ts)
            self.macs[mac] = m
        else:
            self.macs.move_to_end(mac)
            if ts > m.last_ts:
                m.last_ts = ts
            elif ts < m.first_ts:
                m.first_ts = ts
        return m

    def _alive(self, ip: str, ts: float) -> None:
        t = self.targets.get(ip)
        if t is None:
            return
        if t.s_n and (t.best is None or t.s_n > t.best[0]):
            t.best = (t.s_n, t.s_first, t.s_last, list(t.s_frames))
        t.s_n = 0
        t.s_frames = []
        t.alive_last = ts
        t.ever_alive = True

    # ------------------------------------------------------------------ #
    def on_packet(self, pkt: Packet, ctx: AnalysisContext) -> None:
        ts = pkt.ts if pkt.ts is not None else 0.0
        a = pkt.arp
        es = pkt.eth_src
        if a is None:
            d = pkt.dhcp
            if d is not None and d.msg_type in (2, 5) and d.yiaddr and d.yiaddr != "0.0.0.0":
                self.offered[d.yiaddr] = ts
            if es and valid_mac(es):
                m = self._mac(es, ts)
                if pkt.ip_ver == 4 and pkt.src:
                    self._ip_frame(pkt, es, m, ts)
            return
        self.arp_total += 1
        self._storm(pkt, a, ts, ctx)
        sha = (a.sha or "").lower()
        spa, tpa = a.spa or "", a.tpa or ""
        if not valid_mac(sha) or not tpa:
            return
        self._mac(sha, ts)
        op = a.op
        if op == 1 and spa == "0.0.0.0":  # RFC 5227 probe (DAD)
            st = self._ip(tpa)
            if st is not None:
                if len(st.probers) < 8:
                    st.probers.add(sha)
                if len(st.probe_frames) < 10:
                    st.probe_frames.append(pkt.no)
            self.recent_req[("0.0.0.0", tpa)] = ts
            return
        if not spa or spa == "0.0.0.0":
            return
        grat = spa == tpa
        if op == 1:
            self._claim(spa, sha, ts, pkt.no, kind="grat" if grat else "req")
            if not grat:
                self.recent_req[(spa, tpa)] = ts
                self.last_req[tpa] = [ts, set(), False]
                self._scan(sha, spa, tpa, ts, pkt.no)
                self._unanswered(sha, spa, tpa, ts, pkt.no)
        elif op == 2:
            if grat:
                kind = "grat"
            else:
                rts = self.recent_req.get((tpa, spa))
                kind = "solicited" if rts is not None and 0 <= ts - rts <= self.SOLICIT_WINDOW else "unsolicited"
            self._claim(spa, sha, ts, pkt.no, kind=kind)
            lr = self.last_req.get(spa)
            if lr is not None and 0 <= ts - lr[0] <= 1.0:
                lr[1].add(sha)
                if len(lr[1]) >= 2 and not lr[2]:
                    lr[2] = True
                    st = self.ips.get(spa)
                    if st is not None:
                        st.dual += 1
        self._alive(spa, ts)

    def _ip(self, ip: str) -> _IpState | None:
        st = self.ips.get(ip)
        if st is None:
            st = _IpState()
            self.ips[ip] = st
        else:
            self.ips.move_to_end(ip)
        return st

    def _claim(self, ip: str, mac: str, ts: float, no: int, kind: str) -> None:
        st = self._ip(ip)
        c = st.claims.get(mac)
        if c is None:
            if len(st.claims) >= 8:
                return
            c = st.claims[mac] = _Claim(ts, no)
        c.n += 1
        if ts > c.last_ts:
            c.last_ts = ts
        if kind == "req":
            c.req += 1
        elif kind == "grat":
            c.grat += 1
        else:
            c.rep += 1
            if kind == "solicited":
                c.solicited += 1
        unprompted = kind == "unsolicited" or (kind == "grat" and c.grat > 3)
        if unprompted:
            c.unprompted += 1
            if c.last_unp is not None:
                iv = ts - c.last_unp
                if iv >= 0:
                    c.iv_n += 1
                    c.iv_sum += iv
                    c.iv_sq += iv * iv
            c.last_unp = ts
        # keep replies / announcements preferentially as evidence
        if len(c.frames) < 40 and (kind != "req" or len(c.frames) < 10):
            c.frames.append(no)
        if st.last_mac != mac:
            if st.last_mac is not None:
                st.transitions += 1
            st.last_mac = mac
        ips = self.mac_claims.get(mac)
        if ips is None:
            ips = self.mac_claims[mac] = set()
        if len(ips) < 64:
            ips.add(ip)

    def _ip_frame(self, pkt: Packet, es: str, m: _Mac, ts: float) -> None:
        src, dst = pkt.src, pkt.dst
        if is_private(src):
            if src != "0.0.0.0":
                if len(m.l3_srcs) < 16:
                    m.l3_srcs.add(src)
                e = self.l3.get(src)
                if e is None:
                    e = self.l3[src] = {}
                r = e.get(es)
                if r is None:
                    if len(e) < 4:
                        e[es] = [1, ts, ts]
                else:
                    r[0] += 1
                    r[2] = ts
                self._alive(src, ts)
        else:
            m.pub_src += 1
            if len(m.pub_src_frames) < 10:
                m.pub_src_frames.append(pkt.no)
        ed = pkt.eth_dst
        if dst and ed and valid_mac(ed) and not is_private(dst) and not is_multicast_or_broadcast(dst):
            dm = self._mac(ed, ts)
            dm.pub_dst += 1
            if dm.pub_dst_first is None:
                dm.pub_dst_first = ts
            if len(dm.pub_dst_frames) < 20:
                dm.pub_dst_frames.append(pkt.no)
            if len(dm.pub_dst_victims) < 16 and is_private(src):
                dm.pub_dst_victims.add(src)

    def _scan(self, sha: str, spa: str, tpa: str, ts: float, no: int) -> None:
        s = self.scans.get(sha)
        if s is None:
            s = self.scans[sha] = _Scan(spa)
        else:
            self.scans.move_to_end(sha)
        s.requests += 1
        if len(s.spas) < 16 and spa and spa != "0.0.0.0":
            s.spas.add(spa)
        if len(s.seen) >= 1024:
            return
        ti = ip4_int(tpa)
        if ti is None or ti in s.seen:
            return
        s.seen.add(ti)
        s.ts.append(ts)
        s.tgt.append(ti)
        if len(s.frames) < 200:
            s.frames.append(no)

    def _unanswered(self, sha: str, spa: str, tpa: str, ts: float, no: int) -> None:
        if tpa == spa or is_multicast_or_broadcast(tpa) or tpa.startswith("0."):
            return
        t = self.targets.get(tpa)
        if t is None:
            t = self.targets[tpa] = _Target()
        else:
            self.targets.move_to_end(tpa)
        t.total += 1
        if len(t.requesters) < 16:
            t.requesters.add(spa)
        if len(t.req_macs) < 16:
            t.req_macs.add(sha)
        if t.s_n == 0:
            t.s_first = ts
        t.s_n += 1
        t.s_last = max(t.s_last, ts) if t.s_n > 1 else ts
        if len(t.s_frames) < 20:
            t.s_frames.append(no)

    def _storm(self, pkt: Packet, a, ts: float, ctx: AnalysisContext) -> None:
        if self.storm_thr is None:
            self.storm_thr = self.STORM_RATE * ctx.config.scale
        sec = int(ts)
        if sec != self.sec:
            self._close_second()
            self.sec = sec
            self.sec_n = 0
            self.sec_keys = set()
        self.sec_n += 1
        if self.sec_n > self.storm_thr:
            sha = a.sha or "?"
            if sha in self.storm_senders or len(self.storm_senders) < 1000:
                self.storm_senders[sha] += 1
            if len(self.sec_keys) < 5000:
                self.sec_keys.add((a.op, sha, a.spa, a.tpa))
            self.storm_pkts += 1
            if len(self.storm_frames) < 200:
                self.storm_frames.append(pkt.no)
            if self.storm_first is None:
                self.storm_first = ts
            self.storm_last = ts

    def _close_second(self) -> None:
        if self.sec is None:
            return
        if self.storm_thr is not None and self.sec_n > self.storm_thr:
            self.run += 1
            self.heavy_secs += 1
            self.max_run = max(self.max_run, self.run)
            self.peak_rate = max(self.peak_rate, self.sec_n)
            self.storm_uniq += len(self.sec_keys)
        else:
            self.run = 0

    # ------------------------------------------------------------------ #
    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        self._close_second()
        for ip in list(self.targets.keys()):  # flush open streaks
            t = self.targets[ip]
            if t.s_n and (t.best is None or t.s_n > t.best[0]):
                t.best = (t.s_n, t.s_first, t.s_last, list(t.s_frames))
        scale = ctx.config.scale
        self._gw_ips, _ = ctx.hosts.gateway()
        self._dhcp_routers = {ip for ip, _ in ctx.hosts.dhcp_routers.most_common(3)}
        out: list[Finding] = []
        scans = self._find_scans(ctx, scale)
        out.extend(f for _, f in scans)
        scanner_macs = {m for m, _ in scans}
        out.extend(self._find_conflicts(ctx))
        out.extend(self._find_unanswered(ctx, scanner_macs))
        storm = self._find_storm(ctx, scanner_macs)
        if storm:
            out.append(storm)
        return out

    # -- helpers ---------------------------------------------------------- #
    def _router_like(self, mac: str) -> bool:
        m = self.macs.get(mac)
        return m is not None and (m.pub_src >= 3 or len(m.l3_srcs) >= 3)

    def _is_gateway(self, ip: str, legit_mac: str | None = None) -> bool:
        if ip in self._dhcp_routers:
            return True
        if legit_mac is not None:
            m = self.macs.get(legit_mac)
            if m is not None and m.pub_src >= 3:
                return True
        if ip in self._gw_ips:
            t = self.targets.get(ip)
            if ip.endswith((".1", ".254")) or (t is not None and len(t.requesters) >= 3):
                return True
        return False

    def _role(self, ctx: AnalysisContext, ip: str) -> str | None:
        h = ctx.hosts.hosts.get(ip)
        if h is None:
            return None
        for r in ("dns-server", "dhcp-server"):
            if r in h.roles:
                return r
        return None

    # -- duplicate IP / spoofing ------------------------------------------ #
    def _find_conflicts(self, ctx: AnalysisContext) -> list[Finding]:
        conflicts = []  # (ip, legit, suspect, st, l3entry)
        for ip, st in self.ips.items():
            if ip.startswith(("169.254.", "0.")) or is_multicast_or_broadcast(ip):
                continue
            l3e = self.l3.get(ip) or {}
            macs = {m for m, c in st.claims.items() if c.n >= 1}
            for m, r in l3e.items():
                if r[0] >= 3 and not self._router_like(m):
                    macs.add(m)
            if len(macs) < 2:
                continue
            legit = self._pick_legit(ip, st, l3e, macs)
            for sus in sorted(macs - {legit}):
                c = st.claims.get(sus)
                if c is None:
                    # IP-layer use only, never ARP: that is source-address spoofing (e.g. forged DNS
                    # replies), not a device that believes the address is its own.
                    continue
                weight = c.n + (l3e[sus][0] if sus in l3e else 0)
                if weight < 2:
                    continue
                # active-interval overlap: an address that simply moved to a new MAC is fine
                sus_first = min([x for x in ((c.first_ts if c else None), (l3e[sus][1] if sus in l3e else None))
                                 if x is not None])
                lm = self.macs.get(legit)
                legit_last = lm.last_ts if lm is not None else None
                if legit_last is None:
                    lc = st.claims.get(legit)
                    legit_last = lc.last_ts if lc else (l3e[legit][2] if legit in l3e else None)
                if legit_last is None or legit_last < sus_first:
                    continue
                conflicts.append((ip, legit, sus, st, l3e))
        if not conflicts:
            return []
        groups: dict[str, list] = {}
        for c in conflicts:
            groups.setdefault(c[2], []).append(c)
        out = []
        for sus, items in sorted(groups.items(), key=lambda kv: -len(kv[1]))[:10]:
            out.append(self._conflict_finding(ctx, sus, items))
        return out

    def _pick_legit(self, ip: str, st: _IpState, l3e: dict, macs: set[str]) -> str:
        def first_seen(m):
            c = st.claims.get(m)
            vals = [c.first_ts] if c else []
            if m in l3e:
                vals.append(l3e[m][1])
            return min(vals) if vals else float("inf")

        firsts = {m: first_seen(m) for m in macs}
        earliest = min(firsts.values())
        counts = {m: (st.claims[m].n if m in st.claims else 0) + (l3e[m][0] if m in l3e else 0) for m in macs}
        top = max(counts.values())
        best, best_score = None, None
        for m in sorted(macs):
            c = st.claims.get(m)
            s = 0.0
            if firsts[m] == earliest:
                s += 2
            if counts[m] == top:
                s += 1
            if c is not None and c.rep:
                s += 1 if c.solicited >= c.unprompted else -1
            elif c is not None and c.unprompted > 3:
                s -= 1
            if m in l3e and l3e[m][0] >= 3:
                s += 1
            if is_virtual_mac(m):
                s += 0.5
            if best_score is None or s > best_score:
                best, best_score = m, s
        return best

    def _conflict_finding(self, ctx: AnalysisContext, sus: str, items: list) -> Finding:
        ips = [it[0] for it in items]
        legits = {it[0]: it[1] for it in items}
        claims = [it[3].claims.get(sus) for it in items]
        ip0, legit0, _, st0, l3e0 = items[0]
        sm = self.macs.get(sus)
        unprompted = sum(c.unprompted for c in claims if c)
        solicited = sum(c.solicited for c in claims if c)
        grat = sum(c.grat for c in claims if c)
        sus_claims = sum(c.n for c in claims if c)
        sus_first = min((c.first_ts for c in claims if c), default=None)
        if sus_first is None:
            sus_first = min(it[4][sus][1] for it in items if sus in it[4])
        sus_last = max((c.last_ts for c in claims if c), default=sus_first)
        gw_ips = [ip for ip, lg in legits.items() if self._is_gateway(ip, lg)]
        roles = {ip: self._role(ctx, ip) for ip in ips}
        own_ips = sorted((self.mac_claims.get(sus) or set()) - set(ips))
        legit_owners = set(legits.values())
        virtual = any(is_virtual_mac(sus) or is_virtual_mac(lg) for lg in legit_owners)
        adjacent = any(_adjacent_macs(sus, lg) for lg in legit_owners)
        transitions = sum(it[3].transitions for it in items)
        dual = sum(it[3].dual for it in items)
        probed = sorted({it[0] for it in items if it[3].probers})
        # steadiness of unprompted announcements
        iv_n = sum(c.iv_n for c in claims if c)
        iv_sum = sum(c.iv_sum for c in claims if c)
        iv_sq = sum(c.iv_sq for c in claims if c)
        mean_iv = iv_sum / iv_n if iv_n else None
        cv = None
        if iv_n >= 4 and mean_iv and mean_iv > 0:
            var = max(0.0, iv_sq / iv_n - mean_iv * mean_iv)
            cv = math.sqrt(var) / mean_iv
        redirected = sm.pub_dst if sm is not None and sm.pub_dst_first is not None and sm.pub_dst_first >= sus_first - 1 else 0
        relayed = sm.pub_src if sm is not None else 0
        span = max(1.0, (sus_last or sus_first) - sus_first)
        rate_per_min = sus_claims / span * 60 if sus_claims > 1 else 0.0
        both_traffic = all(
            sus in it[4] and it[4][sus][0] >= 3 and it[1] in it[4] and it[4][it[1]][0] >= 3
            and not self._router_like(sus) for it in items
        )

        ip_list = ", ".join(ips[:4]) + ("…" if len(ips) > 4 else "")
        ind: list[Indicator] = []
        A, M = Category.ATTACK, Category.MISCONFIG
        if gw_ips:
            ind.append(Indicator(f"The disputed address {gw_ips[0]} belongs to the router (default gateway)", A, 2.0))
        else:
            ind.append(Indicator(f"The disputed address {ip0} is not the router's", M, 1.0))
        srv = [f"{ip} ({r})" for ip, r in roles.items() if r and ip not in gw_ips]
        if srv:
            ind.append(Indicator(f"The disputed address is a server on this network: {', '.join(srv[:3])}", A, 1.0))
        if unprompted >= 3:
            ind.append(Indicator(f"The suspicious MAC {sus} sent {unprompted} ARP replies nobody asked for", A,
                                 2.0 if unprompted >= 10 else 1.5))
        elif unprompted == 0 and (solicited or grat):
            ind.append(Indicator(f"The suspicious MAC {sus} only answered when asked (no unsolicited ARP replies)", M, 1.0))
        if cv is not None and cv < 0.5 and unprompted >= 5:
            ind.append(Indicator(f"Those replies repeat like clockwork, about every {mean_iv:.1f} s "
                                 f"(typical of a poisoning tool keeping caches poisoned)", A, 1.0))
        multi_owner = len(ips) >= 2 and len(legit_owners) >= 2
        if multi_owner:
            ind.append(Indicator(f"The suspicious MAC answered ARP for {len(ips)} different IPs that belong to other "
                                 f"devices ({ip_list})", A, 2.5))
        elif len(self.mac_claims.get(sus) or ()) <= 1:
            ind.append(Indicator(f"The suspicious MAC {sus} claims only this one address", M, 1.0))
        if own_ips:
            ind.append(Indicator(f"The suspicious MAC also uses its own, different address {own_ips[0]}, "
                                 f"so it is a separate device posing as {ip0}", A, 1.0))
        if transitions >= 4 and unprompted >= 3:
            ind.append(Indicator(f"The owner of {ip0} flipped between the two MACs {transitions} times while the "
                                 f"original MAC stayed active", A, 1.0))
        elif transitions <= 2:
            ind.append(Indicator("Both MACs were stable: the owner of the address changed only rarely", M, 0.5))
        if redirected >= 5:
            ind.append(Indicator(f"{plural(redirected, 'packet')} meant for internet addresses were sent to the "
                                 f"suspicious MAC instead of the router", A, 2.0))
        if relayed >= 5:
            ind.append(Indicator(f"The suspicious device is relaying internet traffic ({relayed} frames), "
                                 f"classic man-in-the-middle forwarding", A, 1.0))
        if probed:
            ind.append(Indicator(f"A device probed {probed[0]} before using it (RFC 5227 duplicate-address check), "
                                 f"which is normal boot behaviour", M, 1.5))
        if 0 < grat <= 3 and unprompted == 0:
            ind.append(Indicator("The newcomer announced itself with a gratuitous ARP once, like a device joining "
                                 "the network", M, 0.5))
        if both_traffic:
            ind.append(Indicator(f"Both MACs send their own normal traffic from {ip0}: two real devices think the "
                                 f"address is theirs", M, 1.5))
        if dual:
            ind.append(Indicator(f"Both MACs answered the same ARP question {plural(dual, 'time')}, which is what two "
                                 f"honest devices with the same address do", M, 1.0))
        if sus_claims >= 2 and rate_per_min <= 6 and unprompted < 3:
            ind.append(Indicator(f"Low ARP rate from the newcomer ({rate_per_min:.1f} per minute)", M, 0.5))
        if adjacent:
            ind.append(Indicator("The two MACs are consecutive addresses from the same manufacturer, probably two "
                                 "network ports of one device", M, 2.0))
        if virtual:
            ind.append(Indicator("A router-redundancy virtual MAC (VRRP/HSRP/GLBP) is involved; routers sharing a "
                                 "virtual address legitimately hand it over", M, 2.0))

        sc = scores_of(ind)
        is_gw = bool(gw_ips)
        target = gw_ips[0] if is_gw else ip0
        legit = legits.get(target, legit0)
        att_sev = Severity.CRITICAL if is_gw and redirected >= 5 else Severity.HIGH
        mis_sev = Severity.HIGH if is_gw else Severity.MEDIUM
        if adjacent or virtual:
            mis_sev = Severity.LOW
        lc = items[0][3].claims.get(legit)

        attack = Variant(
            title=f"Someone is impersonating {target} (ARP spoofing / man-in-the-middle)",
            summary=(f"The device with MAC {sus} keeps claiming to be {ip_list} "
                     f"({plural(sus_claims, 'ARP claim')}, {unprompted} unsolicited), although {legit} owns "
                     f"{target}."),
            explanation=(
                "On a local network, devices use ARP to ask 'who has this IP address?' and trust whoever answers. "
                f"Here a device keeps sending fake answers saying that {target} lives at its MAC address {sus}. "
                "Devices that believe it send their traffic to the impostor, which can read or modify it before "
                "passing it on, so the network may only feel slow or flaky to users."
                + (" Because the impersonated address is your router, internet traffic can pass through the attacker."
                   if is_gw else "")),
            cause=(f"ARP cache poisoning from the device with MAC {sus}"
                   + (f" (its own address is {own_ips[0]})" if own_ips else "")
                   + ", for example a tool like arpspoof, ettercap or bettercap."),
            fix=[
                f"Find the device: look up MAC {sus} in your switch's MAC address table (or the router's client list) "
                "to get its port or Wi-Fi name, then disconnect it.",
                f"Check your own ARP cache with `arp -a` (Windows/macOS) or `ip neigh` (Linux): {target} should map to "
                f"{legit}, not {sus}.",
                f"As a temporary measure, pin the router: `arp -s {target} {legit}` (Linux/macOS) or "
                f"`netsh interface ipv4 add neighbors \"Ethernet\" {target} {legit.replace(':', '-')}` (Windows).",
                "Enable Dynamic ARP Inspection (with DHCP snooping) and port security on managed switches.",
                "Treat passwords typed while this was happening as exposed: change them, and prefer HTTPS/VPN.",
            ],
            analogy="Like someone changing the house numbers on your street so your post is delivered to them first.",
            mitre="T1557.002 ARP Cache Poisoning",
            severity=att_sev,
        )
        misconf = Variant(
            title=("A router-redundancy hand-over or a two-port device shares an address" if (adjacent or virtual)
                   else "Two devices are using the same IP address"),
            summary=(f"{target} is being used by two devices at once: {legit} and {sus} "
                     f"({plural(sus_claims, 'claim')} from the newcomer)."),
            explanation=(
                "Every device on a network needs its own IP address. When two devices are given the same one, "
                "they keep 'stealing' it from each other, so both lose their connection randomly. "
                "This usually happens when someone sets a fixed (static) IP that the DHCP server also hands out, "
                "or two devices were configured by hand with the same number."
                + (" Because the address is the router's, many devices can lose their internet connection." if is_gw else "")),
            cause=("A static IP address that overlaps with another device or with the DHCP pool"
                   if not (adjacent or virtual) else "Two interfaces of one device, or redundant routers, answering for one address"),
            fix=[
                f"Find both devices: look up {legit} and {sus} in the router's client list or switch MAC table.",
                "On the device with the fixed address, switch to automatic (DHCP): Windows `ipconfig /all` to check, "
                "then set 'Obtain an IP address automatically'; Linux `ip addr`.",
                "If you need static addresses, pick them outside the DHCP range, or use DHCP reservations on the router.",
                "Run `ipconfig /release` and `ipconfig /renew` (or reconnect Wi-Fi) on the affected devices.",
            ],
            analogy="Like two houses on the same street with the same house number: the post goes to one or the other at random.",
            severity=mis_sev,
        )
        def_cat = Category.ATTACK if sc.get(A, 0) > sc.get(M, 0) else Category.MISCONFIG
        frames: list[int] = []
        for c in claims:
            if c:
                frames.extend(c.frames)
        if lc:
            frames.extend(lc.frames[:20])
        for it in items:
            frames.extend(it[3].probe_frames)
        if sm is not None and redirected:
            frames.extend(sm.pub_dst_frames[:10])
        firsts = [x for x in (sus_first, lc.first_ts if lc else None) if x is not None]
        lasts = [x for x in (sus_last, lc.last_ts if lc else None) if x is not None]
        ev = evidence_of(sorted(frames), total=sus_claims + (lc.n if lc else 0) + redirected,
                         first_ts=min(firsts) if firsts else None, last_ts=max(lasts) if lasts else None)
        tech = (
            f"IP {ip_list} claimed by MAC {sus} ({sus_claims} ARP sender claims: {sum(c.rep for c in claims if c)} replies, "
            f"{solicited} solicited, {unprompted} unprompted, {grat} gratuitous; first at {clock(sus_first)}); "
            f"likely legitimate owner of {target}: {legit}"
            f"{f' ({lc.n} claims, first at {clock(lc.first_ts)})' if lc else ''}. "
            f"Owner transitions: {transitions}; dual answers to one request: {dual}."
            + (f" Mean unprompted interval {mean_iv:.2f} s (CV {cv:.2f})." if cv is not None else "")
            + (f" Suspect MAC also claims {', '.join(own_ips[:3])}." if own_ips else "")
            + (f" {redirected} frames to public IPs were addressed to {sus}"
               f"{' from ' + ', '.join(sorted(sm.pub_dst_victims)[:5]) if sm and sm.pub_dst_victims else ''}." if redirected else "")
            + (f" Gateway: {', '.join(gw_ips)}." if gw_ips else "")
        )
        metrics = {
            "ips": ips[:10], "suspect_mac": sus, "legit_macs": {ip: legits[ip] for ip in ips[:10]},
            "suspect_claims": sus_claims, "unsolicited_replies": unprompted, "solicited_replies": solicited,
            "gratuitous": grat, "transitions": transitions, "dual_answers": dual,
            "mean_interval_s": round(mean_iv, 3) if mean_iv else None, "interval_cv": round(cv, 3) if cv is not None else None,
            "suspect_own_ips": own_ips[:10], "redirected_frames": redirected, "relayed_frames": relayed,
            "gateway_claimed": is_gw, "probed": probed[:10],
        }
        hosts = list(ips) + own_ips[:3]
        return make_finding("arp.duplicate_ip", {Category.ATTACK: attack, Category.MISCONFIG: misconf}, ind,
                            technical=tech, hosts=hosts, metrics=metrics, evidence=ev, default=def_cat)

    # -- scans ------------------------------------------------------------ #
    def _find_scans(self, ctx: AnalysisContext, scale: float) -> list[tuple[str, Finding]]:
        out = []
        thr = max(8, int(round(self.SCAN_MIN * scale)))
        for mac, s in self.scans.items():
            n = len(s.ts)
            if n < thr:
                continue
            order = sorted(range(n), key=lambda i: s.ts[i])
            tsl = [s.ts[i] for i in order]
            tg = [s.tgt[i] for i in order]
            best, bi, bj, i = 0, 0, 0, 0
            for j in range(n):
                while tsl[j] - tsl[i] > self.SCAN_WINDOW:
                    i += 1
                if j - i + 1 > best:
                    best, bi, bj = j - i + 1, i, j
            if best < thr:
                continue
            win = sorted(tg[bi:bj + 1])
            diffs = [b - a for a, b in zip(win, win[1:])]
            seq = sum(1 for d in diffs if d <= 2) / len(diffs) if diffs else 0.0
            dur = max(0.001, tsl[bj] - tsl[bi])
            rate = best / dur
            answered = sum(1 for t in win if ctx.hosts.arp_claims.get(int_ip4(t)))
            ans_frac = answered / len(win)
            # One MAC answering for several subnets' gateway addresses (x.x.x.1 / .254) is a router doing
            # neighbour resolution for its customers (e.g. an ISP cable head-end), not a scanner.
            gw_like = [ip for ip in s.spas if ip.rsplit(".", 1)[-1] in ("1", "254")]
            multi_subnet_router = len({ip.rsplit(".", 1)[0] for ip in s.spas}) >= 2 and len(gw_like) >= 2
            # Scanners ask each address once or twice; routers re-ask the same absent hosts over and over.
            repeats = s.requests / max(1, len(s.seen))
            retrying = repeats >= 1.5 and seq < 0.3
            infra = (self._role(ctx, s.spa) == "dhcp-server" or self._is_gateway(s.spa, mac) or self._router_like(mac)
                     or multi_subnet_router)
            if infra and (ans_frac >= 0.5 or seq < 0.5 or rate < 1.0):
                continue
            if retrying and seq < 0.3 and s.spa.rsplit(".", 1)[-1] in ("1", "254"):
                continue  # a gateway retrying unreachable neighbours in random order
            offered = sum(1 for t in win if int_ip4(t) in self.offered)
            if offered / len(win) >= 0.5:
                continue  # DHCP server checking addresses before handing them out (conflict detection)
            lo, hi = int_ip4(win[0]), int_ip4(win[-1])
            A, M = Category.ATTACK, Category.MISCONFIG
            ind = [Indicator(f"{s.spa} ({mac}) asked for {best} different addresses within {dur:.0f} s", A,
                             2.5 if best >= 2 * thr else 2.0)]
            if seq >= 0.7:
                ind.append(Indicator(f"The addresses were tried in order ({lo} … {hi}), like a sweep", A, 1.0))
            if ans_frac < 0.5:
                ind.append(Indicator(f"{fmt_frac(1 - ans_frac)} of the asked addresses don't exist: it is probing "
                                     f"for devices rather than talking to known ones", A, 1.0))
            if rate >= 10:
                ind.append(Indicator(f"Very fast: {rate:.0f} new addresses per second", A, 0.5))
            if infra:
                ind.append(Indicator(f"{s.spa} is network infrastructure (router/DHCP server), which ARPs many hosts", M, 1.5))
            if ans_frac >= 0.8 and rate < 2:
                ind.append(Indicator("Slow and mostly aimed at existing devices, like an inventory/monitoring tool", M, 1.5))
            sev = Severity.HIGH if best >= 200 else Severity.MEDIUM
            attack = Variant(
                title=f"A device is scanning the network for targets ({s.spa})",
                summary=f"{s.spa} ({mac}) asked for {best} different IP addresses within {dur:.0f} seconds.",
                explanation=(
                    "Before attacking, someone usually maps the network to see which devices exist. The quickest way "
                    "on a local network is to ARP every address ('who has .1? who has .2? …') and note who answers. "
                    "This device did exactly that. Scanning alone does no damage, but it is often the first step of an attack."),
                cause=f"A network scanner (nmap -sn, arp-scan, netdiscover or malware) running on {s.spa}.",
                fix=[
                    f"Identify the device {s.spa} / {mac} in your router's client list or switch MAC table.",
                    "Ask its owner whether they run a scanner (IT inventory tools do this); if not, disconnect it "
                    "and check it for malware.",
                    "Watch for what follows the scan (connection attempts, ARP spoofing) in later captures.",
                    "On managed switches, enable port security and ARP rate limiting (Dynamic ARP Inspection).",
                ],
                analogy="Like someone walking down your street trying every door handle to see which houses are occupied.",
                mitre="T1018 Remote System Discovery",
                severity=sev,
            )
            benign = Variant(
                title=f"A device is mapping the network ({s.spa}), probably an inventory tool",
                summary=f"{s.spa} asked for {best} addresses in {dur:.0f} s, mostly devices that exist.",
                explanation=("Some legitimate tools (router device lists, monitoring and inventory software) "
                             "periodically ask for every address on the network. This looks like that."),
                cause="A network inventory/monitoring tool or a router refreshing its neighbour table.",
                fix=["Confirm which software on the device is doing this.",
                     "If it is expected, no action is needed; otherwise treat it as a scan."],
                analogy="Like the postman checking which houses are occupied.",
                severity=Severity.LOW,
            )
            ev = evidence_of(s.frames, total=best, first_ts=tsl[bi], last_ts=tsl[bj])
            tech = (f"ARP who-has from {s.spa} / {mac}: {best} distinct targets in {dur:.1f} s "
                    f"({rate:.1f}/s, {s.requests} requests total); range {lo}–{hi}; sequential fraction {seq:.2f}; "
                    f"{answered}/{len(win)} targets answered.")
            metrics = {"scanner_ip": s.spa, "scanner_mac": mac, "distinct_targets": best, "window_s": round(dur, 2),
                       "rate_per_s": round(rate, 2), "sequential_fraction": round(seq, 3),
                       "answered_fraction": round(ans_frac, 3), "first_target": lo, "last_target": hi}
            out.append((mac, make_finding("arp.scan", {A: attack, M: benign}, ind, technical=tech, hosts=[s.spa],
                                          metrics=metrics, evidence=ev, default=A)))
        out.sort(key=lambda x: -x[1].metrics["distinct_targets"])
        return out[:5]

    # -- unanswered ------------------------------------------------------- #
    def _find_unanswered(self, ctx: AnalysisContext, scanner_macs: set[str]) -> list[Finding]:
        cands = []
        for ip, t in self.targets.items():
            if t.best is None:
                continue
            n, first, last, frames = t.best
            if n < self.UNANSWERED_MIN or last - first < self.UNANSWERED_SPAN:
                continue
            if t.req_macs and t.req_macs <= scanner_macs:
                continue
            if ip.startswith("169.254.") or (ip in self.offered and not t.ever_alive and n <= 4):
                continue
            # requesters that are themselves only scanners for this subnet with many dead targets
            cands.append((ip, t, n, first, last, frames))
        if not cands:
            return []
        dead_total = len(cands)
        cands.sort(key=lambda c: (not self._is_gateway(c[0]), -c[2]))
        out = []
        for ip, t, n, first, last, frames in cands[:5]:
            gw = self._is_gateway(ip)
            role = self._role(ctx, ip)
            nreq = len(t.requesters)
            F, M = Category.FAULT, Category.MISCONFIG
            ind = [Indicator(f"{plural(n, 'ARP request')} for {ip} over {last - first:.0f} s got no answer", F, 1.5)]
            if t.ever_alive and t.alive_last is not None and t.alive_last <= first:
                ind.append(Indicator(f"{ip} was answering until {clock(t.alive_last)} and then went silent", F, 2.0))
            if nreq >= 2:
                ind.append(Indicator(f"{nreq} different devices are trying to reach {ip}", F, 1.0))
            if not t.ever_alive and nreq == 1:
                ind.append(Indicator(f"{ip} never answered at any point and only one device asks for it: that "
                                     f"device may have a wrong address configured", M, 1.0))
            if gw:
                sev = Severity.HIGH
                title = f"Your router ({ip}) isn't responding at all"
            elif role:
                sev = Severity.HIGH if n >= 10 else Severity.MEDIUM
                title = f"The {role.replace('-', ' ')} {ip} isn't responding"
            else:
                sev = Severity.MEDIUM if (nreq >= 2 and n >= 10) else Severity.LOW
                title = f"Device {ip} is offline or unplugged"
            fault = Variant(
                title=title,
                summary=(f"{plural(nreq, 'device')} asked for {ip} {plural(n, 'time')} over {last - first:.0f} s "
                         f"and nobody answered."),
                explanation=(
                    "Before talking to a device on the local network, a computer asks 'who has this address?' (ARP). "
                    f"Nobody answered for {ip}, so nothing can reach it: the device is switched off, unplugged, "
                    "out of Wi-Fi range or has crashed."
                    + (" Because it is your router, no device can reach the internet." if gw else "")),
                cause=(f"The router {ip} is powered off, frozen or disconnected from this network segment" if gw
                       else f"{ip} is offline (powered off, unplugged, or on another network)"),
                fix=([
                    "Check the router's power and lights; restart it (unplug for 30 seconds).",
                    "Check the cable between this switch / access point and the router.",
                    "From a computer run `ping " + ip + "` and `arp -a` (or `ip neigh`) to confirm it stays unresolved.",
                    "If the router was replaced, make sure devices use the new gateway address (`ipconfig /all`).",
                ] if gw else [
                    f"Check that {ip} is powered on and connected (cable / Wi-Fi).",
                    f"Run `ping {ip}` and `arp -a` (or `ip neigh`) to confirm it does not resolve.",
                    f"If {ip} moved to a new address, update the devices or settings that still point to it.",
                ]),
                analogy="Like knocking on a door again and again when nobody is home.",
                severity=sev,
            )
            misconf = Variant(
                title=f"A device is configured to use an address that doesn't exist ({ip})",
                summary=f"One device keeps asking for {ip}, which never answered during the capture.",
                explanation=("A device is trying to reach an address that nobody on this network uses. This often "
                             "means a wrong static gateway, DNS or printer address in its settings."),
                cause=f"A stale or mistyped address ({ip}) in a device's configuration.",
                fix=["Check the requesting device's gateway/DNS/printer settings (`ipconfig /all`, `ip route`).",
                     "Switch it to automatic (DHCP) settings, or correct the address."],
                analogy="Like posting letters to an address that was never built.",
                severity=Severity.LOW if not gw else Severity.MEDIUM,
            )
            ev = evidence_of(frames, total=n, first_ts=first, last_ts=last)
            tech = (f"{n} unanswered ARP who-has for {ip} between {clock(first)} and {clock(last)} from "
                    f"{', '.join(sorted(t.requesters)[:6])} ({t.total} requests total); "
                    f"{'previously alive until ' + clock(t.alive_last) if t.alive_last else 'never seen alive'}"
                    f"{'; gateway' if gw else ''}. {dead_total} unanswered target(s) overall.")
            metrics = {"target": ip, "requests": n, "span_s": round(last - first, 2), "requesters": sorted(t.requesters)[:10],
                       "is_gateway": gw, "ever_alive": t.ever_alive, "unanswered_targets": dead_total}
            variants = {F: fault}
            if not gw or not t.ever_alive:
                variants[M] = misconf
            out.append(make_finding("arp.unanswered", variants, ind, technical=tech, hosts=[ip] + sorted(t.requesters)[:4],
                                    metrics=metrics, evidence=ev, default=F))
        return out

    # -- storm ------------------------------------------------------------ #
    def _find_storm(self, ctx: AnalysisContext, scanner_macs: set[str]) -> Finding | None:
        if self.max_run < self.STORM_SECONDS:
            return None
        top = self.storm_senders.most_common(5)
        total = sum(self.storm_senders.values()) or 1
        top_mac, top_n = top[0] if top else ("?", 0)
        if top_mac in scanner_macs and top_n / total >= 0.7:
            return None
        dup = 1 - self.storm_uniq / max(1, self.storm_pkts)
        F, A = Category.FAULT, Category.ATTACK
        ind = [Indicator(f"ARP traffic exceeded {int(self.storm_thr)} frames per second for {self.heavy_secs} "
                         f"seconds (peak {self.peak_rate}/s)", F, 1.5)]
        if dup >= 0.7:
            ind.append(Indicator(f"{fmt_frac(dup)} of the frames are exact repeats, the signature of a switching loop", F, 2.0))
        if len(self.storm_senders) >= 5 and top_n / total < 0.5:
            ind.append(Indicator(f"The flood comes from {len(self.storm_senders)} different devices", F, 1.0))
        if top_n / total >= 0.8:
            ind.append(Indicator(f"{fmt_frac(top_n / total)} of the flood comes from one MAC ({top_mac})", A, 1.5))
        if dup < 0.3 and top_n / total >= 0.8:
            ind.append(Indicator("The frames are all different (crafted), not repeats of the same frames", A, 1.0))
        fault = Variant(
            title="ARP broadcast storm",
            summary=f"ARP traffic peaked at {self.peak_rate} frames per second for {self.heavy_secs} seconds.",
            explanation=("Broadcast frames like ARP are copied to every port of the network. When they loop or flood, "
                         "switches and devices spend all their time handling them and real traffic suffers."),
            cause="A switching loop (a cable plugged into two switch ports, or two links without spanning tree), "
                  "or a malfunctioning device.",
            fix=["Look for a cable connecting two ports of the same switch(es) and remove it.",
                 "Enable spanning tree (STP/RSTP) and storm control on managed switches.",
                 f"Find the busiest sender ({top_mac}) in the switch MAC table and unplug it to test."],
            analogy="Like an echo in a canyon that keeps getting louder until nobody can hear anything else.",
            severity=Severity.HIGH,
        )
        attack = Variant(
            title="ARP flood from one device",
            summary=f"{top_mac} sent most of a {self.peak_rate} frames/s ARP flood.",
            explanation="One device is generating a huge number of ARP frames, which can overload switches and other devices.",
            cause=f"A flooding tool or compromised device at {top_mac}.",
            fix=[f"Find {top_mac} in the switch MAC table and disconnect it.",
                 "Enable ARP rate limiting / storm control on the switch."],
            analogy="Like someone shouting non-stop in a meeting so nobody else can speak.",
            mitre="T1498 Network Denial of Service",
            severity=Severity.HIGH,
        )
        ev = evidence_of(self.storm_frames, total=self.storm_pkts, first_ts=self.storm_first, last_ts=self.storm_last)
        tech = (f"{self.heavy_secs} seconds above {int(self.storm_thr)} ARP/s (longest run {self.max_run} s, peak "
                f"{self.peak_rate}/s); duplicate ratio {dup:.2f}; top senders "
                + ", ".join(f"{m} ({n})" for m, n in top))
        metrics = {"peak_rate": self.peak_rate, "heavy_seconds": self.heavy_secs, "longest_run_s": self.max_run,
                   "duplicate_ratio": round(dup, 3), "top_senders": [[m, n] for m, n in top]}
        return make_finding("arp.storm", {F: fault, A: attack}, ind, technical=tech, hosts=[],
                            metrics=metrics, evidence=ev, default=F)


def fmt_frac(x: float) -> str:
    return f"{x * 100:.0f}%"


def _adjacent_macs(a: str, b: str) -> bool:
    try:
        ia, ib = int(a.replace(":", ""), 16), int(b.replace(":", ""), 16)
    except (ValueError, AttributeError):
        return False
    return a[:8] == b[:8] and 0 < abs(ia - ib) <= 3
