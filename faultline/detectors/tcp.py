"""TCP analysis: a per-connection state tracker with Wireshark-expert-style
segment classification, implemented from scratch, plus Faultline's own
diagnosis on top of it.

Per direction ("half") of every connection we track the next expected
sequence number in *unwrapped* 64-bit space (RFC 1982 serial arithmetic, so a
sequence wrap at 2^32 is invisible to the logic), the highest ACK, the
advertised window (scaled by the window-scale option of that side's SYN), and
a small list of *holes*: sequence ranges we never saw although later data
arrived ("previous segment not captured").

Every data segment is then classified as:

* new data (possibly opening a hole),
* **out-of-order**: fills a hole shortly after it opened (< half an RTT),
* **retransmission, lost upstream**: fills a hole *late*, i.e. the original
  never reached the capture point, so it was lost between sender and here,
* **retransmission, lost downstream**: we saw the original, so it got past us
  and was lost between here and the receiver,
* **spurious retransmission**: the receiver had already ACKed it (we saw the
  ACK), so the *ACK* was lost on its way back to the sender,
* keepalive / zero-window probe (ignored).

A hole the receiver ACKs without us ever seeing the data was dropped by the
capture tool, not the network; it is counted separately and never blamed on
the network. Retransmissions are further split into fast (after >= 2 dup
ACKs) and timeout (RTO) retransmissions.

Kinds produced: ``tcp.retransmissions``, ``tcp.refused``, ``tcp.resets``,
``tcp.syn_timeout``, ``tcp.zero_window``.
"""

from __future__ import annotations

import math

from ..context import is_private
from .base import (
    AnalysisContext, BoundedDict, Category, Detector, Evidence, Finding, Indicator,
    Packet, Severity, Variant, fmt_ms, fmt_pct, plural, register,
)

MASK = 0xFFFFFFFF
HALF = 0x80000000
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10

MAX_FLOWS = 200_000
MAX_HOLES = 32
MAX_SERVICES = 50_000

#: well-known service ports, used to guess the server side of mid-stream flows
SERVICE_PORTS = frozenset({
    20, 21, 22, 23, 25, 53, 80, 88, 110, 123, 135, 139, 143, 389, 443, 445, 465, 587, 636,
    853, 993, 995, 1433, 1521, 1883, 2049, 3306, 3389, 5060, 5222, 5432, 5900, 6379, 8000,
    8080, 8443, 8883, 9000, 9200, 27017,
})


def sdiff(a: int, b: int) -> int:
    """Signed difference ``a - b`` of two 32-bit sequence numbers (RFC 1982)."""
    return ((a - b + HALF) & MASK) - HALF


def scaled(n: float, ctx: AnalysisContext) -> int:
    """Count threshold scaled by the configured sensitivity (never below 1)."""
    return max(1, math.ceil(n * ctx.config.scale))


def _cap(s, n: int = 100) -> str:
    """Untrusted text: plain, single line, length-capped."""
    s = "" if s is None else str(s)
    s = "".join(ch if ch.isprintable() else " " for ch in s)
    return s[:n]


def _ep(ip, port) -> str:
    ip = _cap(ip, 45)
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def _mode(d: dict | None):
    if not d:
        return None
    return max(d.items(), key=lambda kv: kv[1])[0]


def _ev_add(ev: Evidence, no, ts) -> None:
    """Record a frame (number + time) into ``ev`` without a Packet object."""
    ev.total += 1
    if no is not None and len(ev.packets) < Evidence.CAP:
        ev.packets.append(no)
    if ts is not None:
        if ev.first_ts is None or ts < ev.first_ts:
            ev.first_ts = ts
        if ev.last_ts is None or ts > ev.last_ts:
            ev.last_ts = ts


def _bump(d: dict, key, cap: int = 64, by: int = 1) -> None:
    if key in d:
        d[key] += by
    elif len(d) < cap:
        d[key] = by


# --------------------------------------------------------------------------- #
# Scan exclusion (shared helper)
# --------------------------------------------------------------------------- #


class SynFanout:
    """Per-source fan-out of connection attempts.

    A source that sends SYNs to more than ``PORT_LIMIT`` distinct ports, or
    to more than ``HOST_LIMIT`` distinct hosts while most of its attempts fail,
    is scanning; its refusals / timeouts are the *expected* result of the scan
    and belong to the scan detector, not to "the service is broken".
    (A browser legitimately opens connections to dozens of hosts, but almost
    all of them succeed, hence the success-ratio condition for host fan-out.)
    """

    PORT_LIMIT = 15
    HOST_LIMIT = 15

    def __init__(self, maxlen: int = 50_000) -> None:
        self._src: BoundedDict = BoundedDict(maxlen)

    def syn(self, src: str, dst: str, dport: int) -> None:
        e = self._src.get(src)
        if e is None:
            e = self._src[src] = [set(), set(), 0, 0]
        if len(e[0]) <= self.PORT_LIMIT:
            e[0].add(dport)
        if len(e[1]) <= self.HOST_LIMIT:
            e[1].add(dst)
        e[2] += 1

    def accepted(self, src: str) -> None:
        e = self._src.get(src)
        if e is not None:
            e[3] += 1

    def is_scanner(self, src: str) -> bool:
        e = self._src.get(src)
        if e is None:
            return False
        if len(e[0]) > self.PORT_LIMIT:
            return True
        return len(e[1]) > self.HOST_LIMIT and e[3] < 0.5 * e[2]

    def fanout(self, src: str) -> tuple[int, int]:
        e = self._src.get(src)
        return (len(e[0]), len(e[1])) if e else (0, 0)


# --------------------------------------------------------------------------- #
# Per-connection state
# --------------------------------------------------------------------------- #


class _Half:
    """One direction of a connection: what *this* endpoint sent."""

    __slots__ = (
        "ip", "port", "base", "isn", "nxt", "wscale", "mss", "last_ack", "last_win", "dup_acks",
        "win_zero", "zero_since", "fin", "pkts", "ttls", "holes",
        "data_segs", "retrans", "fast", "rto", "spurious", "up", "down", "ooo", "gaps",
        "cap_drops", "dupacks", "keepalives", "zw_events", "zw_pkts", "zw_probes", "win_full",
        "stall", "max_stall", "last_data_ts", "last_data_psh", "last_data_len",
    )

    def __init__(self, ip: str, port: int) -> None:
        self.ip, self.port = ip, port
        self.base = False  # nxt initialised
        self.isn = None
        self.nxt = 0  # unwrapped next expected sequence number
        self.wscale = None
        self.mss = None
        self.last_ack = None  # highest ACK *sent by this side* (unwrapped, peer's space)
        self.last_win = None
        self.dup_acks = 0
        self.win_zero = False
        self.zero_since = 0.0
        self.fin = False
        self.pkts = 0
        self.ttls: dict | None = None  # TTL -> count (lazily created, <= 4 keys)
        self.holes: list | None = None
        self.data_segs = self.retrans = self.fast = self.rto = self.spurious = 0
        self.up = self.down = self.ooo = self.gaps = self.cap_drops = self.dupacks = 0
        self.keepalives = self.zw_events = self.zw_pkts = self.zw_probes = self.win_full = 0
        self.stall = self.max_stall = 0.0
        self.last_data_ts = None
        self.last_data_psh = True
        self.last_data_len = 0

    def unwrap(self, seq: int) -> int:
        return self.nxt + sdiff(seq, self.nxt & MASK)


class _Flow:
    __slots__ = (
        "h", "client", "syn_count", "syn_ts", "syn_frames", "synack_ts", "synack_count", "ack_ts",
        "established", "answered", "client_more", "refused", "icmp", "first_ts", "last_ts",
        "rst", "rst_after", "rtt_c", "rtt_s", "zw_ev",
    )

    def __init__(self, h0: _Half, h1: _Half, ts: float) -> None:
        self.h = (h0, h1)
        self.client = None  # index of the SYN sender (or best guess)
        self.syn_count = 0
        self.syn_ts = None
        self.syn_frames: list | None = None  # [(frame, ts)] of SYNs, <= 8
        self.synack_ts = None
        self.synack_count = 0
        self.ack_ts = None
        self.established = False
        self.answered = False  # the SYN target sent *anything*
        self.client_more = False  # client sent non-SYN packets (handshake done out of view)
        self.refused = 0  # syn_count at the last SYN->RST refusal (0 = never refused)
        self.icmp = False
        self.first_ts = self.last_ts = ts
        self.rst = None  # info tuple of the first RST on an established connection
        self.rst_after = 0  # non-RST packets from the RST sender *after* its RST
        self.rtt_c = None  # capture point <-> client round trip (SYN/ACK -> ACK)
        self.rtt_s = None  # capture point <-> server round trip (SYN -> SYN/ACK)
        self.zw_ev = None  # Evidence for zero-window packets (lazily created)


class _Svc:
    """Connection outcomes for one (server ip, port)."""

    __slots__ = (
        "accepted", "first_accept", "last_accept", "synack_ttls", "refused_by", "first_refuse",
        "last_refuse", "rst_ttls", "ev", "to_by", "to_ev", "to_first", "to_last", "to_backoff",
        "to_flows", "to_syns", "to_retried",
    )

    def __init__(self) -> None:
        self.accepted = 0
        self.first_accept = self.last_accept = None
        self.synack_ttls: dict = {}
        self.refused_by: dict = {}
        self.first_refuse = self.last_refuse = None
        self.rst_ttls: dict = {}
        self.ev = Evidence()
        self.to_by: dict = {}  # src -> [flows, syns, flows with >= 2 retries]
        self.to_ev = Evidence()
        self.to_first = self.to_last = None
        self.to_backoff: list = []
        self.to_flows = self.to_syns = self.to_retried = 0


class _FlowTable(BoundedDict):
    """BoundedDict that hands evicted flows to a callback so their counters
    still reach the final statistics."""

    def __init__(self, maxlen: int, on_evict) -> None:
        super().__init__(maxlen)
        self.on_evict = on_evict

    def popitem(self, last: bool = True):
        k, v = super().popitem(last)
        self.on_evict(v)
        return k, v


# --------------------------------------------------------------------------- #
# Detector
# --------------------------------------------------------------------------- #


@register
class TcpDetector(Detector):
    name = "tcp"

    def __init__(self) -> None:
        self.flows = _FlowTable(MAX_FLOWS, self._retire)
        self.services: BoundedDict = BoundedDict(MAX_SERVICES)
        self.fanout = SynFanout()
        self.max_ts = None
        self.end_ts = None  # set at finalize
        # aggregate retransmission statistics (filled when flows retire)
        self.data = {"c": 0, "s": 0}
        self.rx = {"c": 0, "s": 0}
        self.loss_client_side = 0
        self.loss_server_side = 0
        self.spurious = self.fast = self.rto = self.ooo = self.cap_drops = self.gaps = 0
        self.dupacks = self.keepalives = 0
        self.rx_by_server: dict = {}
        self.worst: list = []
        self.rx_ev = Evidence()
        self.dup_ev = Evidence()
        # zero window
        self.zw: dict = {}  # receiver ip -> [events, stall, max_stall, probes, flows, peers{}]
        self.zw_ev = Evidence()
        self.win_full = 0
        # resets
        self.established = 0
        self.est_by_server: dict = {}
        self.aborts: list = []  # (no, ts, sender_role, client, server, flags...)
        self.abort_ev = Evidence()
        self.after_fin_rsts = 0
        self.idle_close_rsts = 0
        self.inject: list = []
        self.inject_ev = Evidence()
        self.flows_seen = 0

    # ------------------------------------------------------------------ #
    def _svc(self, ip: str, port: int) -> _Svc:
        key = (ip, port)
        s = self.services.get(key)
        if s is None:
            s = self.services[key] = _Svc()
        return s

    @staticmethod
    def _new_conn(flow: _Flow, d: int, seq: int) -> bool:
        """A bare SYN on an existing 4-tuple: retransmission or port reuse?"""
        hd = flow.h[d]
        if hd.isn is not None:
            return hd.isn != seq
        return flow.client is None or flow.client == d or flow.rst is not None

    # ------------------------------------------------------------------ #
    def on_packet(self, pkt: Packet, ctx: AnalysisContext) -> None:
        t = pkt.tcp
        if t is None:
            if pkt.icmp is not None and pkt.icmp.inner is not None:
                self._on_icmp(pkt)
            return
        src, dst = pkt.src, pkt.dst
        sport, dport, seq = t.sport, t.dport, t.seq
        if src is None or dst is None or sport is None or dport is None or seq is None:
            return
        ts = pkt.ts if isinstance(pkt.ts, (int, float)) else 0.0
        if self.max_ts is None or ts > self.max_ts:
            self.max_ts = ts
        fl = t.flags or 0
        plen = t.plen or 0
        if (src, sport) <= (dst, dport):
            key, d = (src, sport, dst, dport), 0
        else:
            key, d = (dst, dport, src, sport), 1

        flow = self.flows.get(key)
        if flow is not None and fl & SYN and not fl & ACK and self._new_conn(flow, d, seq):
            del self.flows[key]
            self._retire(flow)
            flow = None
        if flow is None:
            a, b = (src, sport), (dst, dport)
            if d == 1:
                a, b = b, a
            flow = _Flow(_Half(*a), _Half(*b), ts)
            self.flows[key] = flow
            self.flows_seen += 1
        else:
            self.flows.move_to_end(key)
        if ts > flow.last_ts:
            flow.last_ts = ts
        h, o = flow.h[d], flow.h[1 - d]
        h.pkts += 1

        if fl & RST:
            self._on_rst(pkt, flow, d, h, o, seq, ts)
            return
        if flow.rst is not None and flow.rst[0] == d and ts >= flow.rst[2]:
            flow.rst_after += 1
        if pkt.ttl is not None:
            if h.ttls is None:
                h.ttls = {pkt.ttl: 1}
            else:
                _bump(h.ttls, pkt.ttl, cap=4)
        if flow.client is not None and d != flow.client:
            flow.answered = True

        if fl & SYN:
            self._on_syn(pkt, flow, d, h, o, seq, fl, plen, ts)
            return

        if flow.client is not None and d == flow.client and flow.syn_count and flow.synack_ts is None:
            flow.client_more = True
        if not flow.established and fl & ACK:
            if flow.synack_ts is not None and d == flow.client:
                flow.established = True
                if flow.ack_ts is None:
                    flow.ack_ts = ts
                    if flow.synack_count == 1 and flow.syn_count == 1:
                        flow.rtt_c = max(0.0, ts - flow.synack_ts)
            elif flow.syn_count == 0 and flow.synack_ts is None and o.pkts > 0:
                flow.established = True  # mid-stream pick-up: both sides talk

        if fl & ACK and t.ack is not None:
            self._on_ack(pkt, flow, h, o, t.ack, t.win, plen, fl, ts)
        if plen > 0 or fl & FIN:
            self._on_data(pkt, flow, d, h, o, seq, plen, fl, ts)

    # ------------------------------------------------------------------ #
    def _on_syn(self, pkt, flow, d, h, o, seq, fl, plen, ts) -> None:
        t = pkt.tcp
        if not fl & ACK:
            if flow.client is None:
                flow.client = d
            flow.syn_count += 1
            if flow.syn_count == 1:
                flow.syn_ts = ts
                self.fanout.syn(pkt.src, pkt.dst, t.dport)
            if flow.syn_frames is None:
                flow.syn_frames = [(pkt.no, ts)]
            elif len(flow.syn_frames) < 8:
                flow.syn_frames.append((pkt.no, ts))
            h.isn = seq
            h.base = True
            h.nxt = seq + 1 + plen  # TCP Fast Open may carry data
            h.wscale, h.mss = t.wscale, t.mss
            return
        # SYN/ACK
        if flow.client is None:
            flow.client = 1 - d
        flow.answered = True
        flow.synack_count += 1
        if flow.synack_ts is None:
            flow.synack_ts = ts
            if flow.syn_ts is not None and flow.syn_count == 1:
                flow.rtt_s = max(0.0, ts - flow.syn_ts)
            svc = self._svc(pkt.src, t.sport)
            svc.accepted += 1
            if svc.first_accept is None:
                svc.first_accept = ts
            svc.last_accept = ts
            if pkt.ttl is not None:
                _bump(svc.synack_ttls, pkt.ttl, cap=4)
            self.fanout.accepted(pkt.dst)
        h.isn = seq
        h.base = True
        h.nxt = seq + 1
        h.wscale, h.mss = t.wscale, t.mss
        if t.ack is not None and o.base:
            h.last_ack = o.unwrap(t.ack)
        h.last_win = t.win

    # ------------------------------------------------------------------ #
    def _on_rst(self, pkt, flow, d, h, o, seq, ts) -> None:
        t = pkt.tcp
        if flow.client is not None and d != flow.client:
            flow.answered = True
        # SYN answered by RST: connection refused
        if not flow.established and flow.syn_count and flow.synack_ts is None and d != flow.client:
            # count once per SYN (Windows re-sends the SYN after a RST on the same port)
            if flow.syn_count > flow.refused:
                flow.refused = flow.syn_count
                svc = self._svc(pkt.src, t.sport)
                _bump(svc.refused_by, pkt.dst)
                if svc.first_refuse is None or ts < svc.first_refuse:
                    svc.first_refuse = ts
                if svc.last_refuse is None or ts > svc.last_refuse:
                    svc.last_refuse = ts
                if pkt.ttl is not None:
                    _bump(svc.rst_ttls, pkt.ttl, cap=4)
                if flow.syn_frames:
                    _ev_add(svc.ev, flow.syn_frames[-1][0], flow.syn_frames[-1][1])
                svc.ev.add(pkt)
            return
        if not flow.established or flow.rst is not None:
            return
        # first RST of an established connection: snapshot the state now
        after_fin = h.fin or o.fin
        inflight = False
        if o.base and (h.last_ack is None or o.nxt > h.last_ack) and o.data_segs > 0:
            inflight = True  # RST sender discards data it has not acknowledged
        if h.base and o.last_ack is not None and h.nxt > o.last_ack and h.data_segs > 0:
            inflight = True  # its own data is still unacknowledged
        mid_write = (h.last_data_ts is not None and not h.last_data_psh and h.last_data_len >= 500)
        base_ttl = _mode(h.ttls) if h.ttls and sum(h.ttls.values()) >= 2 else None
        ttl_off = (base_ttl is not None and pkt.ttl is not None and abs(pkt.ttl - base_ttl) >= 5)
        seq_off = False
        if h.base:
            diff = h.unwrap(seq) - h.nxt
            if diff != 0:
                sc = o.wscale if (o.wscale is not None and h.wscale is not None) else 0
                win = (o.last_win or 0) << min(sc, 14)
                seq_off = 0 < abs(diff) <= max(win, 1)
        last_activity = max((x for x in (h.last_data_ts, o.last_data_ts) if x is not None), default=None)
        idle = (ts - last_activity) if last_activity is not None else None
        flow.rst = (d, pkt.no, ts, pkt.ttl, base_ttl, ttl_off, seq_off, inflight, after_fin, mid_write, idle)

    # ------------------------------------------------------------------ #
    def _on_ack(self, pkt, flow, h, o, ack, win, plen, fl, ts) -> None:
        # zero-window tracking (receiver = h, the side advertising the window)
        if win is not None and not fl & (SYN | FIN):
            if win == 0:
                h.zw_pkts += 1
                if not h.win_zero:
                    h.win_zero = True
                    h.zero_since = ts
                    h.zw_events += 1
                if flow.zw_ev is None:
                    flow.zw_ev = Evidence()
                flow.zw_ev.add(pkt)
            elif h.win_zero:
                stall = max(0.0, ts - h.zero_since)
                h.stall += stall
                h.max_stall = max(h.max_stall, stall)
                h.win_zero = False
                if flow.zw_ev is not None:
                    flow.zw_ev.add(pkt)  # the window update that ended the stall
        if not o.base:
            h.last_win = win
            return
        ack_u = o.unwrap(ack)
        if h.last_ack is None or ack_u > h.last_ack:
            h.last_ack = ack_u
            h.dup_acks = 0
            if o.holes:
                self._ack_holes(o, ack_u)
        elif ack_u == h.last_ack:
            pure = plen == 0 and not fl & (SYN | FIN | RST)
            if pure and win == h.last_win and o.nxt > ack_u and not h.win_zero:
                h.dup_acks += 1
                h.dupacks += 1
                self.dup_ev.add(pkt)
        h.last_win = win

    @staticmethod
    def _ack_holes(o: _Half, ack_u: int) -> None:
        """Receiver ACKed past a hole we never saw filled: the capture dropped it."""
        keep = []
        for hole in o.holes:
            if hole[0] < ack_u:
                o.cap_drops += 1
                if hole[1] > ack_u:
                    keep.append([ack_u, hole[1], hole[2]])
            else:
                keep.append(hole)
        o.holes = keep or None

    @staticmethod
    def _fill_holes(h: _Half, s: int, e: int):
        """Remove [s, e) from h's holes; return the earliest creation time of a
        hole it overlapped (None if it overlapped none)."""
        if not h.holes:
            return None
        hit = None
        out = []
        for hs, he, hts in h.holes:
            if s >= he or e <= hs:
                out.append([hs, he, hts])
                continue
            hit = hts if hit is None else min(hit, hts)
            if s > hs:
                out.append([hs, s, hts])
            if e < he:
                out.append([e, he, hts])
        h.holes = out or None
        return hit

    # ------------------------------------------------------------------ #
    def _on_data(self, pkt, flow, d, h, o, seq, plen, fl, ts) -> None:
        seglen = plen + (1 if fl & FIN else 0)
        if fl & FIN:
            h.fin = True
        if not h.base:  # first segment of a mid-stream flow: baseline only
            h.base = True
            h.nxt = seq + seglen
            if plen:
                h.data_segs += 1
                self._note_data(h, fl, plen, ts)
            return
        seq_u = h.unwrap(seq)
        end_u = seq_u + seglen
        if plen == 0:  # bare FIN
            if seq_u >= h.nxt:
                h.nxt = max(h.nxt, end_u)
            return
        # keepalive: 0/1 byte at nxt-1 (plen 0 never reaches here)
        if plen <= 1 and seq_u == h.nxt - 1 and not fl & FIN:
            h.keepalives += 1
            return
        # zero-window probe: peer advertised 0, one byte at nxt (or the same byte re-sent)
        if o.win_zero and plen == 1 and seq_u in (h.nxt, h.nxt - 1):
            o.zw_probes += 1
            if seq_u == h.nxt:
                h.nxt += 1
            if flow.zw_ev is not None:
                flow.zw_ev.add(pkt)
            return
        h.data_segs += 1
        self._note_data(h, fl, plen, ts)
        if seq_u >= h.nxt:
            gap = seq_u - h.nxt
            if gap > 0:
                if gap < (1 << 30):
                    h.gaps += 1
                    holes = h.holes or []
                    if len(holes) >= MAX_HOLES:
                        holes.pop(0)
                    holes.append([h.nxt, seq_u, ts])
                    h.holes = holes
            h.nxt = end_u
            # window full: segment ends exactly at the receiver's right window edge
            if o.last_ack is not None and o.last_win and h.wscale is not None and o.wscale is not None:
                if end_u == o.last_ack + (o.last_win << o.wscale):
                    h.win_full += 1
            return
        # seq_u < nxt: out-of-order, or a retransmission
        hole_ts = self._fill_holes(h, seq_u, end_u)
        if hole_ts is not None:
            rtt = (flow.rtt_c or 0) + (flow.rtt_s or 0) if (flow.rtt_c is not None and flow.rtt_s is not None) else None
            thresh = 0.003 if rtt is None else max(0.003, min(0.5 * rtt, 0.2))
            if ts - hole_ts < thresh:
                h.ooo += 1  # a reordered original, not an extra transmission
            else:
                self._retrans(pkt, h, o, seq_u, "up")
        else:
            if o.last_ack is not None and end_u <= o.last_ack:
                self._retrans(pkt, h, o, seq_u, "spurious")
            else:
                self._retrans(pkt, h, o, seq_u, "down")
        if end_u > h.nxt:
            h.nxt = end_u

    @staticmethod
    def _note_data(h: _Half, fl: int, plen: int, ts: float) -> None:
        h.last_data_ts = ts
        h.last_data_psh = bool(fl & PSH)
        h.last_data_len = plen

    def _retrans(self, pkt, h: _Half, o: _Half, seq_u: int, where: str) -> None:
        h.retrans += 1
        if where == "up":
            h.up += 1
        elif where == "down":
            h.down += 1
        else:
            h.spurious += 1
        if where != "spurious":
            if o.dup_acks >= 2 and o.last_ack == seq_u:
                h.fast += 1
            else:
                h.rto += 1
        self.rx_ev.add(pkt)

    # ------------------------------------------------------------------ #
    def _on_icmp(self, pkt: Packet) -> None:
        inn = pkt.icmp.inner
        if inn.proto != 6 or inn.sport is None or inn.dport is None or not inn.src or not inn.dst:
            return
        a, b = (inn.src, inn.sport), (inn.dst, inn.dport)
        key = a + b if a <= b else b + a
        flow = self.flows.get(key)
        if flow is not None:
            flow.icmp = True
            flow.answered = True

    # ------------------------------------------------------------------ #
    def _client_index(self, flow: _Flow) -> int:
        if flow.client is not None:
            return flow.client
        a, b = flow.h
        a_srv, b_srv = a.port in SERVICE_PORTS, b.port in SERVICE_PORTS
        if a_srv != b_srv:
            return 1 if a_srv else 0
        if is_private(a.ip) != is_private(b.ip):
            return 0 if is_private(a.ip) else 1
        return 0 if a.port > b.port else 1

    def _retire(self, flow: _Flow) -> None:
        """Fold a finished (or evicted) connection into the aggregate statistics."""
        ci = self._client_index(flow)
        c, s = flow.h[ci], flow.h[1 - ci]
        # -- retransmissions ------------------------------------------------
        self.data["c"] += c.data_segs
        self.data["s"] += s.data_segs
        self.rx["c"] += c.retrans
        self.rx["s"] += s.retrans
        cside = c.up + c.spurious + s.down
        sside = s.up + s.spurious + c.down
        self.loss_client_side += cside
        self.loss_server_side += sside
        for x in (c, s):
            self.spurious += x.spurious
            self.fast += x.fast
            self.rto += x.rto
            self.ooo += x.ooo
            self.cap_drops += x.cap_drops
            self.gaps += x.gaps
            self.dupacks += x.dupacks
            self.keepalives += x.keepalives
        rx = c.retrans + s.retrans
        if rx:
            _bump(self.rx_by_server, s.ip, cap=4096, by=rx)
            segs = c.data_segs + s.data_segs
            self.worst.append((rx, rx / max(segs, 1), segs, c.ip, c.port, s.ip, s.port, cside, sside))
            if len(self.worst) > 400:
                self.worst.sort(key=lambda w: (-w[0], -w[1]))
                del self.worst[50:]
        # -- zero window ------------------------------------------------------
        for x, peer in ((c, s), (s, c)):
            if x.win_zero:  # still closed when the capture ended
                stall = max(0.0, flow.last_ts - x.zero_since)
                x.stall += stall
                x.max_stall = max(x.max_stall, stall)
                x.win_zero = False
            self.win_full += x.win_full
            if x.zw_events:
                z = self.zw.get(x.ip)
                if z is None:
                    if len(self.zw) >= 4096:
                        continue
                    z = self.zw[x.ip] = [0, 0.0, 0.0, 0, 0, {}, 0]
                z[0] += x.zw_events
                z[1] += x.stall
                z[2] = max(z[2], x.max_stall)
                z[3] += x.zw_probes
                z[4] += 1
                _bump(z[5], peer.ip, cap=16)
                z[6] += x.zw_pkts
        if flow.zw_ev is not None:
            self.zw_ev.merge(flow.zw_ev)
        # -- unanswered SYNs --------------------------------------------------
        if (flow.syn_count and flow.client is not None and not flow.answered and not flow.refused
                and not flow.client_more and not flow.icmp):
            self._syn_timeout(flow, c, s)
        # -- resets -------------------------------------------------------------
        if flow.established:
            self.established += 1
            _bump(self.est_by_server, s.ip, cap=4096)
        if flow.rst is not None and flow.established:
            self._classify_rst(flow, ci, c, s)

    def _syn_timeout(self, flow: _Flow, c: _Half, s: _Half) -> None:
        ref = self.end_ts if self.end_ts is not None else self.max_ts
        if flow.syn_count == 1 and ref is not None and flow.syn_ts is not None and ref - flow.syn_ts < 3.0:
            return  # capture ended before a reply was due: inconclusive
        svc = self._svc(s.ip, s.port)
        e = svc.to_by.get(c.ip)
        if e is None and len(svc.to_by) < 256:
            e = svc.to_by[c.ip] = [0, 0, 0]
        if e is not None:
            e[0] += 1
            e[1] += flow.syn_count
            e[2] += 1 if flow.syn_count >= 3 else 0
        svc.to_flows += 1
        svc.to_syns += flow.syn_count
        svc.to_retried += 1 if flow.syn_count >= 3 else 0
        frames = flow.syn_frames or ()
        for no, ts in frames:
            _ev_add(svc.to_ev, no, ts)
        svc.to_ev.total += max(0, flow.syn_count - len(frames))
        if not svc.to_backoff and len(frames) >= 3:
            tss = [x[1] for x in flow.syn_frames]
            svc.to_backoff = [round(max(0.0, b - a), 3) for a, b in zip(tss, tss[1:])][:6]

    def _classify_rst(self, flow: _Flow, ci: int, c: _Half, s: _Half) -> None:
        (d, no, ts, ttl, base_ttl, ttl_off, seq_off, inflight, after_fin, mid_write, idle) = flow.rst
        role = "client" if d == ci else "server"
        sender = flow.h[d]
        post = flow.rst_after
        suspicious = ttl_off or post >= 1
        if suspicious and not after_fin:
            self.inject.append({
                "frame": no, "flow": f"{_ep(c.ip, c.port)} → {_ep(s.ip, s.port)}", "rst_from": _cap(sender.ip, 45),
                "ttl": ttl, "usual_ttl": base_ttl, "ttl_mismatch": bool(ttl_off), "seq_mismatch": bool(seq_off),
                "packets_after_rst": post,
            })
            _ev_add(self.inject_ev, no, ts)
        if after_fin:
            self.after_fin_rsts += 1
            return
        if not (inflight or mid_write):
            self.idle_close_rsts += 1
            return
        if len(self.aborts) < 2000:
            self.aborts.append((no, ts, role, c.ip, s.ip, s.port, idle, inflight, ttl_off, seq_off, post))
        _ev_add(self.abort_ev, no, ts)

    # ------------------------------------------------------------------ #
    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        self.end_ts = ctx.end_ts if ctx.end_ts is not None else self.max_ts
        for flow in list(self.flows.values()):
            self._retire(flow)
        self.flows.clear()
        out: list[Finding] = []
        for fn in (self._f_retrans, self._f_refused, self._f_syn_timeout, self._f_resets, self._f_zero_window):
            try:
                out.extend(fn(ctx))
            except Exception:  # pragma: no cover - a detector bug must not kill the report
                continue
        return out

    # ================================================================== #
    # tcp.retransmissions
    # ================================================================== #
    def _f_retrans(self, ctx: AnalysisContext) -> list[Finding]:
        segs = self.data["c"] + self.data["s"]
        rx = self.rx["c"] + self.rx["s"]
        if rx == 0 or segs == 0:
            return []
        rate = rx / segs
        self.worst.sort(key=lambda w: (-w[0], -w[1]))
        flow_trig = [w for w in self.worst if w[0] >= scaled(8, ctx) and w[1] >= 0.05]
        overall = rate >= 0.02 and rx >= scaled(10, ctx)
        if not overall and not flow_trig:
            return []
        eff = rate if overall else flow_trig[0][1]
        sev = Severity.CRITICAL if eff >= 0.15 else Severity.HIGH if eff >= 0.05 else Severity.MEDIUM
        if not overall and sev == Severity.CRITICAL:
            sev = Severity.HIGH  # confined to one connection

        rate_c = self.rx["c"] / max(self.data["c"], 1)
        rate_s = self.rx["s"] / max(self.data["s"], 1)
        located = self.loss_client_side + self.loss_server_side
        top_srv = max(self.rx_by_server.items(), key=lambda kv: kv[1])[0] if self.rx_by_server else None
        srv_share = self.rx_by_server.get(top_srv, 0) / rx if top_srv else 0
        one_server = srv_share >= 0.7
        srv_txt = _cap(top_srv, 45) if one_server else "the servers"
        worst_flow = self.worst[0]
        client_ip = worst_flow[3]

        side = None
        if located >= 3:
            if self.loss_server_side >= 0.7 * located:
                side = "server"
            elif self.loss_client_side >= 0.7 * located:
                side = "client"
            else:
                side = "both"
        if side == "server":
            where = f"between this capture point and {srv_txt}"
            where_long = (f"Most lost packets ({fmt_pct(self.loss_server_side / located)}) went missing between this "
                          f"capture point and {srv_txt}, so the problem is on the far side of where you captured "
                          f"(typically your Internet uplink, the ISP or the server's network).")
        elif side == "client":
            where = "between the local device(s) and this capture point"
            where_long = (f"Most lost packets ({fmt_pct(self.loss_client_side / located)}) went missing between the "
                          f"local device(s) such as {_cap(client_ip, 45)} and this capture point, so the problem is on "
                          f"the near side (typically Wi-Fi, a cable, a switch port or the device's network card).")
        elif side == "both":
            where = "on both sides of this capture point"
            where_long = (f"Losses are spread over both sides of the capture point ({fmt_pct(self.loss_client_side / located)} "
                          f"near the local devices, {fmt_pct(self.loss_server_side / located)} towards {srv_txt}), "
                          f"which points to general congestion rather than one bad link.")
        else:
            where = "somewhere on the path"
            where_long = "There were too few clearly located losses to say on which side of the capture point they happen."

        if one_server:
            title = f"Packets are getting lost on the way to or from {srv_txt}"
        else:
            title = "Packets are getting lost on several connections"
        worst_list = [
            {"flow": f"{_ep(w[3], w[4])} → {_ep(w[5], w[6])}", "retransmissions": w[0], "segments": w[2],
             "rate": round(w[1], 4)}
            for w in self.worst[:5]
        ]
        if side == "client" and is_private(client_ip):
            cause = ("A weak or noisy link close to the local device(s): poor Wi-Fi signal or interference, "
                     "a damaged cable, a bad switch port, or a speed/duplex mismatch.")
        elif side == "server":
            cause = ("Congestion or a faulty link beyond the capture point: a saturated Internet uplink, "
                     "problems at the ISP, or an overloaded path to the server.")
        else:
            cause = "Congestion or a faulty link somewhere on the path; the evidence does not pin it to one side."
        if self.cap_drops > rx:
            cause += (" Note: the capture tool itself also missed packets that did arrive; keep that in mind "
                      "when reading the numbers.")
        fix = []
        if side in ("client", "both", None):
            fix += [
                "On the affected device, check the link first: for Wi-Fi move closer to the access point or try a "
                "cable; for Ethernet swap the cable and switch port.",
                "Look at interface error counters: `ethtool -S eth0` / `ip -s link` on Linux, `netstat -e` on "
                "Windows; rising CRC/FCS errors or drops confirm a bad link, and a duplex mismatch shows up as late "
                "collisions (`ethtool eth0`).",
            ]
        if side in ("server", "both", None):
            fix += [
                f"Measure the path loss beyond the capture point: `mtr -rwc 100 {srv_txt if one_server else '<server>'}` "
                "(Linux/macOS) or `pathping` (Windows); loss that starts at one hop and continues to the end shows "
                "where it begins.",
                "Check whether the Internet uplink is saturated (router traffic graphs); if it is, enable QoS/SQM "
                "on the router or reduce the load.",
            ]
        fix += [
            "Check the router/switch logs for interface errors or flapping links during the capture window.",
            "If the problem persists with a clean local link, contact the ISP or the server's operator with these "
            "numbers (loss rate and where it happens).",
        ]
        fix = fix[:5]
        f = Finding(
            kind="tcp.retransmissions",
            category=Category.FAULT,
            severity=sev,
            title=title[:120],
            summary=(f"{fmt_pct(rate)} of TCP data packets ({rx:,} of {segs:,}) had to be sent again, mostly "
                     f"{where}."),
            explanation=(
                "When a packet is lost, TCP notices that the other side never confirmed it and sends it again "
                "(a retransmission). Each resend costs time, and TCP also slows down on purpose because it assumes "
                "the network is overloaded, so pages load slowly and downloads crawl. " + where_long
            ),
            analogy=("Like a phone call where every so often a word drops out and you have to say the sentence "
                     "again, and you start talking slower to be understood."),
            cause=cause,
            fix=fix,
            technical=(
                f"{rx:,} retransmissions over {segs:,} data segments ({fmt_pct(rate)}): client→server {fmt_pct(rate_c)} "
                f"({self.rx['c']:,}/{self.data['c']:,}), server→client {fmt_pct(rate_s)} ({self.rx['s']:,}/{self.data['s']:,}). "
                f"Fast retransmissions {self.fast:,}, RTO retransmissions {self.rto:,}, spurious {self.spurious:,}, "
                f"duplicate ACKs {self.dupacks:,}, out-of-order {self.ooo:,}, 'previous segment not captured' {self.gaps:,} "
                f"(of which {self.cap_drops:,} were later ACKed without being seen, i.e. capture drops). "
                f"Loss localisation from the capture point: client side {self.loss_client_side:,}, server side "
                f"{self.loss_server_side:,} (original seen then resent = loss after the capture point; hole filled "
                f"late = loss before it; spurious = ACK lost on its way back)."
            ),
            hosts=[h for h in dict.fromkeys([client_ip] + ([top_srv] if top_srv else []) +
                                            [w[5] for w in self.worst[:5]]) if h][:10],
            metrics={
                "retransmissions": rx,
                "data_segments": segs,
                "retrans_rate": round(rate, 4),
                "rate_client_to_server": round(rate_c, 4),
                "rate_server_to_client": round(rate_s, 4),
                "fast_retransmissions": self.fast,
                "rto_retransmissions": self.rto,
                "spurious_retransmissions": self.spurious,
                "dup_acks": self.dupacks,
                "out_of_order": self.ooo,
                "lost_segment_gaps": self.gaps,
                "capture_drops": self.cap_drops,
                "loss_client_side": self.loss_client_side,
                "loss_server_side": self.loss_server_side,
                "loss_location": side or "unknown",
                "worst_flows": worst_list,
            },
        )
        f.indicators = [
            Indicator(f"{fmt_pct(rate)} of data segments were retransmitted across {plural(len(self.worst), 'connection')}",
                      Category.FAULT, 2.0 if rate >= 0.05 else 1.5),
        ]
        if self.fast + self.rto:
            f.indicators.append(Indicator(
                f"Normal TCP recovery behaviour ({self.fast:,} fast and {self.rto:,} timeout retransmissions): "
                "endpoints are reacting to real loss", Category.FAULT, 1.0))
        if self.dupacks:
            f.indicators.append(Indicator(f"{self.dupacks:,} duplicate ACKs: receivers report missing data",
                                          Category.FAULT, 0.5))
        if not one_server and len(self.rx_by_server) >= 3:
            f.indicators.append(Indicator("Loss affects connections to many unrelated servers: a shared link problem",
                                          Category.FAULT, 1.0))
        f.indicators.append(Indicator("No sign of deliberate interference: the loss pattern matches congestion or "
                                      "a bad link", Category.FAULT, 0.5))
        self.rx_ev.apply(f)
        return [f]

    # ================================================================== #
    # tcp.refused
    # ================================================================== #
    def _f_refused(self, ctx: AnalysisContext) -> list[Finding]:
        need = scaled(3, ctx)
        cands = []
        for (ip, port), svc in self.services.items():
            if not svc.refused_by:
                continue
            clients = {s: n for s, n in svc.refused_by.items() if not self.fanout.is_scanner(s)}
            n = sum(clients.values())
            if n >= need:
                cands.append((n, ip, port, svc, clients))
        cands.sort(key=lambda x: -x[0])
        out = []
        for n, ip, port, svc, clients in cands[:10]:
            out.append(self._refused_finding(n, ip, port, svc, clients))
        return out

    def _refused_finding(self, n, ip, port, svc: _Svc, clients: dict) -> Finding:
        target = _ep(ip, port)
        ipc = _cap(ip, 45)
        crashed = (svc.first_accept is not None and svc.first_refuse is not None
                   and svc.first_accept < svc.first_refuse)
        flapping = crashed and svc.last_accept is not None and svc.last_accept > svc.first_refuse
        never = svc.first_accept is None
        rst_ttl = _mode(svc.rst_ttls)
        ok_ttl = _mode(svc.synack_ttls)
        middlebox = rst_ttl is not None and ok_ttl is not None and abs(rst_ttl - ok_ttl) >= 5
        ncl = len(clients)
        ind = []
        if never:
            ind.append(Indicator(f"Every one of {n} attempts was refused and the service never accepted a "
                                 "connection in this capture", Category.MISCONFIG, 2.0))
        if crashed and not flapping:
            ind.append(Indicator(f"The service accepted {plural(svc.accepted, 'connection')} earlier, then started "
                                 "refusing: it stopped or crashed during the capture", Category.FAULT, 2.5))
        if flapping:
            ind.append(Indicator("The service alternates between accepting and refusing: it is restarting or "
                                 "overloaded", Category.FAULT, 2.0))
        if middlebox:
            ind.append(Indicator(f"The refusals arrive with IP TTL {rst_ttl} while the server's own replies have TTL "
                                 f"{ok_ttl}: a firewall in between is rejecting them", Category.MISCONFIG, 1.5))
        ind.append(Indicator(f"Refusals come from {plural(ncl, 'normal client')} retrying one service, not a scan "
                             "across many ports or hosts", Category.MISCONFIG if never else Category.FAULT, 1.0))
        if ncl >= 20:
            ind.append(Indicator(f"{ncl} different sources hit this closed port", Category.ATTACK, 0.5))
        if never:
            cat = Category.MISCONFIG
            sev = Severity.MEDIUM if (n >= 5 or ncl >= 2) else Severity.LOW
        else:
            cat = Category.FAULT
            sev = Severity.HIGH if crashed and not flapping else Severity.MEDIUM

        mis = Variant(
            title=f"Connections to {target} are being refused",
            summary=f"{n} connection attempts to {target} were refused immediately; nothing is listening there.",
            explanation=(
                f"The computer at {ipc} answered every connection request on port {port} with a TCP reset, which "
                "means \"no program is accepting connections on this port\". The network itself works (the host "
                "answered quickly); the problem is the address or the service configuration."
            ),
            cause=("The service is not running, listens on a different port or only on localhost, the client is "
                   "configured with the wrong port, or a firewall rule rejects it."
                   + (" The reset comes from a device in between (different TTL), so a firewall is the likely "
                      "culprit." if middlebox else "")),
            fix=[
                f"On {ipc}, check that the service is running and listening on port {port}: `ss -ltnp | grep :{port}` "
                f"(Linux) or `netstat -ano | findstr :{port}` (Windows).",
                "If it listens on 127.0.0.1 only, change its bind address to the server's network address or 0.0.0.0.",
                "Check the client's configuration: is the port number right (e.g. 8080 vs 80, 5432 vs 5433)?",
                f"Check host and network firewalls for a reject rule on port {port} (`sudo iptables -L -n -v`, "
                "`sudo nft list ruleset`, Windows Defender Firewall).",
                f"Re-test from the client with `nc -vz {ipc} {port}` or `Test-NetConnection {ipc} -Port {port}`.",
            ],
            analogy="Like ringing a doorbell and having someone shout \"nobody by that name lives here\" every time.",
            severity=Severity.MEDIUM if n >= 5 or ncl >= 2 else Severity.LOW,
        )
        flt = Variant(
            title=f"The service at {target} stopped accepting connections",
            summary=(f"{target} accepted {plural(svc.accepted, 'connection')} and then refused {n} attempts: the "
                     "service appears to have crashed or been stopped."),
            explanation=(
                f"Earlier in the capture {ipc} accepted connections on port {port} normally. Later the same port "
                "answered new connections with an immediate reset, which is what an operating system does when no "
                "program is listening any more. The computer is still up; the program behind the port went away"
                + (" and came back at times, so it is restarting or overloaded." if flapping else ".")
            ),
            cause=("The server application crashed, was restarted, or was stopped; it may also be hitting a "
                   "resource limit and restarting."),
            fix=[
                f"Check whether the service on {ipc} is still running (`systemctl status <service>`, `docker ps`, "
                "Windows Services).",
                "Read the service's logs and the system log around the time the refusals started (`journalctl -u "
                "<service> --since ...`, Event Viewer) for crashes or out-of-memory kills.",
                "Restart the service and confirm it listens again: `ss -ltnp | grep :" + str(port) + "`.",
                "If it keeps dying, check resources (memory, disk, file-descriptor limits) and add a process "
                "supervisor/health check so it is restarted automatically.",
            ],
            analogy="Like a shop that was open this morning and now has the shutters down in the middle of the day.",
            severity=Severity.HIGH if crashed and not flapping else Severity.MEDIUM,
        )
        v = mis if cat == Category.MISCONFIG else flt
        f = Finding(
            kind="tcp.refused", category=cat, severity=sev,
            title=v.title, summary=v.summary, explanation=v.explanation, cause=v.cause, fix=v.fix, analogy=v.analogy,
            technical=(
                f"{n} SYNs to {target} were answered with RST/ACK (connection refused) from {plural(ncl, 'client')}; "
                f"{svc.accepted} SYN/ACKs from the same service in the capture"
                + (f", first accept before the first refusal (crash at ~{fmt_ms(svc.first_refuse - svc.first_accept)} "
                   "after the first accept)" if crashed else "")
                + (f"; RST TTL {rst_ttl} vs SYN/ACK TTL {ok_ttl} (middlebox-generated)" if middlebox else "")
                + ". Scanning sources (>15 ports, or >15 hosts mostly failing) were excluded."
            ),
            hosts=[ip] + [c for c in list(clients)[:9]],
            metrics={
                "service": target, "refused": n, "accepted": svc.accepted, "clients": ncl,
                "pattern": "never_accepted" if never else ("intermittent" if flapping else "stopped"),
                "rst_ttl": rst_ttl, "synack_ttl": ok_ttl,
                "top_clients": [{"ip": _cap(c, 45), "attempts": k} for c, k in
                                sorted(clients.items(), key=lambda kv: -kv[1])[:10]],
            },
            indicators=ind,
            variants={Category.MISCONFIG: mis, Category.FAULT: flt},
        )
        svc.ev.apply(f)
        return f

    # ================================================================== #
    # tcp.syn_timeout
    # ================================================================== #
    def _f_syn_timeout(self, ctx: AnalysisContext) -> list[Finding]:
        cands = []
        for (ip, port), svc in self.services.items():
            if not svc.to_flows:
                continue
            by = {s: e for s, e in svc.to_by.items() if not self.fanout.is_scanner(s)}
            if not by:
                continue
            flows = sum(e[0] for e in by.values())
            syns = sum(e[1] for e in by.values())
            retried = sum(e[2] for e in by.values())
            if retried >= max(2, scaled(2, ctx)) or syns >= scaled(5, ctx):
                cands.append((syns, ip, port, svc, by, flows, retried))
        cands.sort(key=lambda x: -x[0])
        return [self._syn_timeout_finding(ctx, *c) for c in cands[:10]]

    def _syn_timeout_finding(self, ctx, syns, ip, port, svc: _Svc, by: dict, flows: int, retried: int) -> Finding:
        target = _ep(ip, port)
        ipc = _cap(ip, 45)
        host = ctx.hosts.hosts.get(ip)
        host_alive = host is not None and host.packets_sent > 0
        ncl = len(by)
        single_syn_sources = sum(1 for e in by.values() if e[0] == 1 and e[1] == 1)
        bo = svc.to_backoff
        backoff = len(bo) >= 2 and all(b >= a * 1.5 for a, b in zip(bo, bo[1:]) if a > 0)
        flood = ncl >= 20 and single_syn_sources >= 0.8 * ncl  # spoofed sources never retry
        ind = []
        if retried:
            ind.append(Indicator(f"{plural(retried, 'connection attempt')} retried the SYN 2+ times"
                                 + (" with exponential backoff (" + ", ".join(f"{x:g}s" for x in bo) + "), the normal "
                                    "behaviour of a real client's operating system" if backoff else ""),
                                 Category.FAULT, 1.5))
        if ncl <= 5:
            ind.append(Indicator(f"SYNs come from {plural(ncl, 'normal client')} to one service; not a scan pattern",
                                 Category.FAULT, 1.0))
        if host_alive:
            ind.append(Indicator(f"{ipc} is up (it sent other traffic in this capture) but port {port} never "
                                 "answers: a firewall is silently dropping it", Category.MISCONFIG, 2.0))
        else:
            ind.append(Indicator(f"{ipc} never sent a single packet in this capture: host down, unreachable or "
                                 "wrong address", Category.FAULT, 1.0))
            ind.append(Indicator("The address may simply be wrong (stale DNS record or configuration)",
                                 Category.MISCONFIG, 0.5))
        if svc.accepted:
            ind.append(Indicator(f"The same service accepted {plural(svc.accepted, 'other connection')}: it is "
                                 "intermittently overloaded or losing packets", Category.FAULT, 1.0))
        if flood:
            ind.append(Indicator(f"{ncl} different sources each sent a single never-retried SYN: the signature of a "
                                 "SYN flood with spoofed addresses", Category.ATTACK, 2.5))
        if flood:
            cat = Category.ATTACK
        elif host_alive and not svc.accepted:
            cat = Category.MISCONFIG
        else:
            cat = Category.FAULT
        sev = Severity.HIGH if (flows >= 5 or ncl >= 2) and not svc.accepted else Severity.MEDIUM
        flt = Variant(
            title=f"Nobody answers connection attempts to {target}",
            summary=f"{plural(flows, 'connection attempt')} to {target} got no reply at all ({syns} SYNs sent).",
            explanation=(
                f"To start a TCP connection, the client sends a \"hello\" (SYN) and waits for a reply. Requests to "
                f"{ipc} on port {port} got no reply whatsoever, not even a refusal, so the client kept retrying with "
                "growing pauses and finally gave up. To the user this looks like an app that hangs and then "
                "times out."
            ),
            cause=("The server is down or unreachable, its address is wrong, or something on the path silently "
                   "drops the packets."),
            fix=[
                f"Check that {ipc} is the right address (DNS record, app config) and that the machine is powered on.",
                f"Test basic reachability: `ping {ipc}` and `traceroute {ipc}` (Windows: `tracert`); the trace shows "
                "where packets stop.",
                f"Test the port itself: `nc -vz -w 5 {ipc} {port}` or `Test-NetConnection {ipc} -Port {port}`.",
                "Check routes and the default gateway on the client (`ip route`, `route print`).",
                f"If the host is up, check its firewall and any network firewall for a DROP rule on port {port}.",
            ],
            analogy="Like knocking on a door again and again and hearing nothing at all, not even \"go away\".",
        )
        mis = Variant(
            title=f"A firewall seems to silently block {target}",
            summary=(f"{ipc} is reachable, but {plural(flows, 'connection attempt')} to its port {port} were "
                     "silently ignored."),
            explanation=(
                f"The computer {ipc} is clearly alive (it sent other traffic), yet connection requests to port {port} "
                "vanish without any answer. A closed port would answer with a refusal; silence usually means a "
                "firewall rule set to \"drop\" is swallowing the packets."
            ),
            cause=f"A firewall on {ipc} or on the path drops traffic to port {port} (a DROP rule instead of ALLOW).",
            fix=[
                f"Check the firewall on {ipc}: `sudo iptables -L -n -v | grep {port}`, `sudo nft list ruleset`, "
                "`sudo ufw status`, or Windows Defender Firewall inbound rules.",
                "Check network firewalls, cloud security groups and router ACLs between client and server.",
                f"Confirm the service listens: `ss -ltnp | grep :{port}` on the server.",
                f"Re-test from the client: `nc -vz -w 5 {ipc} {port}`.",
            ],
            analogy="Like a guarded gate where the guard quietly bins your letters instead of returning them.",
        )
        atk = Variant(
            title=f"Possible SYN flood towards {target}",
            summary=f"{ncl} sources sent never-answered SYNs to {target}.",
            explanation=("Many different addresses sent a single connection request each and never retried; real "
                         "clients retry. This pattern fits a SYN flood using forged sender addresses."),
            cause="A denial-of-service attempt with spoofed source addresses.",
            fix=["Enable SYN cookies on the server (`sysctl -w net.ipv4.tcp_syncookies=1`).",
                 "Rate-limit SYNs at the firewall or ask the upstream provider for DDoS filtering.",
                 "Check the scan/flood findings in this report for the same time window."],
            mitre="T1499 Endpoint Denial of Service",
        )
        v = {Category.MISCONFIG: mis, Category.ATTACK: atk}.get(cat, flt)
        f = Finding(
            kind="tcp.syn_timeout", category=cat, severity=sev, mitre=v.mitre,
            title=v.title, summary=v.summary, explanation=v.explanation, cause=v.cause, fix=v.fix, analogy=v.analogy,
            technical=(
                f"{flows} connection attempts ({syns} SYNs, {retried} with >=2 retransmitted SYNs) to {target} received "
                f"no SYN/ACK, RST or ICMP error. SYN retry intervals: {bo or 'n/a'}. Target host "
                f"{'did' if host_alive else 'did not'} send other packets; service accepted {svc.accepted} connections. "
                "Single-SYN attempts within 3 s of the capture end and scanning sources were excluded."
            ),
            hosts=[ip] + list(by)[:9],
            metrics={"service": target, "attempts": flows, "syns": syns, "retried_attempts": retried, "clients": ncl,
                     "syn_retry_intervals_s": bo, "host_alive": host_alive, "accepted_elsewhere": svc.accepted},
            indicators=ind,
            variants={Category.FAULT: flt, Category.MISCONFIG: mis, Category.ATTACK: atk},
        )
        svc.to_ev.apply(f)
        return f

    # ================================================================== #
    # tcp.resets
    # ================================================================== #
    def _f_resets(self, ctx: AnalysisContext) -> list[Finding]:
        n = len(self.aborts)
        est = max(self.established, 1)
        inj = self.inject
        # one forged-looking reset alone is not enough unless two independent signs agree
        inj_strong = [i for i in inj if (i["ttl_mismatch"] + (i["packets_after_rst"] >= 1) + 0.5 * i["seq_mismatch"]) >= 2]
        trig = n >= scaled(5, ctx) or (n >= max(2, scaled(3, ctx)) and n / est >= 0.10)
        inj_trig = len(inj) >= 2 or bool(inj_strong)
        if not trig and not inj_trig:
            return []
        by_server: dict = {}
        by_sender = {"client": 0, "server": 0}
        idle_kills = 0
        for a in self.aborts:
            _bump(by_server, a[4], cap=1024)
            by_sender[a[2]] += 1
            if a[6] is not None and a[6] >= 300:
                idle_kills += 1
        top_srv = max(by_server.items(), key=lambda kv: kv[1])[0] if by_server else (None)
        top_share = by_server.get(top_srv, 0) / n if n else 0
        srv_txt = _cap(top_srv, 45) if top_srv and top_share >= 0.6 else None
        who = "server" if by_sender["server"] >= by_sender["client"] else "client"
        ind = []
        if n:
            ind.append(Indicator(f"{n} of {self.established:,} established connections ({fmt_pct(n / est)}) were "
                                 "aborted with a reset while data was still in flight", Category.FAULT, 1.5))
            genuine = sum(1 for a in self.aborts if not a[8] and not a[10])
            if genuine:
                ind.append(Indicator(f"{genuine} resets carry the same IP TTL as the endpoint's other packets and the "
                                     "endpoint went silent afterwards: they really came from the endpoint",
                                     Category.FAULT, 1.5 if genuine >= 0.7 * n else 0.5))
        if idle_kills:
            ind.append(Indicator(f"{idle_kills} connections were reset after being idle for 5+ minutes: a firewall/NAT "
                                 "timeout", Category.MISCONFIG, 1.0))
        if inj:
            ttl_n = sum(1 for i in inj if i["ttl_mismatch"])
            post_n = sum(1 for i in inj if i["packets_after_rst"])
            seq_n = sum(1 for i in inj if i["seq_mismatch"])
            if ttl_n:
                ind.append(Indicator(f"{ttl_n} resets arrived with an IP TTL that differs by 5+ from every other packet "
                                     "of the same sender in that connection: they were probably forged by a device on "
                                     "the path", Category.ATTACK, 2.0))
            if post_n:
                ind.append(Indicator(f"In {post_n} connections the supposed sender of the reset kept sending normally "
                                     "afterwards, so it never sent the reset itself", Category.ATTACK, 2.5))
            if seq_n:
                ind.append(Indicator(f"{seq_n} resets used a sequence number that is inside the window but not the "
                                     "exact expected value (blind-reset pattern)", Category.ATTACK, 1.0))
        elif n:
            ind.append(Indicator("No forged-reset signs (TTL and sequence numbers match the endpoints)",
                                 Category.FAULT, 1.0))
        attack = bool(inj) and (not n or len(inj) >= 0.5 * n)
        cat = Category.ATTACK if attack else Category.FAULT
        sev_n = Severity.HIGH if n >= scaled(20, ctx) or n / est >= 0.3 else Severity.MEDIUM
        if not trig:
            sev_n = Severity.LOW
        where = f" with {srv_txt}" if srv_txt else ""
        flt = Variant(
            title=f"Connections{where} are being cut off in the middle",
            summary=(f"{n} connections were aborted mid-transfer with a TCP reset ({fmt_pct(n / est)} of established "
                     f"connections), mostly sent by the {who}."),
            explanation=(
                "A TCP reset (RST) is an emergency hang-up: instead of saying goodbye properly, one side abruptly "
                "kills the connection, and any data still on the way is thrown away. Here it happened while data was "
                f"still being transferred, so users see errors like \"connection reset\" or broken downloads. Most "
                f"resets came from the {who} side."
            ),
            cause=(f"The {who} application closed or crashed mid-transfer, hit a timeout, or a load balancer/firewall "
                   "dropped the connection." + (" Several connections died after a long idle period, which is typical "
                                                "of a firewall or NAT forgetting idle connections." if idle_kills else "")),
            fix=[
                f"Check the {who} application logs at the times of the resets (see evidence frames) for crashes, "
                "timeouts or 'connection reset' errors.",
                "If a load balancer, proxy or firewall sits in between, check its idle-timeout and max-connection "
                "settings and its logs.",
                "For long idle connections, enable TCP keepalives shorter than the firewall/NAT idle timeout "
                "(e.g. `sysctl net.ipv4.tcp_keepalive_time=300`).",
                "Check server resources (memory, worker/connection limits) if the server is the one resetting.",
            ],
            analogy="Like a phone call where the other person suddenly hangs up in the middle of a sentence.",
            severity=sev_n,
        )
        atk = Variant(
            title="Someone may be injecting forged resets into connections",
            summary=(f"{plural(len(inj), 'connection')} were killed by resets that do not look like they came from "
                     "the real endpoint."),
            explanation=(
                "A reset is supposed to come from one of the two computers in a conversation. These resets have tell-"
                "tale differences: a different hop count (TTL) than every other packet from that computer, or the "
                "\"sender\" kept talking normally after supposedly hanging up. That means a third device forged them "
                "to cut the connection, as censorship systems, some intrusion-prevention boxes, or an attacker do."
            ),
            cause=("An on-path device (firewall/IPS, ISP filtering, or an attacker with access to the path) is "
                   "injecting TCP resets to tear down connections."),
            fix=[
                "Check whether a firewall, IPS or web filter in your own network is configured to reset these "
                "connections (its logs will show deliberate 'reset' actions).",
                "Compare the TTL of the reset with the endpoint's normal packets (shown in the metrics) and run "
                "`traceroute` to find which hop that TTL corresponds to.",
                "If no device of yours does it, test the same connection over a VPN or another network; if the "
                "resets disappear, report it to the ISP.",
                "Prefer encrypted, authenticated transports (TLS, VPN); they cannot stop resets but prevent content "
                "tampering.",
            ],
            analogy="Like someone cutting into your phone line and hanging up the call while imitating the other person's voice.",
            mitre="T1499 Endpoint Denial of Service",
            severity=Severity.HIGH,
        )
        v = atk if cat == Category.ATTACK else flt
        f = Finding(
            kind="tcp.resets", category=cat, severity=Severity.HIGH if attack else sev_n,
            title=v.title, summary=v.summary, explanation=v.explanation, cause=v.cause, fix=v.fix, analogy=v.analogy,
            mitre=v.mitre,
            technical=(
                f"{n} established connections aborted by RST with unacknowledged data in flight or mid-write (of "
                f"{self.established:,} established; {by_sender['server']} RSTs from servers, {by_sender['client']} from "
                f"clients). Ignored as benign: {self.after_fin_rsts} RSTs after a FIN, {self.idle_close_rsts} abortive "
                f"closes of idle connections. Injection candidates: {len(inj)} (TTL deviation >= 5 from the sender's "
                "per-flow TTL mode, sender activity after its own RST, in-window but inexact sequence numbers)."
            ),
            hosts=[h for h in dict.fromkeys(([top_srv] if top_srv else []) + [a[3] for a in self.aborts[:5]] +
                                            [a[4] for a in self.aborts[:5]]) if h][:10],
            metrics={
                "aborted_connections": n, "established_connections": self.established,
                "abort_rate": round(n / est, 4), "rst_from_server": by_sender["server"],
                "rst_from_client": by_sender["client"], "ignored_after_fin": self.after_fin_rsts,
                "ignored_idle_abortive_close": self.idle_close_rsts, "idle_timeouts": idle_kills,
                "injection_candidates": inj[:10],
                "top_servers": [{"ip": _cap(k, 45), "aborts": c} for k, c in
                                sorted(by_server.items(), key=lambda kv: -kv[1])[:10]],
            },
            indicators=ind,
            variants={Category.FAULT: flt, Category.ATTACK: atk},
        )
        ev = Evidence()
        ev.merge(self.inject_ev)
        ev.merge(self.abort_ev)
        ev.apply(f)
        return [f]

    # ================================================================== #
    # tcp.zero_window
    # ================================================================== #
    def _f_zero_window(self, ctx: AnalysisContext) -> list[Finding]:
        if not self.zw:
            return []
        events = sum(z[0] for z in self.zw.values())
        stall = sum(z[1] for z in self.zw.values())
        if events < scaled(3, ctx) and stall < 1.0:
            return []
        recv, z = max(self.zw.items(), key=lambda kv: (kv[1][1], kv[1][0]))
        rc = _cap(recv, 45)
        many = len(self.zw) > 1
        peers = list(z[5])
        sev = Severity.HIGH if stall >= 5.0 else Severity.MEDIUM if stall >= 1.0 else Severity.LOW
        probes = sum(q[3] for q in self.zw.values())
        f = Finding(
            kind="tcp.zero_window", category=Category.FAULT, severity=sev,
            title=f"{rc} is receiving data faster than it can handle"[:120],
            summary=(f"{rc} told the sender to pause {plural(events, 'time')} (TCP zero window), stalling transfers for "
                     f"{fmt_ms(stall)} in total."),
            explanation=(
                "Every TCP receiver has an inbox (the receive buffer) and keeps telling the sender how much free room "
                f"is left (the window). {rc} repeatedly reported \"0 bytes free\", so the sender had to stop and wait. "
                "The network was fine; the program on the receiving computer was not reading its data fast enough."
            ),
            analogy="Like a mailbox that is full: the postman has to wait until someone empties it before delivering more.",
            cause=(f"The receiving application on {rc} is too slow or blocked (busy CPU, slow disk writes, a "
                   "frozen/overloaded process, or a small receive buffer). This is a host problem, not a network one."),
            fix=[
                f"On {rc}, check CPU, memory and disk load during the transfer (`top`, `iostat -x 1`, Task Manager / "
                "Resource Monitor).",
                "Check the receiving application: is it blocked, single-threaded, or writing to a slow disk/network share?",
                "On Linux, check receive-buffer autotuning: `sysctl net.ipv4.tcp_rmem net.core.rmem_max`, and make "
                "sure the application does not set a tiny SO_RCVBUF.",
                "Do not chase the network: the zero window is the receiver's own message.",
            ],
            technical=(
                f"{events} zero-window episodes ({z[6] if not many else sum(q[6] for q in self.zw.values())} zero-window "
                f"packets, {probes} zero-window probes) on {plural(sum(q[4] for q in self.zw.values()), 'connection')}; "
                f"total stall {stall:.3f} s, longest {max(q[2] for q in self.zw.values()):.3f} s (from the first win=0 "
                f"until the window update). Window-full events: {self.win_full}. Worst receiver {rc}: {z[0]} episodes, "
                f"{z[1]:.3f} s stalled."
            ),
            hosts=[recv] + [p for p in peers[:5]] + [ip for ip in self.zw if ip != recv][:4],
            metrics={
                "zero_window_events": events, "stall_seconds": round(stall, 3),
                "longest_stall_seconds": round(max(q[2] for q in self.zw.values()), 3),
                "zero_window_probes": probes, "window_full": self.win_full, "receiver": rc,
                "receivers": [{"ip": _cap(k, 45), "events": q[0], "stall_seconds": round(q[1], 3)}
                              for k, q in sorted(self.zw.items(), key=lambda kv: -kv[1][1])[:10]],
            },
            indicators=[
                Indicator(f"The receiver itself advertised a zero window {events} times: it is the bottleneck, "
                          "not the network", Category.FAULT, 2.0),
                Indicator("Zero window is ordinary flow control from a legitimate endpoint; no attack pattern",
                          Category.FAULT, 0.5),
            ],
        )
        self.zw_ev.apply(f)
        return [f]
