"""Path-MTU problems.

* ``mtu.frag_needed``: routers sending ICMPv4 "fragmentation needed" (type 3
  code 4) or ICMPv6 "packet too big". We report the router, the MTU it
  advertises and, by watching the quoted flows *after* the ICMP, whether the
  senders actually adapted (later packets fit the MTU) or kept sending
  oversized packets (ICMP filtered between capture point and sender, or
  ignored).

* ``mtu.blackhole``: the PMTUD black hole. Full-size DF segments are resent
  again and again and never acknowledged, no ICMP arrives, yet the same
  connection works for small packets (handshake / small data ACKed, or the
  sender finally falls back to smaller segments that do get through, the
  "smoking gun"). Classic behind VPNs, PPPoE and tunnels whose MTU is below
  1500 when a firewall blocks ICMP.

MSS sanity (SYN MSS larger than the link allows, wildly asymmetric MSS) is
recorded in the metrics of these findings only; on its own it is not a
problem worth an alert.
"""

from __future__ import annotations

import math

from .base import (
    AnalysisContext, BoundedDict, Category, Detector, Evidence, Finding, Indicator,
    Packet, Severity, plural, register,
)

MASK = 0xFFFFFFFF
HALF = 0x80000000
SYN, ACK, RST = 0x02, 0x10, 0x04
BIG = 1200  # payload bytes: a "full-size" segment
TUNNEL_MTUS = {
    1492: "PPPoE (DSL)", 1480: "6in4 / IP-in-IP tunnel", 1476: "GRE tunnel", 1472: "GRE+key / L2TP",
    1460: "IPsec / tunnel", 1450: "VXLAN", 1440: "WireGuard (IPv6 underlay)", 1420: "WireGuard",
    1400: "VPN / IPsec", 1380: "IPsec (NAT-T)", 1280: "IPv6 minimum / tunnel",
}


def sdiff(a: int, b: int) -> int:
    return ((a - b + HALF) & MASK) - HALF


def scaled(n: float, ctx: AnalysisContext) -> int:
    return max(1, math.ceil(n * ctx.config.scale))


def _cap(s, n: int = 100) -> str:
    s = "" if s is None else str(s)
    return "".join(ch if ch.isprintable() else " " for ch in s)[:n]


def _ip_size(pkt: Packet) -> int | None:
    """IP packet size from the headers (independent of how ip_len is defined)."""
    iph = 40 if pkt.ip_ver == 6 else 20
    if pkt.tcp is not None:
        return iph + (pkt.tcp.hlen or 20) + (pkt.tcp.plen or 0)
    if pkt.udp is not None:
        return iph + 8 + (pkt.udp.plen or 0)
    return None


class _Dir:
    """One direction (data sender → receiver) of a TCP connection."""

    __slots__ = ("mss", "isn", "max_ack", "acked_data", "big", "pend", "max_ok", "icmp", "v6", "hlen", "first_big_ts")

    def __init__(self) -> None:
        self.mss = None
        self.isn = None
        self.max_ack = None  # highest raw ACK from the receiver
        self.acked_data = False  # receiver acknowledged real data from this sender
        self.big = None  # seq -> [sends_before_ack, frames, plen, first_ts, acked, fallback_plen]
        self.pend = None  # recent unacked segments: [seq, plen, sends] (ring of 16)
        self.max_ok = 0  # largest payload ACKed within its first two transmissions
        self.icmp = False
        self.v6 = False
        self.hlen = 20
        self.first_big_ts = None


class _Router:
    __slots__ = ("count", "mtus", "flows", "ev", "senders", "v6", "tiny", "unknown_flow")

    def __init__(self) -> None:
        self.count = 0
        self.mtus: dict = {}
        self.flows: list = []
        self.ev = Evidence()
        self.senders: set = set()
        self.v6 = False
        self.tiny = 0
        self.unknown_flow = 0


@register
class MtuDetector(Detector):
    name = "mtu"

    def __init__(self) -> None:
        self.dirs: BoundedDict = BoundedDict(200_000)
        self.routers: dict = {}
        self.watch: BoundedDict = BoundedDict(10_000)  # quoted flow -> [icmp_ts, mtu, big, small, router]
        self.last_sent: BoundedDict = BoundedDict(100_000)  # ip -> last ts it sent anything
        self.seen_pairs: BoundedDict = BoundedDict(100_000)  # (src, dst) pairs that carried traffic
        self.mss_big = 0
        self.mss_max = 0
        self.mss_asym: list = []

    # ------------------------------------------------------------------ #
    def on_packet(self, pkt: Packet, ctx: AnalysisContext) -> None:
        if pkt.src is None or pkt.dst is None:
            return
        ts = pkt.ts if isinstance(pkt.ts, (int, float)) else 0.0
        self.last_sent[pkt.src] = ts
        if pkt.icmp is not None:
            if pkt.icmp.is_frag_needed:
                self._on_frag_needed(pkt, ts)
            return
        if pkt.tcp is None and pkt.udp is None:
            return
        pair = (pkt.src, pkt.dst)
        if pair not in self.seen_pairs:
            self.seen_pairs[pair] = True
        sport, dport = pkt.sport, pkt.dport
        if sport is None or dport is None:
            return
        if self.watch:
            w = self.watch.get((pkt.src, pkt.dst, sport, dport))
            if w is not None and ts > w[0] + 0.05:  # grace for packets already in flight
                size = _ip_size(pkt)
                if size is not None and w[1]:
                    if size > w[1]:
                        w[2] += 1
                    elif size >= 0.7 * w[1]:
                        w[3] += 1
        t = pkt.tcp
        if t is None or t.seq is None:
            return
        fl = t.flags or 0
        if fl & RST:
            return
        dk = (pkt.src, sport, pkt.dst, dport)
        if fl & SYN:
            e = self._dir(dk)
            e.mss, e.isn, e.v6 = t.mss, t.seq, pkt.ip_ver == 6
            if t.mss:
                limit = 1440 if pkt.ip_ver == 6 else 1460
                if t.mss > limit and pkt.linktype in (1, None):
                    self.mss_big += 1
                self.mss_max = max(self.mss_max, t.mss)
                if fl & ACK:
                    peer = self.dirs.get((pkt.dst, dport, pkt.src, sport))
                    if peer is not None and peer.mss and abs(peer.mss - t.mss) >= 200 and len(self.mss_asym) < 10:
                        self.mss_asym.append({"a": _cap(pkt.dst, 45), "a_mss": peer.mss,
                                              "b": _cap(pkt.src, 45), "b_mss": t.mss})
            return
        # ACK from this packet's sender acknowledges the *reverse* direction's data
        if fl & ACK and t.ack is not None:
            er = self.dirs.get((pkt.dst, dport, pkt.src, sport))
            if er is not None:
                self._on_ack(er, t.ack)
        plen = t.plen or 0
        if plen <= 0:
            return
        e = self.dirs.get(dk)
        if e is None:
            if plen < BIG:
                return  # untracked mid-stream flow with small data: nothing to learn
            e = self._dir(dk)
            e.v6 = pkt.ip_ver == 6
        e.hlen = t.hlen or 20
        df = pkt.df or pkt.ip_ver == 6
        pend = e.pend
        if pend is None:
            pend = e.pend = []
        for p_ in pend:
            if p_[0] == t.seq:
                p_[2] += 1
                break
        else:
            pend.append([t.seq, plen, 1])
            if len(pend) > 16:
                pend.pop(0)
        if e.big is not None:
            ent = e.big.get(t.seq)
            if ent is not None:
                if not ent[4]:
                    if plen >= ent[2]:
                        ent[0] += 1
                        if len(ent[1]) < 12:
                            ent[1].append(pkt.no)
                    elif ent[0] >= 2:
                        ent[5] = max(ent[5], plen)  # re-segmented smaller: PMTU fallback
                        if len(ent[1]) < 12:
                            ent[1].append(pkt.no)
                return
        if plen >= BIG and df:
            if e.big is None:
                e.big = {}
                e.first_big_ts = ts
            if len(e.big) < 32:
                e.big[t.seq] = [1, [pkt.no], plen, ts, False, 0]

    def _dir(self, dk) -> _Dir:
        e = self.dirs.get(dk)
        if e is None:
            e = self.dirs[dk] = _Dir()
        return e

    @staticmethod
    def _on_ack(er: _Dir, ack: int) -> None:
        if er.max_ack is not None and sdiff(ack, er.max_ack) <= 0:
            return
        if er.isn is not None:
            if sdiff(ack, (er.isn + 1) & MASK) > 0:
                er.acked_data = True  # beyond the SYN: real data was acknowledged
        elif er.max_ack is not None:
            er.acked_data = True  # mid-stream flow: the ACK moved forward
        er.max_ack = ack
        if er.pend:
            keep = []
            for p_ in er.pend:
                if sdiff(ack, (p_[0] + p_[1]) & MASK) >= 0:
                    if p_[2] <= 2 and p_[1] > er.max_ok:
                        er.max_ok = p_[1]  # this size gets through the path
                else:
                    keep.append(p_)
            er.pend = keep
        if er.big:
            for seq, ent in er.big.items():
                if not ent[4] and sdiff(ack, seq) > 0:
                    ent[4] = True

    def _on_frag_needed(self, pkt: Packet, ts: float) -> None:
        ic = pkt.icmp
        r = self.routers.get(pkt.src)
        if r is None:
            if len(self.routers) >= 1024:
                return
            r = self.routers[pkt.src] = _Router()
        r.count += 1
        r.v6 = r.v6 or bool(ic.v6)
        mtu = ic.mtu if isinstance(ic.mtu, int) and ic.mtu > 0 else None
        k = mtu if mtu is not None else 0
        if k in r.mtus or len(r.mtus) < 16:
            r.mtus[k] = r.mtus.get(k, 0) + 1
        if mtu is not None and mtu < (1280 if ic.v6 else 576):
            r.tiny += 1
        r.ev.add(pkt)
        inn = ic.inner
        if inn is None or not inn.src or not inn.dst:
            return
        if len(r.senders) < 64:
            r.senders.add(inn.src)
        if (inn.src, inn.dst) not in self.seen_pairs:
            r.unknown_flow += 1
        if inn.sport is not None and inn.dport is not None:
            fk = (inn.src, inn.dst, inn.sport, inn.dport)
            if len(r.flows) < 50 and fk not in r.flows:
                r.flows.append(fk)
            if fk not in self.watch:
                self.watch[fk] = [ts, mtu, 0, 0, pkt.src]
            else:
                w = self.watch[fk]
                w[0], w[1] = ts, mtu or w[1]
            if inn.proto == 6:
                e = self.dirs.get((inn.src, inn.sport, inn.dst, inn.dport))
                if e is not None:
                    e.icmp = True

    # ------------------------------------------------------------------ #
    def _mss_metrics(self) -> dict:
        return {"syn_mss_above_link": self.mss_big, "max_syn_mss": self.mss_max or None,
                "asymmetric_mss": self.mss_asym[:10]}

    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        out: list[Finding] = []
        for fn in (self._f_frag_needed, self._f_blackhole):
            try:
                out.extend(fn(ctx))
            except Exception:  # pragma: no cover
                continue
        return out

    # ================================================================== #
    # mtu.frag_needed
    # ================================================================== #
    def _f_frag_needed(self, ctx: AnalysisContext) -> list[Finding]:
        out = []
        for rip, r in sorted(self.routers.items(), key=lambda kv: -kv[1].count)[:5]:
            out.append(self._frag_finding(ctx, rip, r))
        return out

    def _frag_finding(self, ctx, rip, r: _Router) -> Finding:
        ripc = _cap(rip, 45)
        mtu = max(r.mtus.items(), key=lambda kv: kv[1])[0] if r.mtus else 0
        mtu_txt = str(mtu) if mtu else "unspecified"
        adapted = not_adapted = unknown = 0
        for fk in r.flows:
            w = self.watch.get(fk)
            if w is None or (w[2] == 0 and w[3] == 0):
                unknown += 1
            elif w[2] >= 2:
                not_adapted += 1
            else:
                adapted += 1
        tunnel = TUNNEL_MTUS.get(mtu)
        gw_ips, _ = ctx.hosts.gateway()
        is_gw = rip in gw_ips
        if not_adapted:
            sev = Severity.HIGH
        elif adapted and not unknown and r.count <= 2:
            sev = Severity.LOW
        else:
            sev = Severity.MEDIUM
        ind = [Indicator(f"Router {ripc} reports a path MTU of {mtu_txt} bytes, below the usual 1500",
                         Category.MISCONFIG, 1.5)]
        if tunnel:
            ind.append(Indicator(f"{mtu} is the typical MTU of {tunnel}: a tunnel/link with extra headers",
                                 Category.MISCONFIG, 1.5))
        if not_adapted:
            ind.append(Indicator(f"{plural(not_adapted, 'sender')} kept sending oversized packets after the warning: "
                                 "the ICMP message is probably filtered before it reaches them", Category.MISCONFIG, 1.0))
        if adapted:
            ind.append(Indicator(f"{plural(adapted, 'flow')} adapted to the smaller size afterwards: path MTU "
                                 "discovery works", Category.MISCONFIG, 0.5))
        if is_gw:
            ind.append(Indicator(f"{ripc} is this network's gateway", Category.MISCONFIG, 0.5))
        if r.tiny:
            ind.append(Indicator(f"{r.tiny} messages advertise an implausibly small MTU (< {1280 if r.v6 else 576}): "
                                 "forged ICMP is used to degrade connections", Category.ATTACK, 1.5))
        if r.unknown_flow and r.unknown_flow >= 0.8 * r.count and self.seen_pairs:
            ind.append(Indicator(f"{r.unknown_flow} messages quote traffic never seen in this capture",
                                 Category.ATTACK, 0.5))
        senders = sorted(r.senders)[:8]
        icmp_name = "ICMPv6 \"Packet Too Big\"" if r.v6 else "ICMP \"Fragmentation needed\" (type 3, code 4)"
        f = Finding(
            kind="mtu.frag_needed", category=Category.MISCONFIG, severity=sev,
            title=f"A router says packets are too big for the path (MTU {mtu_txt})",
            summary=(f"Router {ripc} sent {plural(r.count, 'warning')} that packets larger than {mtu_txt} bytes do "
                     f"not fit; {adapted} flow(s) adapted, {not_adapted} did not."),
            explanation=(
                "Every link has a maximum packet size (the MTU, normally 1500 bytes on Ethernet). When a packet is "
                "too big and marked \"don't fragment\", the router drops it and sends back a warning so the sender "
                f"can use smaller packets. Router {ripc} is doing exactly that, which means some link on this path, "
                f"often a VPN, PPPoE or tunnel, only carries {mtu_txt} bytes. "
                + ("Some senders ignored the warning (or never got it), so their large packets keep getting dropped "
                   "and connections hang." if not_adapted else
                   "The senders adapted, so things work, but with extra delay at the start of each connection.")
            ),
            analogy=("Like a low bridge on a truck route: a sign tells drivers to use smaller trucks; if a driver "
                     "never sees the sign, the truck gets stuck."),
            cause=(f"A link with a smaller MTU ({tunnel or 'tunnel/VPN/PPPoE'}) on the path, while the hosts still "
                   "assume 1500 bytes" + (" and the ICMP warning is blocked before it reaches the sender."
                                          if not_adapted else ".")),
            fix=[
                f"Find the real path MTU: `ping -M do -s 1472 <server>` on Linux (`ping -D -s 1472` on macOS, "
                f"`ping -f -l 1472 <server>` on Windows) and lower the size until it passes; MTU = size + 28.",
                "Lower the MTU on the tunnel/VPN interface to match, e.g. `sudo ip link set dev wg0 mtu 1420`, or "
                "`netsh interface ipv4 set subinterface \"<name>\" mtu=1400 store=persistent` on Windows.",
                "On the router/VPN, clamp TCP MSS to the path MTU: `iptables -t mangle -A FORWARD -p tcp "
                "--tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu`.",
                "Make sure firewalls allow ICMP type 3 code 4 (and ICMPv6 type 2) so path MTU discovery works.",
            ],
            technical=(
                f"{r.count} {icmp_name} from {ripc}; advertised MTUs {dict(sorted(r.mtus.items()))}. Quoted senders: "
                f"{', '.join(_cap(s, 45) for s in senders)}. After the ICMP (50 ms grace): {adapted} flows sent only "
                f"packets <= MTU, {not_adapted} sent >= 2 larger packets, {unknown} sent nothing more."
                + (f" Advertised MTU matches {tunnel}." if tunnel else "")
            ),
            hosts=[rip] + [s for s in senders if s != rip][:9],
            metrics={
                "router": ripc, "messages": r.count, "mtu": mtu or None,
                "mtus": {str(k): v for k, v in list(r.mtus.items())[:10]},
                "flows_adapted": adapted, "flows_not_adapted": not_adapted, "flows_unknown": unknown,
                "affected_flows": [f"{_cap(a, 45)}:{c} → {_cap(b, 45)}:{d}" for a, b, c, d in r.flows[:10]],
                "likely_link": tunnel, **self._mss_metrics(),
            },
            indicators=ind,
        )
        r.ev.apply(f)
        return f

    # ================================================================== #
    # mtu.blackhole
    # ================================================================== #
    def _f_blackhole(self, ctx: AnalysisContext) -> list[Finding]:
        hits = []
        for (src, sport, dst, dport), e in self.dirs.items():
            if not e.big or e.icmp:
                continue
            # size-specific: a segment as large as the stuck one got through -> just loss
            stuck = [(seq, ent) for seq, ent in e.big.items()
                     if ent[0] >= 4 and (not ent[4] or ent[5]) and ent[2] > e.max_ok]
            if not stuck:
                continue
            if e.max_ack is None:
                continue  # receiver never answered at all: dead peer, not an MTU problem
            fallback = max((ent[5] for _, ent in stuck), default=0)
            last_rx = self.last_sent.get(dst)
            alive = last_rx is not None and e.first_big_ts is not None and last_rx > e.first_big_ts
            # evidence tiers: re-segmentation that got through is conclusive; earlier small data ACKed
            # plus a receiver still alive is strong; a merely alive receiver is moderate
            if fallback:
                tier = "fallback"
            elif e.acked_data and alive:
                tier = "small_acked"
            else:
                tier = "alive" if alive else "weak"
            hits.append((src, sport, dst, dport, e, stuck, fallback, tier))
        if not hits:
            return []
        strong = [h for h in hits if h[7] in ("fallback", "small_acked")]
        weak = [h for h in hits if h[7] in ("alive", "weak")]
        alive_weak = [h for h in weak if h[7] == "alive"]
        if not strong and not (len(weak) >= scaled(3, ctx) or (len(weak) >= 2 and alive_weak)):
            return []
        hits.sort(key=lambda h: ({"fallback": 0, "small_acked": 1, "alive": 2, "weak": 3}[h[7]],
                                 -max(ent[0] for _, ent in h[5])))
        n = len(hits)
        senders = list(dict.fromkeys(h[0] for h in hits))
        receivers = list(dict.fromkeys(h[2] for h in hits))
        big_plen = max(ent[2] for h in hits for _, ent in h[5])
        h0 = hits[0]
        iph = 40 if h0[4].v6 else 20
        big_size = big_plen + h0[4].hlen + iph
        mss_neg = []
        for src, sport, dst, dport, e, *_ in hits:
            peer = self.dirs.get((dst, dport, src, sport))
            pm = [m for m in (e.mss, peer.mss if peer else None) if m]
            if pm:
                mss_neg.append(min(pm))
        mss = max(set(mss_neg), key=mss_neg.count) if mss_neg else None
        fb = max(h[6] for h in hits)
        ok = max(h[4].max_ok for h in hits)
        through = max(fb, ok if ok >= BIG // 2 else 0)  # largest payload proven to pass
        if through:
            pmtu_val = through + h0[4].hlen + iph
            pmtu_est = f"between {pmtu_val} and {big_size - 1} bytes ({pmtu_val} bytes got through, {big_size} did not)"
        else:
            pmtu_est = f"below {big_size} bytes (likely 1400-1492 for a VPN/PPPoE/tunnel)"
            pmtu_val = None
        resend = max(ent[0] for h in hits for _, ent in h[5])
        sc, rc = _cap(senders[0], 45), _cap(receivers[0], 45)
        ind = [
            Indicator(f"Full-size packets ({big_size} bytes, DF set) were sent up to {resend} times and never "
                      "acknowledged", Category.MISCONFIG, 1.5),
            Indicator("No ICMP \"fragmentation needed\" message arrived for these connections: the warning is "
                      "being blocked or never sent", Category.MISCONFIG, 1.0),
        ]
        if strong:
            if any(h[7] == "fallback" for h in hits):
                ind.append(Indicator("The sender finally re-sent the same data in smaller packets and those got "
                                     "through: a size limit, not general loss", Category.MISCONFIG, 3.0))
            if ok >= BIG // 2:
                ind.append(Indicator(f"Segments of {ok} bytes on the same connection were acknowledged at once while "
                                     f"{big_plen}-byte ones never were: the loss depends on packet size",
                                     Category.MISCONFIG, 2.0))
            if any(h[7] == "small_acked" for h in hits):
                ind.append(Indicator("Small packets on the same connection were acknowledged normally while the big "
                                     "ones vanished", Category.MISCONFIG, 2.0))
        if alive_weak:
            ind.append(Indicator("The receiver stayed active while the large packets went unanswered",
                                 Category.MISCONFIG, 1.0))
        if not strong:
            ind.append(Indicator("Only the handshake got through; the receiver going away would look similar",
                                 Category.FAULT, 0.5))
        f = Finding(
            kind="mtu.blackhole", category=Category.MISCONFIG,
            severity=Severity.MEDIUM if fb and len(hits) == 1 else Severity.HIGH,  # fallback: slow, not dead
            title=(f"Large packets from {sc} silently disappear (path MTU black hole)")[:120],
            summary=(f"On {plural(n, 'connection')}, full-size {big_size}-byte packets were resent up to {resend} times "
                     "and never arrived, while small packets worked."),
            explanation=(
                "Connections start fine (the small handshake packets get through) but as soon as a full-size packet "
                "is sent, it vanishes, and the sender keeps resending it in vain. Somewhere on the path a link only "
                "carries smaller packets (typically a VPN, PPPoE or other tunnel), and the router that should warn "
                "the sender to use smaller packets is blocked or silent. Users see websites or file transfers that "
                "start loading and then hang forever."
            ),
            analogy=("Like a tunnel that is too low for big trucks, with the warning sign missing: small cars pass, "
                     "big trucks get stuck and keep trying."),
            cause=("A link with an MTU below the senders' packet size (VPN/tunnel/PPPoE) combined with a firewall "
                   "that blocks ICMP \"fragmentation needed\" messages, so path MTU discovery cannot work."),
            fix=[
                f"Confirm it: `ping -M do -s 1472 {rc}` on Linux (Windows: `ping -f -l 1472 {rc}`); if it fails but "
                "`-s 1300` works, lower the size until it passes; path MTU = size + 28.",
                "Lower the MTU on the VPN/tunnel interface, e.g. `sudo ip link set dev wg0 mtu 1420`, or on Windows "
                "`netsh interface ipv4 set subinterface \"<name>\" mtu=1400 store=persistent`.",
                "Clamp TCP MSS on the router/VPN gateway: `iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST "
                "SYN -j TCPMSS --clamp-mss-to-pmtu` (or the router's 'MSS clamping' option).",
                "Allow ICMP type 3 code 4 (IPv6: ICMPv6 type 2) through every firewall on the path.",
                "As a stopgap on Linux hosts enable `sysctl -w net.ipv4.tcp_mtu_probing=1`.",
            ],
            technical=(
                f"{n} flow directions with a full-size DF segment ({big_plen} B payload, {big_size} B IP) transmitted >= 4 "
                f"times without being ACKed (max {resend}), no ICMP frag-needed/PTB quoting them, no full-size segment of "
                f"those senders ever ACKed on 1st/2nd try. Negotiated MSS {mss or 'unknown'}; likely path MTU "
                f"{pmtu_est}. Evidence tiers: "
                + ", ".join(f"{_cap(h[0], 45)}:{h[1]}→{_cap(h[2], 45)}:{h[3]}={h[7]}" for h in hits[:5]) + "."
            ),
            hosts=list(dict.fromkeys(senders[:5] + receivers[:5])),
            metrics={
                "flows": n, "max_resends": resend, "segment_payload": big_plen, "packet_size": big_size,
                "negotiated_mss": mss, "estimated_path_mtu": pmtu_val, "fallback_seen": bool(fb),
                "largest_payload_through": through or None,
                "affected_flows": [{"flow": f"{_cap(h[0], 45)}:{h[1]} → {_cap(h[2], 45)}:{h[3]}", "evidence": h[7]}
                                   for h in hits[:10]],
                **self._mss_metrics(),
            },
            indicators=ind,
        )
        ev = Evidence()
        for h in hits:
            for seq, ent in h[5]:
                for no in ent[1]:
                    if len(ev.packets) < Evidence.CAP:
                        ev.packets.append(no)
                ev.total += max(ent[0], len(ent[1]))
                ev.first_ts = ent[3] if ev.first_ts is None else min(ev.first_ts, ent[3])
                ev.last_ts = ent[3] if ev.last_ts is None else max(ev.last_ts, ent[3])
        ev.apply(f)
        return [f]
