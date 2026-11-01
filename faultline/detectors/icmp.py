"""ICMP diagnostics: destination unreachable, TTL exceeded / routing loops,
redirects.

ICMP is the network's error-reporting channel, so most of what it says is a
*symptom*. The work here is attributing each message correctly:

* **Unreachables** are grouped by meaning (no route / host down / nothing
  listening / blocked by a firewall). We drop the ones that are *not* a
  problem: port-unreachables caused by a UDP scan (``scanner_sources``, or
  one prober hitting many ports), the final hop of a UDP traceroute, and
  "late reply to a closed socket" (a DNS/QUIC answer arriving after the
  client gave up). Fragmentation-needed is left to the MTU detector.
* **Time exceeded** is normal during a traceroute (probes with increasing TTL,
  each hop answering a few times, UDP 33434+). A routing loop looks
  different: the same one or two routers keep reporting, or we literally see
  the *same packet* (same IP ID, ports) passing again and again with its TTL
  dropping by the same step each lap.
* **Redirects** are legitimate when the network's router points a host to a
  better router on the same LAN (a misconfiguration: two routers on one
  subnet). They are an attack (T1557) when sent by a host that is not the
  gateway, point to a host that never forwarded traffic (often the sender
  itself), come from off-link, or target many hosts.
"""

from __future__ import annotations

from collections import Counter

from ..context import is_multicast_or_broadcast, is_private
from .base import (
    AnalysisContext, BoundedDict, Category, Detector, Evidence, Finding, Indicator, Packet,
    Severity, Variant, fmt_pct, plural, register,
)
from .scan import is_traceroute_port, scanner_sources

UNREACH_THRESHOLD = 3
TE_THRESHOLD = 3
REDIRECT_THRESHOLD = 3
LATE_REPLY_PORTS = {53, 123, 443, 3478, 5353, 19302, 500, 4500}

# (v6, code) -> group
_V4_GROUP = {0: "route", 1: "host", 2: "port", 3: "port", 5: "other", 6: "route", 7: "host", 8: "host",
             9: "admin", 10: "admin", 11: "route", 12: "host", 13: "admin", 14: "admin", 15: "other"}
_V6_GROUP = {0: "route", 1: "admin", 2: "other", 3: "host", 4: "port", 5: "admin", 6: "admin", 7: "other"}
_V4_NAMES = {0: "network unreachable", 1: "host unreachable", 2: "protocol unreachable", 3: "port unreachable",
             5: "source route failed", 6: "destination network unknown", 7: "destination host unknown",
             8: "source host isolated", 9: "network administratively prohibited",
             10: "host administratively prohibited", 11: "network unreachable for TOS",
             12: "host unreachable for TOS", 13: "communication administratively prohibited",
             14: "host precedence violation", 15: "precedence cutoff"}
_V6_NAMES = {0: "no route to destination", 1: "administratively prohibited", 2: "beyond scope of source address",
             3: "address unreachable", 4: "port unreachable", 5: "source address failed policy", 6: "reject route",
             7: "error in source routing header"}
_PROTO = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}


def _code_name(v6: bool, code: int) -> str:
    return (_V6_NAMES if v6 else _V4_NAMES).get(code, f"code {code}")


def _prefix(ip: str | None) -> str:
    if not ip:
        return "?"
    if "." in ip and ":" not in ip:
        return ".".join(ip.split(".")[:3]) + ".0/24"
    parts = ip.split(":")
    return ":".join(parts[:4]) + "::/64" if len(parts) >= 4 else ip


def _same24(a: str | None, b: str | None) -> bool:
    return bool(a and b and "." in a and "." in b and a.rsplit(".", 1)[0] == b.rsplit(".", 1)[0])


class _Unreach:
    __slots__ = ("count", "ev", "codes", "reporters", "targets", "hosts", "dports", "matched", "v6")

    def __init__(self, v6: bool) -> None:
        self.count = 0
        self.ev = Evidence()
        self.codes: Counter = Counter()
        self.reporters: Counter = Counter()
        self.targets: Counter = Counter()  # "dst UDP port N"
        self.hosts: Counter = Counter()  # original destination IPs
        self.dports: set = set()
        self.matched = 0
        self.v6 = v6


class _TE:
    __slots__ = ("count", "ev", "reporters", "proto", "udp_trace", "dst")

    def __init__(self, dst: str | None, proto) -> None:
        self.count = 0
        self.ev = Evidence()
        self.reporters: Counter = Counter()
        self.proto = proto
        self.udp_trace = 0
        self.dst = dst


class _Loop:
    __slots__ = ("packets", "max_copies", "macs", "ev", "steps", "dsts", "srcs")

    def __init__(self) -> None:
        self.packets = 0
        self.max_copies = 0
        self.macs: Counter = Counter()
        self.ev = Evidence()
        self.steps: Counter = Counter()
        self.dsts: set = set()
        self.srcs: set = set()


class _Redirect:
    __slots__ = ("count", "ev", "targets", "gateways", "dests", "hop_limits", "macs", "v6", "first", "last")

    def __init__(self, v6: bool) -> None:
        self.count = 0
        self.ev = Evidence()
        self.targets: set = set()
        self.gateways: Counter = Counter()
        self.dests: set = set()
        self.hop_limits: Counter = Counter()
        self.macs: Counter = Counter()
        self.v6 = v6
        self.first = self.last = None


def _popcount(x: int) -> int:
    return bin(x).count("1")


@register
class IcmpDetector(Detector):
    name = "icmp"

    def __init__(self) -> None:
        self.unreach: BoundedDict = BoundedDict(20_000)  # (group, inner_src) -> _Unreach
        self.excluded = Counter()  # reason -> count
        self.flows: BoundedDict = BoundedDict(100_000)  # (src, dst, proto, dport) seen
        self.te: BoundedDict = BoundedDict(10_000)  # (inner_src, inner_dst, proto) -> _TE
        self.low_ttl: BoundedDict = BoundedDict(50_000)  # (src, dst) -> bitmask of TTLs <= 32
        self.src_ttl: BoundedDict = BoundedDict(50_000)  # src -> bitmask of TTLs <= 32
        self.copies: BoundedDict = BoundedDict(50_000)  # packet signature -> [ttl, step, n, ts, Evidence|None]
        self.loops: dict[str, _Loop] = {}  # dst prefix -> _Loop
        self.redirects: dict[str, _Redirect] = {}  # reporter -> _Redirect
        self.sent: BoundedDict = BoundedDict(50_000)  # src -> packets sent (for "matched flow" sanity)

    # ------------------------------------------------------------------ #
    def on_packet(self, pkt: Packet, ctx: AnalysisContext) -> None:
        src, dst = pkt.src, pkt.dst
        if src is None or dst is None:
            return
        t = pkt.ts or 0.0
        ttl = pkt.ttl
        proto = pkt.proto
        ic = pkt.icmp
        if ic is not None and (ic.is_unreachable or ic.is_time_exceeded or ic.is_redirect):
            if ic.is_unreachable:
                self._unreachable(pkt, ic)
            elif ic.is_time_exceeded:
                self._time_exceeded(pkt, ic)
            else:
                self._redirect(pkt, ic, t)
            return
        # remember initiating flows (to validate quoted datagrams) and low TTLs (traceroute / TTL misconfig)
        tcp, udp = pkt.tcp, pkt.udp
        dport = tcp.dport if tcp is not None else (udp.dport if udp is not None else None)
        if (tcp is not None and tcp.flags & 0x02) or udp is not None or (ic is not None and ic.is_echo_request):
            self.flows[(src, dst, proto, dport)] = None
            if ttl is not None and ttl <= 32:
                k = (src, dst)
                self.low_ttl[k] = self.low_ttl.get(k, 0) | (1 << ttl)
                self.src_ttl[src] = self.src_ttl.get(src, 0) | (1 << ttl)
        if src not in self.sent:
            self.sent[src] = 0
        self.sent[src] += 1
        # same packet seen again with a lower TTL => it is circling between routers
        if ttl is None or pkt.ip_id is None and tcp is None:
            return
        if is_multicast_or_broadcast(dst):
            return
        sig = (src, dst, pkt.ip_id, proto, pkt.sport, pkt.dport, tcp.seq if tcp is not None else None)
        e = self.copies.get(sig)
        if e is None:
            self.copies[sig] = [ttl, 0, 1, t, None]
            return
        diff = e[0] - ttl
        if 1 <= diff <= 4 and (e[1] == 0 or e[1] == diff) and abs(t - e[3]) <= 2.0:
            e[0], e[1], e[3] = ttl, diff, t
            e[2] += 1
            if e[4] is None:
                e[4] = Evidence()
            e[4].add(pkt)
            if e[2] >= 3:
                lp = self.loops.get(_prefix(dst))
                if lp is None:
                    if len(self.loops) >= 256:
                        return
                    lp = self.loops[_prefix(dst)] = _Loop()
                if e[2] == 3:
                    lp.packets += 1
                    lp.ev.merge(e[4])
                else:
                    lp.ev.add(pkt)
                lp.max_copies = max(lp.max_copies, e[2])
                lp.steps[diff] += 1
                if pkt.eth_src:
                    lp.macs[pkt.eth_src] += 1
                if len(lp.dsts) < 32:
                    lp.dsts.add(dst)
                if len(lp.srcs) < 32:
                    lp.srcs.add(src)
        elif diff != 0:
            self.copies[sig] = [ttl, 0, 1, t, None]

    # -- unreachable ----------------------------------------------------- #
    def _unreachable(self, pkt: Packet, ic) -> None:
        if ic.is_frag_needed:
            return  # handled by the MTU detector
        v6 = bool(ic.v6)
        group = (_V6_GROUP if v6 else _V4_GROUP).get(ic.code, "other")
        inner = ic.inner
        isrc = inner.src if inner is not None else pkt.dst
        if group == "port" and inner is not None:
            if inner.proto == 17 and is_traceroute_port(inner.dport):
                self.excluded["traceroute"] += 1
                return
            if inner.sport in LATE_REPLY_PORTS and (inner.dport or 0) >= 1024:
                self.excluded["late_reply"] += 1  # an answer arrived after the client closed the socket
                return
        key = (group, isrc)
        u = self.unreach.get(key)
        if u is None:
            u = self.unreach[key] = _Unreach(v6)
        u.count += 1
        u.ev.add(pkt)
        u.codes[ic.code] += 1
        if len(u.reporters) < 64 or pkt.src in u.reporters:
            u.reporters[pkt.src] += 1
        if inner is not None:
            pr = _PROTO.get(inner.proto, f"protocol {inner.proto}")
            tgt = f"{inner.dst} {pr} port {inner.dport}" if inner.dport is not None else f"{inner.dst} ({pr})"
            if len(u.targets) < 256 or tgt in u.targets:
                u.targets[tgt] += 1
            if inner.dst and (len(u.hosts) < 256 or inner.dst in u.hosts):
                u.hosts[inner.dst] += 1
            if inner.dport is not None and len(u.dports) < 256:
                u.dports.add((inner.dst, inner.dport))
            if (inner.src, inner.dst, inner.proto, inner.dport) in self.flows:
                u.matched += 1

    # -- time exceeded --------------------------------------------------- #
    def _time_exceeded(self, pkt: Packet, ic) -> None:
        if ic.code != 0:
            return  # code 1 = fragment reassembly timeout (fragment loss), not a loop
        inner = ic.inner
        key = (inner.src, inner.dst, inner.proto) if inner is not None else (pkt.dst, None, None)
        te = self.te.get(key)
        if te is None:
            te = self.te[key] = _TE(key[1], key[2])
        te.count += 1
        te.ev.add(pkt)
        if len(te.reporters) < 64 or pkt.src in te.reporters:
            te.reporters[pkt.src] += 1
        if inner is not None and inner.proto == 17 and is_traceroute_port(inner.dport):
            te.udp_trace += 1

    # -- redirect -------------------------------------------------------- #
    def _redirect(self, pkt: Packet, ic, t: float) -> None:
        r = self.redirects.get(pkt.src)
        if r is None:
            if len(self.redirects) >= 1024:
                return
            r = self.redirects[pkt.src] = _Redirect(bool(ic.v6))
        r.count += 1
        r.ev.add(pkt)
        r.first = t if r.first is None else min(r.first, t)
        r.last = t if r.last is None else max(r.last, t)
        if len(r.targets) < 256:
            r.targets.add(pkt.dst)
        if ic.gateway:
            r.gateways[ic.gateway] += 1
        if ic.inner is not None and ic.inner.dst and len(r.dests) < 64:
            r.dests.add(ic.inner.dst)
        if pkt.ttl is not None:
            r.hop_limits[pkt.ttl] += 1
        if pkt.eth_src:
            r.macs[pkt.eth_src] += 1

    # ------------------------------------------------------------------ #
    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        sc = ctx.config.scale
        out: list[Finding] = []
        out.extend(self._unreach_findings(ctx, max(2, round(UNREACH_THRESHOLD * sc))))
        out.extend(self._loop_findings(ctx, max(2, round(TE_THRESHOLD * sc))))
        out.extend(self._redirect_findings(ctx, max(2, round(REDIRECT_THRESHOLD * sc))))
        return out

    # -- unreachable findings -------------------------------------------- #
    def _unreach_findings(self, ctx: AnalysisContext, thr: int) -> list[Finding]:
        scanners = scanner_sources(ctx)
        groups: dict[str, list[_Unreach]] = {}
        srcs: dict[str, list[str]] = {}
        for (group, isrc), u in self.unreach.items():
            if isrc in scanners:
                self.excluded["scan"] += u.count
                continue
            if group == "port" and len({d for d, _ in u.dports}) <= 2 and len(u.dports) >= 10:
                self.excluded["scan_like"] += u.count  # one prober, many closed ports: a UDP scan
                continue
            if group == "host" and len(u.hosts) >= 20 and len({_prefix(h) for h in u.hosts}) <= 2:
                self.excluded["sweep_like"] += u.count  # one source walking through a subnet
                continue
            groups.setdefault(group, []).append(u)
            srcs.setdefault(group, []).append(isrc)
        out = []
        gw_ips = ctx.hosts.gateway()[0]
        for group, us in groups.items():
            n = sum(u.count for u in us)
            if n < thr:
                continue
            out.append(self._unreach_finding(group, us, srcs[group], n, gw_ips, ctx))
        return out

    def _unreach_finding(self, group: str, us: list[_Unreach], sources: list[str], n: int, gw_ips: set,
                         ctx: AnalysisContext) -> Finding:
        codes: Counter = Counter()
        reporters: Counter = Counter()
        targets: Counter = Counter()
        hosts: Counter = Counter()
        matched = 0
        ev = Evidence()
        for u in sorted(us, key=lambda x: -x.count):
            codes.update(u.codes)
            reporters.update(u.reporters)
            targets.update(u.targets)
            hosts.update(u.hosts)
            matched += u.matched
            ev.merge(u.ev)
        v6 = us[0].v6
        top_code = codes.most_common(1)[0][0]
        code_names = [f"{_code_name(v6, c)} ({k})" for c, k in codes.most_common(4)]
        rep = [r for r, _ in reporters.most_common(5)]
        tg = [t for t, _ in targets.most_common(10)]
        tgt_hosts = [h for h, _ in hosts.most_common(10)]
        main_t = tg[0] if tg else "the destination"
        main_r = rep[0] if rep else "a router"
        n_src = len(set(sources))
        n_tg = len(targets)
        rep_is_gw = any(r in gw_ips for r in rep)
        rep_is_target = bool(rep) and rep[0] in tgt_hosts[:3]
        sev = Severity.MEDIUM if (n >= 10 or n_tg >= 3 or n_src >= 3) else Severity.LOW
        ind: list[Indicator] = []
        clients = ", ".join(sorted(set(sources))[:3])
        if group == "route":
            ind.append(Indicator(f"Router {main_r} answered {plural(n, 'time')} that it has no route to {main_t}",
                                 Category.FAULT, 2.0))
            if rep_is_gw and tgt_hosts and all(is_private(h) for h in tgt_hosts[:3]):
                ind.append(Indicator("The local gateway has no route to an internal network: a route is probably "
                                     "missing from its configuration", Category.MISCONFIG, 1.0))
            title = f"No route: the network cannot find a path to {main_t}"
            expl = (f"Routers are the signposts of a network. {main_r} replied that it does not know any road to "
                    f"{main_t}, so the traffic from {clients} was dropped. This usually means an internet/WAN link is "
                    "down, a route is missing, or the device uses the wrong default gateway.")
            cause = "A missing or withdrawn route (WAN/VPN link down, or a static route not configured)."
            fix = ["Check the internet/VPN link status on the router reporting it (" + main_r + ").",
                   "Look at its routing table (`ip route`, `route print`, `show ip route`) for the destination network.",
                   "Make sure the client's default gateway is correct (`ipconfig` / `ip route`).",
                   "Run `traceroute " + (tgt_hosts[0] if tgt_hosts else "<destination>") + "` to see where the path stops."]
            cat = Category.FAULT
        elif group == "host":
            ind.append(Indicator(f"{main_r} reported {plural(n, 'time')} that host {tgt_hosts[0] if tgt_hosts else main_t} cannot be "
                                 "reached (no reply on its local network)", Category.FAULT, 2.0))
            title = f"Host down: {tgt_hosts[0] if tgt_hosts else main_t} is not reachable"
            expl = (f"The router next to {tgt_hosts[0] if tgt_hosts else 'the destination'} tried to deliver the "
                    f"traffic but nobody answered at that address. The device is probably switched off, unplugged, "
                    "asleep, or has changed its IP address.")
            cause = "The destination device is offline or no longer uses that IP address."
            fix = ["Check that the device is powered on and connected (link light, Wi-Fi).",
                   "Ping it from the same subnet; check `arp -a` for its MAC address.",
                   "If its address changed (DHCP), update the clients / DNS record that point to the old IP.",
                   "Check the router's ARP table for the address."]
            cat = Category.FAULT
        elif group == "port":
            proto_word = "UDP" if any(" UDP " in t for t in tg) else "protocol"
            ind.append(Indicator(f"{plural(n, 'reply', 'ies')} said nothing is listening on {main_t}" +
                                 (": the computer itself answered, so it is up but the service is not running"
                                  if rep_is_target else ""), Category.FAULT, 2.0))
            if n_src == 1 and n_tg <= 2:
                ind.append(Indicator(f"Only {clients} keeps sending to {main_t}: it may be configured with the "
                                     "wrong server or port", Category.MISCONFIG, 1.0))
            ind.append(Indicator("Few ports and few senders are involved, unlike a scan that tries many ports",
                                 Category.FAULT, 0.5))
            title = f"Service not running: nothing answers on {main_t}"
            expl = (f"{clients} sent {proto_word} traffic to {main_t}, and the destination replied 'port "
                    "unreachable', meaning the computer is on but no program is listening on that port. The service "
                    "has crashed or was stopped, or the client points to the wrong port.")
            cause = "The service on the destination is stopped or crashed, or the client uses the wrong port."
            fix = [f"On {tgt_hosts[0] if tgt_hosts else 'the server'}, check the service is running and listening "
                   "(`ss -ulnp` / `netstat -an`).",
                   "Restart the service and look at its logs for why it stopped.",
                   "Verify the port configured on the client matches the server.",
                   "If the service was moved, update the clients' configuration / DNS."]
            cat = Category.FAULT
        elif group == "admin":
            ind.append(Indicator(f"{main_r} actively rejected {plural(n, 'packet')} to {main_t} with 'administratively "
                                 "prohibited': a firewall rule or access list is blocking it", Category.MISCONFIG, 2.5))
            ind.append(Indicator("A firewall that rejects (rather than silently dropping) is working as configured; "
                                 "the question is whether the rule is intended", Category.FAULT, 0.5))
            title = f"Blocked by a firewall: traffic to {main_t} is rejected"
            expl = (f"A firewall or router ({main_r}) has a rule that forbids this traffic and told the sender so "
                    f"('administratively prohibited'). Either the rule is wrong, or {clients} is trying to reach "
                    "something it is not supposed to.")
            cause = "A firewall / ACL rule on " + main_r + " blocks this traffic."
            fix = [f"Check the firewall/ACL rules on {main_r} for {main_t}.",
                   "If the traffic is legitimate, add an allow rule for exactly this source, destination and port.",
                   "If it is not, find out why " + clients + " is trying (unwanted software?).",
                   "Re-test after the change."]
            cat = Category.MISCONFIG
        else:
            ind.append(Indicator(f"{plural(n, 'message')} '{_code_name(v6, top_code)}' from {main_r}", Category.FAULT, 1.5))
            title = f"Delivery errors: '{_code_name(v6, top_code)}' for {main_t}"
            expl = (f"{main_r} could not deliver traffic to {main_t} and explained why with an ICMP error "
                    f"('{_code_name(v6, top_code)}'). This points to a routing or policy problem along the path.")
            cause = "A routing or policy problem on " + main_r + "."
            fix = ["Check the router " + main_r + " configuration and logs.", "Run a traceroute to the destination.",
                   "Compare with a working client to find what differs."]
            cat = Category.FAULT
        unmatched = n - matched
        if n >= 5 and unmatched / n >= 0.8 and all(self.sent.get(s, 0) >= 10 for s in set(sources)):
            ind.append(Indicator(f"{fmt_pct(unmatched / n)} of the errors refer to packets that were never seen leaving "
                                 "the sender, so some of these messages may be forged", Category.ATTACK, 0.5))
        summary = f"{plural(n, 'ICMP error')} ({', '.join(code_names[:2])}) for {main_t}, reported by {main_r}."
        technical = (
            f"ICMP{'v6' if v6 else ''} destination unreachable, group '{group}': {n} messages; codes "
            f"{', '.join(code_names)}; reporters {', '.join(f'{r} ({c})' for r, c in reporters.most_common(5))}; "
            f"original destinations {', '.join(f'{t} ({c})' for t, c in targets.most_common(6))}; {n_src} affected "
            f"sender(s); {matched}/{n} quoted datagrams match flows seen in the capture. Excluded elsewhere: "
            + ", ".join(f"{k}={v}" for k, v in sorted(self.excluded.items())) + "."
        )
        variants = {cat: Variant(title, summary, expl, cause, fix, severity=sev,
                                 analogy="Like a letter coming back stamped 'return to sender: " +
                                         {"route": "no such road", "host": "nobody lives here",
                                          "port": "no one at this desk", "admin": "delivery refused"}.get(group, "undeliverable") + "'.")}
        if group == "port" and any(i.supports is Category.MISCONFIG for i in ind):
            variants[Category.MISCONFIG] = Variant(
                f"Wrong destination configured: {clients} keeps sending to closed {main_t}",
                summary, f"{clients} is configured to send to {main_t}, where nothing listens. The setting is "
                         "probably out of date (server moved or port changed).",
                "An outdated server/port setting on the client.",
                [f"Check the server/port configured on {clients} (e.g. syslog, SNMP, DNS or app settings).",
                 "Update it to the current server.", "Confirm the errors stop."], severity=Severity.LOW)
        if group == "admin":
            variants[Category.FAULT] = Variant(title, summary, expl, cause, fix, severity=Severity.LOW)
        f = Finding(kind="icmp.unreachable", category=cat, severity=sev, title=title, summary=summary,
                    explanation=expl, cause=cause, fix=fix, technical=technical,
                    analogy=variants[cat].analogy,
                    hosts=sorted(set(sources))[:5] + rep[:3] + [h for h in tgt_hosts[:3] if h not in rep],
                    metrics={"group": group, "messages": n, "codes": code_names, "reporters": rep, "targets": tg,
                             "affected_sources": sorted(set(sources))[:10], "matched_flows": matched,
                             "excluded": dict(self.excluded)},
                    indicators=ind, variants=variants)
        return ev.apply(f)

    # -- routing loop findings ------------------------------------------- #
    def _is_traceroute(self, key: tuple, te: _TE) -> bool:
        isrc, idst, proto = key
        reps = te.reporters
        if te.udp_trace >= max(1, te.count // 2) or _popcount(self.low_ttl.get((isrc, idst), 0)) >= 3:
            # a traceroute, unless it ran into a loop: then the same two routers answer at many hops
            top2 = sum(c for _, c in reps.most_common(2))
            return not (max(reps.values(), default=0) >= 10 and top2 >= 0.5 * te.count)
        if len(reps) >= 3 and max(reps.values()) <= 4:
            return True  # each hop answered a few times: the classic traceroute picture
        return False

    def _loop_findings(self, ctx: AnalysisContext, thr: int) -> list[Finding]:
        by_prefix: dict[str, dict] = {}
        trace_msgs = 0
        trace_pairs = set()
        for key, te in self.te.items():
            if self._is_traceroute(key, te):
                trace_msgs += te.count
                trace_pairs.add((key[0], key[1]))
                continue
            p = _prefix(te.dst)
            g = by_prefix.setdefault(p, {"count": 0, "reporters": Counter(), "ev": Evidence(), "srcs": set(), "dsts": set()})
            g["count"] += te.count
            g["reporters"].update(te.reporters)
            g["ev"].merge(te.ev)
            g["srcs"].add(key[0])
            if te.dst:
                g["dsts"].add(te.dst)
        out = []
        for p in set(by_prefix) | set(self.loops):
            g = by_prefix.get(p)
            lp = self.loops.get(p)
            te_n = g["count"] if g else 0
            reps: Counter = g["reporters"] if g else Counter()
            dominant = sum(c for _, c in reps.most_common(2)) / te_n if te_n else 0.0
            te_ok = te_n >= thr and dominant >= 0.7
            loop_ok = lp is not None and lp.max_copies >= 4 and (lp.packets >= 2 or lp.max_copies >= 6)
            if not te_ok and not loop_ok:
                continue
            out.append(self._loop_finding(p, g, lp, te_n, reps, dominant, te_ok, loop_ok, trace_msgs, ctx))
        return out

    def _loop_finding(self, prefix, g, lp, te_n, reps, dominant, te_ok, loop_ok, trace_msgs, ctx) -> Finding:
        routers = [r for r, _ in reps.most_common(4)]
        macs = [m for m, _ in lp.macs.most_common(4)] if lp else []
        srcs = sorted((g["srcs"] if g else set()) | (lp.srcs if lp else set()))
        ind: list[Indicator] = []
        if te_ok:
            ind.append(Indicator(f"Router(s) {', '.join(routers[:2])} reported 'time exceeded' {plural(te_n, 'time')} for "
                                 f"traffic to {prefix}: packets used up all their hops before arriving",
                                 Category.FAULT, 2.0))
            if dominant >= 0.9 and len(reps) <= 2:
                ind.append(Indicator("It is always the same one or two routers, which is what happens when packets "
                                     "bounce back and forth between them", Category.FAULT, 1.0))
        if loop_ok:
            step = lp.steps.most_common(1)[0][0] if lp.steps else 1
            ind.append(Indicator(f"{plural(lp.packets, 'packet')} passed this capture point up to {lp.max_copies} times "
                                 f"each, the TTL dropping by {step} on every lap: the packet is literally going in "
                                 "circles", Category.FAULT, 3.0))
            if len(macs) >= 2:
                ind.append(Indicator(f"The copies alternate between the devices {macs[0]} and {macs[1]}",
                                     Category.FAULT, 0.5))
        low = []
        for s in srcs[:10]:
            bm = self.src_ttl.get(s, 0)
            if bm and _popcount(bm) == 1 and bm.bit_length() - 1 <= 10:
                low.append((s, bm.bit_length() - 1))
        if low:
            ind.append(Indicator(f"{low[0][0]} sends its packets with a TTL of only {low[0][1]}, so they expire "
                                 "after a few hops even without a loop", Category.MISCONFIG, 2.0))
        else:
            ind.append(Indicator("Loops like this usually come from two static routes pointing at each other or a "
                                 "default route sent back the way it came", Category.MISCONFIG, 0.5))
        if trace_msgs:
            ind.append(Indicator(f"{plural(trace_msgs, 'other time-exceeded message')} belonged to traceroute runs and "
                                 "were ignored", Category.FAULT, 0.0))
        n = te_n + (lp.packets if lp else 0)
        sev = Severity.HIGH if (loop_ok or te_n >= 20) else Severity.MEDIUM
        who = " and ".join(routers[:2]) if routers else (" and ".join(macs[:2]) if macs else "two routers")
        title = f"Routing loop: traffic to {prefix} is going round in circles"
        summary = (f"Packets to {prefix} never arrive: " + (f"{plural(te_n, 'time-exceeded error')} from {who}"
                   if te_ok else f"the same packets passed up to {lp.max_copies} times with falling TTL") + ".")
        expl = ("Every packet carries a 'TTL' counter that each router lowers by one, so a lost packet cannot "
                f"wander forever. Here the routers ({who}) keep handing the traffic for {prefix} to each other, "
                "like two people each pointing to the other for directions, until the counter hits zero and the "
                "packet is thrown away. Nothing sent to that network gets through.")
        cause = (f"Inconsistent routing between {who}: typically two static routes pointing at each other, or a "
                 "default route that sends the traffic back where it came from.")
        fix = [f"Run `traceroute {next(iter(g['dsts'])) if g and g['dsts'] else prefix.split('/')[0]}`: the same "
               "two router addresses will repeat.",
               f"Compare the routing tables of {who} (`show ip route`, `ip route`) for {prefix}.",
               "Remove or correct the route that points back to the previous router; make sure exactly one router "
               "owns the path to that network.",
               "If a dynamic routing protocol is used, check for redistribution loops and wait for it to converge.",
               "Re-test with ping/traceroute."]
        technical = (
            f"Destination {prefix}: {te_n} ICMP time-exceeded (code 0) messages, reporters "
            f"{', '.join(f'{r} ({c})' for r, c in reps.most_common(4)) or 'none'} (top-2 share {fmt_pct(dominant)}); "
            + (f"looping copies: {lp.packets} packets, max {lp.max_copies} sightings, TTL steps "
               f"{dict(lp.steps)}, MACs {', '.join(macs) or 'n/a'}; " if lp else "")
            + f"senders {', '.join(srcs[:5])}; traceroute messages excluded: {trace_msgs}."
        )
        variants = {Category.FAULT: Variant(title, summary, expl, cause, fix, severity=sev,
                                            analogy="Like two people each pointing at the other when you ask for "
                                                    "directions, so you walk back and forth forever.")}
        if low:
            variants[Category.MISCONFIG] = Variant(
                f"TTL set too low on {low[0][0]}", f"{low[0][0]} sends packets with TTL {low[0][1]}, so they expire en route.",
                f"{low[0][0]} gives its packets a very small hop budget ({low[0][1]}), so they die after a few routers "
                "and the routers report 'time exceeded'. Normal systems use 64 or 128.",
                "A wrong TTL / hop-limit setting on the sender (sysctl, registry or application option).",
                ["Check `sysctl net.ipv4.ip_default_ttl` (Linux) or DefaultTTL in the Windows registry.",
                 "Set it back to 64 (or 128 on Windows).", "Check applications that set their own TTL."],
                severity=Severity.MEDIUM)
        ev = Evidence()
        if lp:
            ev.merge(lp.ev)
        if g:
            ev.merge(g["ev"])
        f = Finding(kind="icmp.routing_loop", category=Category.FAULT, severity=sev, title=title, summary=summary,
                    explanation=expl, cause=cause, fix=fix, technical=technical,
                    analogy=variants[Category.FAULT].analogy, hosts=routers[:4] + srcs[:4],
                    metrics={"destination_prefix": prefix, "time_exceeded": te_n, "routers": routers,
                             "dominant_share": round(dominant, 3), "looping_packets": lp.packets if lp else 0,
                             "max_copies": lp.max_copies if lp else 0, "loop_macs": macs, "senders": srcs[:10],
                             "traceroute_messages_ignored": trace_msgs},
                    indicators=ind, variants=variants)
        return ev.apply(f)

    # -- redirect findings ----------------------------------------------- #
    def _redirect_findings(self, ctx: AnalysisContext, thr: int) -> list[Finding]:
        out = []
        if not self.redirects:
            return out
        gw_ips, gw_macs = ctx.hosts.gateway()
        for rep, r in self.redirects.items():
            f = self._redirect_finding(rep, r, gw_ips, gw_macs, thr, ctx)
            if f is not None:
                out.append(f)
        return out

    def _is_router(self, ip: str, gw_ips: set, gw_macs: set, ctx: AnalysisContext) -> bool:
        if ip in gw_ips:
            return True
        h = ctx.hosts.hosts.get(ip)
        if h is None:
            return False
        if "gateway" in h.roles:
            return True
        for mac in h.macs:
            if mac in gw_macs:
                return True
            if sum(1 for x in ctx.hosts.mac_ips.get(mac, ()) if not is_private(x)) >= 3:
                return True  # this MAC forwards traffic for many internet addresses
        return False

    def _redirect_finding(self, rep: str, r: _Redirect, gw_ips: set, gw_macs: set, thr: int,
                          ctx: AnalysisContext) -> Finding | None:
        gws = [g for g, _ in r.gateways.most_common(5)]
        new_gw = gws[0] if gws else None
        targets = sorted(r.targets)
        ind: list[Indicator] = []
        rep_macs = set(r.macs)
        rep_is_gw = rep in gw_ips or bool(rep_macs & gw_macs)
        if rep in gw_ips and gw_macs and rep_macs and not rep_macs & gw_macs:
            rep_is_gw = False
            ind.append(Indicator(f"The redirect claims to come from the gateway {rep} but was sent from a different "
                                 f"device (MAC {sorted(rep_macs)[0]}, the router is {sorted(gw_macs)[0]}): forged",
                                 Category.ATTACK, 2.5))
        elif rep_is_gw:
            ind.append(Indicator(f"The redirect comes from {rep}, this network's gateway, which is the only device "
                                 "that should send redirects", Category.MISCONFIG, 2.0))
        elif gw_ips:
            ind.append(Indicator(f"The redirect comes from {rep}, which is NOT this network's gateway "
                                 f"({', '.join(sorted(gw_ips)[:2])})", Category.ATTACK, 2.0))
        else:
            ind.append(Indicator(f"The gateway of this network could not be identified, so {rep} could not be "
                                 "verified as the router", Category.ATTACK, 0.5))
        if not is_private(rep) and targets and is_private(targets[0]):
            ind.append(Indicator(f"{rep} is an internet address; real redirects only come from the local router",
                                 Category.ATTACK, 2.0))
        if r.v6 and r.hop_limits and any(h != 255 for h in r.hop_limits):
            ind.append(Indicator("The IPv6 redirect arrived with a hop limit below 255, so it came from outside the "
                                 "local link: forged", Category.ATTACK, 2.5))
        if new_gw:
            if new_gw == rep:
                ind.append(Indicator(f"It tells hosts to send their traffic to the sender itself ({rep})",
                                     Category.ATTACK, 2.0 if not rep_is_gw else 1.0))
            gh = ctx.hosts.hosts.get(new_gw)
            if gh is not None and rep_macs & set(gh.macs) and new_gw != rep:
                ind.append(Indicator(f"The 'better router' {new_gw} has the same MAC address as the sender: one "
                                     "machine is inviting traffic to itself", Category.ATTACK, 2.0))
            if self._is_router(new_gw, gw_ips, gw_macs, ctx):
                ind.append(Indicator(f"The suggested router {new_gw} really forwards traffic (it behaves like a router)",
                                     Category.MISCONFIG, 1.5))
            elif new_gw != rep:
                ind.append(Indicator(f"The suggested router {new_gw} never forwarded any traffic in this capture",
                                     Category.ATTACK, 1.0))
            if targets and not r.v6 and not all(_same24(new_gw, t) for t in targets[:5]):
                ind.append(Indicator(f"{new_gw} is not on the same subnet as the redirected hosts, which a valid "
                                     "redirect requires", Category.ATTACK, 1.0))
            if targets and all(_same24(new_gw, t) for t in targets[:5]) and rep_is_gw:
                ind.append(Indicator("The redirected hosts and the new router share one subnet: classic sign of two "
                                     "routers on one LAN", Category.MISCONFIG, 1.0))
        dur = max(0.001, (r.last or 0) - (r.first or 0))
        if len(targets) >= 5:
            ind.append(Indicator(f"Redirects were sent to {len(targets)} different hosts", Category.ATTACK, 1.5 if not rep_is_gw else 0.5))
        if r.count >= 20 and r.count / dur >= 5:
            ind.append(Indicator(f"{r.count} redirects at {r.count / dur:.0f}/s, far more than a router normally sends",
                                 Category.ATTACK, 1.0))
        att = sum(i.weight for i in ind if i.supports is Category.ATTACK)
        mis = sum(i.weight for i in ind if i.supports is Category.MISCONFIG)
        attackish = any(i.supports is Category.ATTACK and i.weight >= 2 for i in ind)
        if not attackish and r.count < thr:
            return None
        cat = Category.ATTACK if att > mis else Category.MISCONFIG
        sev_a = Severity.HIGH
        sev_m = Severity.MEDIUM if r.count >= 10 or len(targets) >= 5 else Severity.LOW
        gw_txt = new_gw or "another address"
        tg_txt = targets[0] if len(targets) == 1 else plural(len(targets), "host")
        title_a = f"Traffic hijack attempt: {rep} is sending fake 'use another route' messages"
        sum_a = f"{plural(r.count, 'ICMP redirect')} from {rep} told {tg_txt} to send traffic via {gw_txt}."
        expl_a = ("An ICMP redirect is a message by which the router says 'next time, use that other router, it's "
                  f"quicker'. {rep} is abusing it to make computers send their traffic through {gw_txt}, where it can be "
                  "read or changed (a man-in-the-middle).")
        cause_a = f"A host at {rep} forging ICMP redirects (e.g. with a MITM tool) to intercept traffic."
        fix_a = [f"Identify the device behind {rep} / MAC {', '.join(sorted(rep_macs)[:2]) or 'unknown'} (`arp -a`, "
                 "switch MAC table) and disconnect it.",
                 "Make hosts ignore redirects: Linux `sysctl -w net.ipv4.conf.all.accept_redirects=0` (and "
                 "`net.ipv6.conf.all.accept_redirects=0`); Windows `netsh int ip set global icmpredirects=disabled`.",
                 "Flush the redirected routes on affected hosts (`ip route flush cache`, or reboot).",
                 "Block ICMP type 5 from anything but the real router at the switch/firewall.",
                 "Change passwords used by the affected hosts during the incident."]
        title_m = f"Router redirects: {rep} keeps telling hosts to use {gw_txt} instead"
        sum_m = f"{plural(r.count, 'ICMP redirect')} from router {rep} point {tg_txt} to {gw_txt}."
        expl_m = (f"The router {rep} is forwarding traffic to another router ({gw_txt}) on the same network and tells "
                  "each computer to go there directly next time. It works, but it means the hosts' default gateway "
                  "is not the best exit for these destinations: typically two routers on one subnet.")
        cause_m = "Two routers on one subnet, with hosts using the 'wrong' one as their default gateway."
        fix_m = [f"Decide which router should be the default gateway and set it in DHCP (router option) or on the hosts.",
                 f"Or add the missing route on {rep} / the hosts so traffic goes to {gw_txt} directly.",
                 "Disable sending redirects on the router once routing is fixed (`no ip redirects`).",
                 "Check the hosts' routing tables (`route print` / `ip route`)."]
        mitre = "T1557 Adversary-in-the-Middle"
        technical = (f"{r.count} ICMP{'v6' if r.v6 else ''} redirects from {rep} (MAC {', '.join(sorted(rep_macs)[:3]) or 'n/a'}) "
                     f"to {len(targets)} hosts ({', '.join(targets[:5])}) for destinations "
                     f"{', '.join(sorted(r.dests)[:5]) or 'n/a'}; new gateways {', '.join(gws) or 'n/a'}; inferred gateway "
                     f"{', '.join(sorted(gw_ips)[:3]) or 'unknown'}; hop limits {dict(r.hop_limits.most_common(3))}; "
                     f"{dur:.2f} s. Attack score {att:.1f} vs misconfig {mis:.1f}.")
        variants = {Category.ATTACK: Variant(title_a, sum_a, expl_a, cause_a, fix_a, mitre=mitre, severity=sev_a,
                                             analogy="Like a stranger in a fake uniform waving cars onto a detour "
                                                     "that leads past his own garage."),
                    Category.MISCONFIG: Variant(title_m, sum_m, expl_m, cause_m, fix_m, severity=sev_m,
                                                analogy="Like a receptionist who keeps telling visitors 'next time, "
                                                        "use the side entrance'.")}
        v = variants[cat]
        f = Finding(kind="icmp.redirect", category=cat, severity=v.severity, title=v.title, summary=v.summary,
                    explanation=v.explanation, cause=v.cause, fix=v.fix, technical=technical, analogy=v.analogy,
                    mitre=mitre if cat is Category.ATTACK else None,
                    hosts=[rep] + ([new_gw] if new_gw and new_gw != rep else []) + targets[:8],
                    metrics={"reporter": rep, "redirects": r.count, "targets": targets[:10], "new_gateways": gws,
                             "destinations": sorted(r.dests)[:10], "gateway": sorted(gw_ips)[:3],
                             "reporter_is_gateway": rep_is_gw, "attack_score": round(att, 2),
                             "misconfig_score": round(mis, 2)},
                    indicators=ind, variants=variants)
        return r.ev.apply(f)
