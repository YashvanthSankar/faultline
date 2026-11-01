"""DHCP detectors: rogue server vs. second router, no server, NAK storms, starvation.

Kinds
-----
``dhcp.multiple_servers``  more than one server sends OFFER/ACK. ATTACK reading
                           "rogue DHCP server" vs. MISCONFIG "a second router is
                           handing out addresses"; indicators decide.
``dhcp.no_server``         clients keep DISCOVERing and nobody offers.
``dhcp.nak``               repeated DHCPNAKs.
``dhcp.starvation``        DISCOVER flood from many (forged) client MACs.
"""

from __future__ import annotations

import statistics
from collections import Counter, deque

from ..context import is_private
from .arp import clip, clock, evidence_of, fmt_frac, ip4_int, int_ip4, make_finding, valid_mac
from .base import (
    AnalysisContext,
    BoundedDict,
    Category,
    Detector,
    Finding,
    Indicator,
    Packet,
    Severity,
    Variant,
    plural,
    register,
)

PUBLIC_DNS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "208.67.222.222",
    "208.67.220.220", "94.140.14.14", "94.140.15.15", "76.76.2.0", "76.76.10.0", "64.6.64.6",
}

DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK = 1, 2, 3, 4, 5, 6


def _mask_bits(mask: str | None) -> int:
    n = ip4_int(mask) if mask else None
    if n is None or n == 0:
        return 24
    bits = bin(n).count("1")
    return bits if 8 <= bits <= 30 else 24


def _net(ip: str | None, bits: int) -> int | None:
    n = ip4_int(ip)
    if n is None or n == 0:
        return None
    m = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
    return n & m


class _Server:
    __slots__ = ("key", "ips", "macs", "offers", "acks", "naks", "first_ts", "last_ts", "routers", "dns", "masks",
                 "yiaddrs", "clients", "acked_clients", "lat", "wins", "contested", "frames", "selected", "leases")

    def __init__(self, key: str, ts: float) -> None:
        self.key = key
        self.ips: Counter = Counter()
        self.macs: Counter = Counter()
        self.offers = self.acks = self.naks = 0
        self.first_ts = self.last_ts = ts
        self.routers: Counter = Counter()
        self.dns: Counter = Counter()
        self.masks: Counter = Counter()
        self.yiaddrs: Counter = Counter()
        self.clients: set[str] = set()
        self.acked_clients: set[str] = set()
        self.lat: list[float] = []
        self.wins = 0
        self.contested = 0
        self.frames: list[int] = []
        self.selected = 0
        self.leases: Counter = Counter()

    # derived ---------------------------------------------------------------
    @property
    def bits(self) -> int:
        return _mask_bits(self.masks.most_common(1)[0][0]) if self.masks else 24

    @property
    def mac(self) -> str:
        return self.macs.most_common(1)[0][0] if self.macs else "?"

    @property
    def ip(self) -> str:
        return self.ips.most_common(1)[0][0] if self.ips else self.key

    def nets(self, bits: int) -> set[int]:
        out = set()
        for y in self.yiaddrs:
            n = _net(y, bits)
            if n is not None:
                out.add(n)
        if not out:
            n = _net(self.ip, bits)
            if n is not None:
                out.add(n)
        return out

    def subnet_str(self) -> str:
        b = self.bits
        nets = self.nets(b)
        return ", ".join(f"{int_ip4(n)}/{b}" for n in sorted(nets)[:3]) or "?"


class _Client:
    __slots__ = ("since", "first_since", "last", "frames", "total", "offered", "hostname", "naks", "acked_after_nak",
                 "eth_match")

    def __init__(self) -> None:
        self.since = 0
        self.first_since = self.last = 0.0
        self.frames: list[int] = []
        self.total = 0
        self.offered = False
        self.hostname = None
        self.naks = 0
        self.acked_after_nak = False
        self.eth_match = True


@register
class DhcpDetector(Detector):
    name = "dhcp"

    STARVE_WINDOW = 60.0
    STARVE_MIN = 30
    NO_SERVER_MIN = 3
    NO_SERVER_SPAN = 4.0
    NAK_MIN = 2

    def __init__(self) -> None:
        self.servers: BoundedDict = BoundedDict(256)
        self.xids: BoundedDict = BoundedDict(50_000)       # xid -> [ts, chaddr, winner, set(servers)]
        self.reqs: BoundedDict = BoundedDict(50_000)       # xid -> (requested_ip, server_id, chaddr)
        self.clients: BoundedDict = BoundedDict(50_000)    # chaddr -> _Client
        self.discovers = 0
        self.offers_total = 0
        self.naks: list[tuple] = []                       # (ts, no, server, chaddr, requested_ip, req_server)
        self.nak_total = 0
        # starvation
        self.first_seen: BoundedDict = BoundedDict(200_000)  # chaddr -> ts
        self.new_ts: deque = deque()
        self.peak = 0
        self.peak_first = self.peak_last = None
        self.starve_frames: list[int] = []
        self.starve_eth: Counter = Counter()
        self.starve_mismatch = 0
        self.starve_multicast = 0
        self.starve_hostname = 0
        self.starve_seen = 0
        # APIPA
        self.apipa_macs: set[str] = set()
        self.apipa_frames: list[int] = []
        # after >= 2 servers: frames sent to their MACs for public destinations (used as gateway)
        self.watch: dict[str, list] = {}

    # ------------------------------------------------------------------ #
    def on_packet(self, pkt: Packet, ctx: AnalysisContext) -> None:
        ts = pkt.ts if pkt.ts is not None else 0.0
        if pkt.arp is not None:
            a = pkt.arp
            for ip in (a.spa, a.tpa if a.spa == "0.0.0.0" else None):
                if ip and ip.startswith("169.254.") and a.sha:
                    self._apipa(a.sha, pkt.no)
                    break
            return
        if self.watch and pkt.eth_dst in self.watch and pkt.dst and not is_private(pkt.dst):
            w = self.watch[pkt.eth_dst]
            w[0] += 1
            if len(w[1]) < 10:
                w[1].append(pkt.no)
        d = pkt.dhcp
        if d is None:
            if pkt.src and pkt.src.startswith("169.254.") and pkt.eth_src:
                self._apipa(pkt.eth_src, pkt.no)
            return
        mt = d.msg_type
        chaddr = (d.chaddr or "").lower()
        if mt == DISCOVER:
            self._discover(pkt, d, chaddr, ts)
        elif mt in (OFFER, ACK, NAK):
            self._server_msg(pkt, d, chaddr, ts, mt)
        elif mt == REQUEST:
            if d.xid is not None:
                self.reqs[d.xid] = (d.requested_ip or (d.ciaddr if d.ciaddr != "0.0.0.0" else None), d.server_id, chaddr)
            if d.server_id:
                s = self.servers.get(d.server_id)
                if s is not None:
                    s.selected += 1
            self._starve_track(pkt, d, chaddr, ts)

    def _apipa(self, mac: str, no: int) -> None:
        if len(self.apipa_macs) < 64:
            self.apipa_macs.add(mac.lower())
        if len(self.apipa_frames) < 20:
            self.apipa_frames.append(no)

    def _discover(self, pkt: Packet, d, chaddr: str, ts: float) -> None:
        self.discovers += 1
        if d.xid is not None and d.xid not in self.xids:
            self.xids[d.xid] = [ts, chaddr, None, set()]
        if chaddr:
            c = self.clients.get(chaddr)
            if c is None:
                c = self.clients[chaddr] = _Client()
            if c.since == 0:
                c.first_since = ts
                c.frames = []
            c.since += 1
            c.total += 1
            c.last = max(c.last, ts)
            if len(c.frames) < 10:
                c.frames.append(pkt.no)
            if d.hostname:
                c.hostname = clip(d.hostname, 64)
            if pkt.eth_src and pkt.eth_src != chaddr:
                c.eth_match = False
        self._starve_track(pkt, d, chaddr, ts)

    def _starve_track(self, pkt: Packet, d, chaddr: str, ts: float) -> None:
        if not chaddr or chaddr in self.first_seen:
            return
        self.first_seen[chaddr] = ts
        self.new_ts.append(ts)
        while self.new_ts and ts - self.new_ts[0] > self.STARVE_WINDOW:
            self.new_ts.popleft()
        if len(self.new_ts) > self.peak:
            self.peak = len(self.new_ts)
            self.peak_first, self.peak_last = self.new_ts[0], ts
        self.starve_seen += 1
        if pkt.eth_src:
            if len(self.starve_eth) < 4096 or pkt.eth_src in self.starve_eth:
                self.starve_eth[pkt.eth_src] += 1
            if pkt.eth_src != chaddr:
                self.starve_mismatch += 1
        try:
            if int(chaddr[:2], 16) & 1:
                self.starve_multicast += 1
        except ValueError:
            pass
        if d.hostname:
            self.starve_hostname += 1
        if len(self.starve_frames) < 200:
            self.starve_frames.append(pkt.no)

    def _server_msg(self, pkt: Packet, d, chaddr: str, ts: float, mt: int) -> None:
        sid = d.server_id or pkt.src
        if not sid or sid == "0.0.0.0":
            return
        s = self.servers.get(sid)
        if s is None:
            s = _Server(sid, ts)
            self.servers[sid] = s
        s.last_ts = max(s.last_ts, ts)
        if pkt.src and pkt.src != "0.0.0.0" and (len(s.ips) < 4 or pkt.src in s.ips):
            s.ips[pkt.src] += 1
        if pkt.eth_src and (len(s.macs) < 4 or pkt.eth_src in s.macs):
            s.macs[pkt.eth_src] += 1
        if len(s.frames) < 60:
            s.frames.append(pkt.no)
        c = self.clients.get(chaddr) if chaddr else None
        if mt == NAK:
            s.naks += 1
            self.nak_total += 1
            req = self.reqs.get(d.xid) if d.xid is not None else None
            if len(self.naks) < 200:
                self.naks.append((ts, pkt.no, sid, chaddr, req[0] if req else None, req[1] if req else None))
            if c is None and chaddr:
                c = self.clients[chaddr] = _Client()
            if c is not None:
                c.naks += 1
                c.acked_after_nak = False
            return
        for r in (d.routers or [])[:4]:
            if len(s.routers) < 8 or r in s.routers:
                s.routers[r] += 1
        for r in (d.dns_servers or [])[:4]:
            if len(s.dns) < 8 or r in s.dns:
                s.dns[r] += 1
        if d.subnet_mask and (len(s.masks) < 4 or d.subnet_mask in s.masks):
            s.masks[d.subnet_mask] += 1
        if d.lease_time is not None and len(s.leases) < 8:
            s.leases[d.lease_time] += 1
        if d.yiaddr and d.yiaddr != "0.0.0.0" and (len(s.yiaddrs) < 64 or d.yiaddr in s.yiaddrs):
            s.yiaddrs[d.yiaddr] += 1
        if chaddr and len(s.clients) < 512:
            s.clients.add(chaddr)
        if mt == OFFER:
            s.offers += 1
            self.offers_total += 1
            x = self.xids.get(d.xid) if d.xid is not None else None
            if x is not None:
                lat = ts - x[0]
                if 0 <= lat < 30 and len(s.lat) < 500:
                    s.lat.append(lat)
                if x[2] is None:
                    x[2] = sid
                if len(x[3]) < 8:
                    x[3].add(sid)
        else:
            s.acks += 1
            if chaddr and len(s.acked_clients) < 512:
                s.acked_clients.add(chaddr)
        if c is not None:
            c.since = 0
            c.offered = True
            if mt == ACK and c.naks:
                c.acked_after_nak = True
        if len(self.servers) >= 2:
            for srv in self.servers.values():
                for m in srv.macs:
                    if m not in self.watch and len(self.watch) < 32:
                        self.watch[m] = [0, []]

    # ------------------------------------------------------------------ #
    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        out: list[Finding] = []
        scale = ctx.config.scale
        starve = self._find_starvation(ctx, scale)
        if starve:
            out.append(starve)
        out.extend(self._find_multiple(ctx))
        ns = self._find_no_server(ctx, starve is not None)
        if ns:
            out.append(ns)
        nak = self._find_naks(ctx)
        if nak:
            out.append(nak)
        return out

    # -- rogue / second server ------------------------------------------- #
    def _router_like_macs(self, ctx: AnalysisContext) -> set[str]:
        out = set()
        for mac, ips in ctx.hosts.mac_ips.items():
            if sum(1 for ip in ips if not is_private(ip)) >= 3:
                out.add(mac)
        return out

    def _find_multiple(self, ctx: AnalysisContext) -> list[Finding]:
        servers = [s for s in self.servers.values() if s.offers + s.acks >= 1]
        if len(servers) < 2:
            return []
        rl = self._router_like_macs(ctx)

        max_acks = max(x.acks for x in servers)
        min_first = min(x.first_ts for x in servers)
        max_clients = max(len(x.acked_clients) for x in servers)

        def legit_score(s: _Server):
            sc = 0.0
            if s.macs and any(m in rl for m in s.macs):
                sc += 3
            for r in s.routers:
                claims = ctx.hosts.arp_claims.get(r)
                if claims and claims.most_common(1)[0][0] in rl:
                    sc += 2
                    break
            if s.acks == max_acks:
                sc += 2
            if s.first_ts == min_first:
                sc += 1
            if len(s.acked_clients) == max_clients:
                sc += 1
            return (sc, s.acks + s.selected, -s.first_ts)

        servers.sort(key=legit_score, reverse=True)
        legit = servers[0]
        out = []
        for rogue in servers[1:4]:
            f = self._server_finding(ctx, legit, rogue, rl)
            if f is not None:
                out.append(f)
        return out

    def _server_finding(self, ctx: AnalysisContext, legit: _Server, rogue: _Server, rl: set[str]) -> Finding | None:
        if set(legit.macs) & set(rogue.macs) and set(legit.routers) == set(rogue.routers):
            return None  # one device (e.g. server + its relay path) with two identities
        bits = legit.bits
        same_subnet = bool(legit.nets(bits) & rogue.nets(bits))
        rr, rd = set(rogue.routers), set(rogue.dns)
        lr, ld = set(legit.routers), set(legit.dns)
        if same_subnet and rr == lr and rd == ld:
            return None  # redundant / failover pair handing out identical settings
        rogue_ips = set(rogue.ips) | {rogue.key}
        A, M = Category.ATTACK, Category.MISCONFIG
        ind: list[Indicator] = []
        router_self = bool(rr & rogue_ips)
        router_other_lan = sorted(r for r in rr - lr - rogue_ips if is_private(r))
        dns_self = bool(rd & rogue_ips)
        dns_lan = sorted(d for d in rd - ld - lr if is_private(d))
        dns_public = sorted(d for d in rd if d in PUBLIC_DNS or not is_private(d))
        rname = f"{rogue.ip} ({rogue.mac})"
        if same_subnet:
            ind.append(Indicator(f"{rname} hands out addresses in the same subnet as the real server "
                                 f"({rogue.subnet_str()}), so its leases look normal", A, 1.5))
            if router_self and not (lr & rogue_ips):
                ind.append(Indicator(f"It names itself ({', '.join(sorted(rr & rogue_ips))}) as the router instead of "
                                     f"{', '.join(sorted(lr)) or 'the real gateway'}", A, 2.5))
            elif router_other_lan:
                ind.append(Indicator(f"It names another local device ({router_other_lan[0]}) as the router instead of "
                                     f"{', '.join(sorted(lr)) or 'the real gateway'}", A, 2.0))
            if dns_self or dns_lan:
                bad = sorted((rd & rogue_ips) | set(dns_lan))
                ind.append(Indicator(f"It points clients' DNS at a local device ({', '.join(bad[:3])}) instead of "
                                     f"{', '.join(sorted(ld)) or 'the normal resolver'}", A, 2.0))
        else:
            ind.append(Indicator(f"{rname} offers a different subnet ({rogue.subnet_str()} vs "
                                 f"{legit.subnet_str()}), like a second home router plugged in by mistake", M, 2.0))
            if router_self:
                ind.append(Indicator("It names itself as the router, as a home router does for its own network", M, 1.0))
            if dns_self and router_self:
                ind.append(Indicator("It also acts as its own DNS server, normal for a consumer router", M, 0.5))
            elif dns_lan:
                ind.append(Indicator(f"It points DNS at another local device ({dns_lan[0]})", A, 1.0))
        if dns_public and not dns_self and not dns_lan:
            ind.append(Indicator(f"It hands out public DNS ({', '.join(dns_public[:2])}), typical of a factory-default router", M, 1.0))
        contested = [x for x in self.xids.values() if legit.key in x[3] and rogue.key in x[3]]
        rwins = sum(1 for x in contested if x[2] == rogue.key)
        r_lat = statistics.median(rogue.lat) if rogue.lat else None
        l_lat = statistics.median(legit.lat) if legit.lat else None
        if contested and rwins / len(contested) >= 0.5 and (r_lat is None or l_lat is None or r_lat < l_lat):
            ind.append(Indicator(f"It answered first in {rwins} of {len(contested)} races with the real server"
                                 + (f" ({r_lat * 1000:.0f} ms vs {l_lat * 1000:.0f} ms)" if r_lat is not None and l_lat is not None else ""),
                                 A, 1.5))
        if rogue.acks or rogue.selected:
            ind.append(Indicator(f"{plural(len(rogue.acked_clients) or rogue.selected, 'client')} accepted its leases", A, 0.5))
        used_dns = [ip for ip in rogue_ips | rd if ip in ctx.hosts.dns_servers and is_private(ip) and ip not in ld]
        if used_dns and same_subnet:
            ind.append(Indicator(f"Clients then used {used_dns[0]} as their DNS server", A, 1.5))
        gw_frames = sum(self.watch.get(m, [0])[0] for m in rogue.macs)
        if gw_frames >= 5 and not any(m in rl for m in legit.macs if m in rogue.macs):
            if same_subnet:
                ind.append(Indicator(f"{plural(gw_frames, 'packet')} for the internet were then sent to its MAC as if it "
                                     f"were the router", A, 1.5))
        if not ind:
            return None

        legit_desc = (f"{legit.ip} ({legit.mac}): subnet {legit.subnet_str()}, router {', '.join(sorted(lr)) or '-'}, "
                      f"DNS {', '.join(sorted(ld)) or '-'}, {legit.offers} offers / {legit.acks} ACKs")
        rogue_desc = (f"{rogue.ip} ({rogue.mac}): subnet {rogue.subnet_str()}, router {', '.join(sorted(rr)) or '-'}, "
                      f"DNS {', '.join(sorted(rd)) or '-'}, {rogue.offers} offers / {rogue.acks} ACKs")
        accepted = len(rogue.acked_clients)
        impact = (gw_frames >= 5 or used_dns) and accepted
        attack = Variant(
            title=f"Rogue DHCP server on the network ({rogue.ip})",
            summary=(f"An unauthorised DHCP server {rogue.ip} ({rogue.mac}) sent {plural(rogue.offers + rogue.acks, 'DHCP message')}"
                     f" telling devices to use router {', '.join(sorted(rr)) or '?'} and DNS {', '.join(sorted(rd)) or '?'}."),
            explanation=(
                "When a device joins a network it shouts 'can someone give me an address?' (DHCP) and trusts the first "
                f"answer. A second server, {rogue.ip}, is answering too, and it tells devices to send their traffic "
                "and name lookups through a device that is not your real router. That lets it watch or redirect "
                "everything those devices do, while the addresses it hands out look completely normal."),
            cause=f"A rogue DHCP server at {rogue.mac} (an attacker's laptop or a tool like yersinia, ettercap or bettercap).",
            fix=[
                f"Find the port: look up {rogue.mac} in the switch MAC address table (`show mac address-table address {rogue.mac}`) "
                "or the router's client list, and disconnect it.",
                "Enable DHCP snooping on the switch, trusting only the uplink to your real DHCP server.",
                "On affected devices, renew the lease (`ipconfig /release` then `ipconfig /renew`, or reconnect Wi-Fi) "
                f"and check with `ipconfig /all` that the gateway is {', '.join(sorted(lr)) or 'the real router'}.",
                "Treat traffic from affected devices as possibly intercepted: change important passwords.",
            ],
            analogy="Like a fake receptionist at the hotel entrance handing out room keys and directions that lead to their own office.",
            mitre="T1557.003 DHCP Spoofing",
            severity=Severity.CRITICAL if impact else Severity.HIGH,
        )
        misconf = Variant(
            title=f"A second router is handing out addresses ({rogue.ip})",
            summary=(f"Two DHCP servers answer on this network: {legit.ip} and {rogue.ip}, which offers "
                     f"{rogue.subnet_str()}; devices that take its addresses will not work properly."),
            explanation=(
                "A network should have exactly one DHCP server, the device that gives everyone an address. A second "
                f"one ({rogue.ip}) is answering as well, which usually means a home router or Wi-Fi extender was "
                "plugged in with its 'LAN' port. Devices that get their address from it end up on a different "
                "network and can't reach the internet or other devices."),
            cause=f"A second router or access point (MAC {rogue.mac}) with its own DHCP server enabled.",
            fix=[
                f"Find the device with MAC {rogue.mac} (switch MAC table or router client list).",
                "Disable DHCP on it and use it as an access point only, or plug the uplink into its WAN/Internet port.",
                "Renew the address on affected devices: `ipconfig /release` and `ipconfig /renew`, or reconnect Wi-Fi.",
                "Enable DHCP snooping on managed switches to stop this happening again.",
            ],
            analogy="Like two receptionists giving out room numbers from two different hotels.",
            severity=Severity.HIGH if accepted else Severity.MEDIUM,
        )
        frames = list(rogue.frames) + list(legit.frames[:20])
        ev = evidence_of(sorted(frames), total=rogue.offers + rogue.acks + legit.offers + legit.acks,
                         first_ts=min(rogue.first_ts, legit.first_ts), last_ts=max(rogue.last_ts, legit.last_ts))
        tech = (f"Legitimate server (most ACKs / gateway match / first seen): {legit_desc}. Other server: {rogue_desc}"
                f"; same subnet: {same_subnet}; contested transactions: {len(contested)}, other server won {rwins}"
                + (f"; median offer latency {r_lat * 1000:.1f} ms vs {l_lat * 1000:.1f} ms" if r_lat is not None and l_lat is not None else "")
                + (f"; {gw_frames} internet-bound frames sent to its MAC" if gw_frames else "") + ".")
        metrics = {
            "legit_server": legit.ip, "legit_mac": legit.mac, "legit_routers": sorted(lr)[:10], "legit_dns": sorted(ld)[:10],
            "legit_subnet": legit.subnet_str(), "other_server": rogue.ip, "other_mac": rogue.mac,
            "other_routers": sorted(rr)[:10], "other_dns": sorted(rd)[:10], "other_subnet": rogue.subnet_str(),
            "same_subnet": same_subnet, "other_offers": rogue.offers, "other_acks": rogue.acks,
            "other_clients": sorted(rogue.acked_clients)[:10], "races": len(contested), "other_wins": rwins,
            "other_median_latency_ms": round(r_lat * 1000, 2) if r_lat is not None else None,
            "legit_median_latency_ms": round(l_lat * 1000, 2) if l_lat is not None else None,
        }
        return make_finding("dhcp.multiple_servers", {A: attack, M: misconf}, ind, technical=tech,
                            hosts=[rogue.ip, legit.ip] + sorted(rr)[:2], metrics=metrics, evidence=ev,
                            default=A if same_subnet else M)

    # -- no server --------------------------------------------------------- #
    def _find_no_server(self, ctx: AnalysisContext, starving: bool) -> Finding | None:
        stuck = []
        for mac, c in self.clients.items():
            if c.since >= 2 and (c.eth_match or not starving):
                stuck.append((mac, c))
        if not stuck:
            return None
        n_disc = sum(c.since for _, c in stuck)
        first = min(c.first_since for _, c in stuck)
        last = max(c.last for _, c in stuck)
        if n_disc < self.NO_SERVER_MIN or last - first < self.NO_SERVER_SPAN:
            return None
        if not any(c.since >= 3 or c.last - c.first_since >= self.NO_SERVER_SPAN for _, c in stuck):
            return None
        macs = sorted(m for m, _ in stuck)
        apipa = sorted(self.apipa_macs & set(macs)) or sorted(self.apipa_macs)
        F, M, A = Category.FAULT, Category.MISCONFIG, Category.ATTACK
        ind = [Indicator(f"{plural(len(stuck), 'device')} sent {n_disc} DHCP requests over {last - first:.0f} s "
                         f"without getting any offer", F, 1.5)]
        if self.offers_total == 0:
            ind.append(Indicator("No DHCP server answered anyone during the whole capture", F, 2.0))
        else:
            ind.append(Indicator(f"A DHCP server did answer {plural(self.offers_total, 'time')} but not these devices "
                                 "(full address pool, MAC filtering or a VLAN/relay problem)", M, 1.5))
        if apipa:
            ind.append(Indicator(f"{plural(len(apipa), 'device')} gave up and used a 169.254.x.x emergency address", F, 1.5))
        if starving:
            ind.append(Indicator("A DHCP starvation flood was seen, which can exhaust the server's address pool", A, 1.5))
        names = sorted({c.hostname for _, c in stuck if c.hostname})[:3]
        who = ", ".join(names) if names else ", ".join(macs[:3])
        fault = Variant(
            title="No DHCP server is answering",
            summary=f"{plural(len(stuck), 'device')} asked for an address {n_disc} times over {last - first:.0f} s and nobody answered.",
            explanation=(
                "When a device connects, it asks the network's DHCP server for an address. Nobody is answering, so "
                "these devices can't get an IP address and can't use the network"
                + (" (some of them fell back to a useless 169.254.x.x address)" if apipa else "")
                + ". This is a fault on the network side, not on the devices."),
            cause="The DHCP server (usually the router) is down or its DHCP service stopped, a DHCP relay is broken, "
                  "or the switch port is in the wrong VLAN.",
            fix=[
                "Restart the router / DHCP server and check its DHCP service is enabled.",
                "If the server is on another subnet, check the DHCP relay (`ip helper-address`) on the router.",
                "Check the switch port VLAN of the affected device; try another port or the Wi-Fi.",
                "On the device, run `ipconfig /renew` (Windows) or `sudo dhclient -v` (Linux) and watch for an OFFER.",
                "As a stopgap, set a static IP, mask, gateway and DNS on the affected device.",
            ],
            analogy="Like arriving at a hotel where the reception desk is empty, so nobody can give you a room key.",
            severity=Severity.HIGH if (len(stuck) >= 2 or n_disc >= 10) else Severity.MEDIUM,
        )
        misconf = Variant(
            title="The DHCP server ignores some devices",
            summary=f"The DHCP server answered other devices but not {who} ({n_disc} requests).",
            explanation=("The DHCP server works, but it doesn't answer these devices. Typical reasons: its address "
                         "pool is full, MAC filtering is on, or these devices are on a different VLAN."),
            cause="Exhausted DHCP pool, MAC filtering, or a VLAN / relay configuration problem.",
            fix=["Check the DHCP server's lease table: is the pool full? Shorten lease time or enlarge the pool.",
                 "Check MAC filtering / access control lists on the router.",
                 "Check the VLAN of the affected switch ports and the DHCP relay."],
            analogy="Like a receptionist who has run out of room keys.",
            severity=Severity.MEDIUM,
        )
        frames = [no for _, c in stuck for no in c.frames] + self.apipa_frames
        ev = evidence_of(sorted(frames), total=n_disc + len(self.apipa_frames), first_ts=first, last_ts=last)
        tech = (f"{n_disc} DISCOVERs without OFFER from {len(stuck)} client(s) ({', '.join(macs[:6])}) between "
                f"{clock(first)} and {clock(last)}; total DISCOVERs {self.discovers}, OFFERs {self.offers_total}; "
                f"APIPA hosts: {', '.join(apipa[:5]) or 'none'}.")
        metrics = {"clients": macs[:10], "discovers": n_disc, "span_s": round(last - first, 2),
                   "offers_seen": self.offers_total, "apipa_macs": apipa[:10], "hostnames": names}
        variants = {F: fault, M: misconf}
        if starving:
            variants[A] = Variant(
                title="DHCP pool exhausted by a starvation attack",
                summary=f"After a DHCP starvation flood, {plural(len(stuck), 'device')} could not get an address.",
                explanation="An attacker grabbed all addresses with fake requests, so real devices get none.",
                cause="DHCP starvation attack (see the related finding).",
                fix=["Find and disconnect the flooding device.", "Enable DHCP snooping with rate limiting / port security."],
                analogy="Like someone booking every table in a restaurant under fake names.",
                mitre="T1557.003 DHCP Spoofing", severity=Severity.HIGH)
        return make_finding("dhcp.no_server", variants, ind, technical=tech, hosts=macs[:10], metrics=metrics,
                            evidence=ev, default=F)

    # -- NAK --------------------------------------------------------------- #
    def _find_naks(self, ctx: AnalysisContext) -> Finding | None:
        if self.nak_total < self.NAK_MIN:
            return None
        srv = Counter(n[2] for n in self.naks)
        clients = Counter(n[3] for n in self.naks if n[3])
        recovered = sum(1 for m in clients if (self.clients.get(m) and self.clients[m].acked_after_nak))
        M, A = Category.MISCONFIG, Category.ATTACK
        ind = [Indicator(f"{plural(self.nak_total, 'DHCPNAK')} sent to {plural(len(clients), 'device')}", M, 1.0)]
        foreign = []
        for ts, no, sid, ch, req_ip, req_srv in self.naks:
            s = self.servers.get(sid)
            if req_ip and s is not None and s.yiaddrs:
                if _net(req_ip, s.bits) not in s.nets(s.bits):
                    foreign.append(req_ip)
        if foreign:
            ind.append(Indicator(f"Devices asked to keep addresses from another network (e.g. {foreign[0]}): "
                                 "stale leases after moving networks", M, 1.5))
        fighting = []
        for ts, no, sid, ch, req_ip, req_srv in self.naks:
            for other in self.servers.values():
                if other.key != sid and ch in other.acked_clients:
                    fighting.append((sid, other.key))
                    break
        if fighting:
            ind.append(Indicator(f"Server {fighting[0][0]} rejects leases that server {fighting[0][1]} handed out: "
                                 "two DHCP servers are fighting", M, 2.0))
        nak_only = [k for k in srv if (s := self.servers.get(k)) is not None and s.acks == 0 and s.offers == 0]
        if nak_only and any(s.acks for s in self.servers.values() if s.key not in nak_only):
            ind.append(Indicator(f"{nak_only[0]} never hands out addresses, it only rejects other servers' leases "
                                 "(forcing devices to ask again)", A, 2.0))
        loops = [m for m, n in clients.items() if n >= 3]
        if loops:
            ind.append(Indicator(f"{plural(len(loops), 'device')} were rejected 3 or more times in a row", M, 1.0))
        if recovered == len(clients) and not fighting and not loops:
            ind.append(Indicator("Every rejected device got a new address right after: normal after moving networks", M, 1.0))
        sev = Severity.LOW if (recovered == len(clients) and self.nak_total <= 3 and not fighting) else Severity.MEDIUM
        misconf = Variant(
            title="The DHCP server is rejecting devices' addresses (DHCPNAK)",
            summary=f"The DHCP server refused {plural(self.nak_total, 'address request')} from {plural(len(clients), 'device')}.",
            explanation=(
                "A DHCPNAK is the server saying 'no, you can't keep that address'. It is normal once when a laptop "
                "comes from another network, but repeated rejections mean devices hold addresses for a different "
                "network or two DHCP servers disagree."),
            cause=("Two DHCP servers with different settings on the same network" if fighting else
                   "Devices requesting stale leases from another network (or a server whose scope changed)"),
            fix=["Make sure only one DHCP server is active on this network (check the router and any extra access points).",
                 "On the affected devices, release and renew: `ipconfig /release` then `ipconfig /renew`, or forget and rejoin Wi-Fi.",
                 "If the DHCP scope was recently changed, clear old leases / reservations on the server."],
            analogy="Like trying to use last year's hotel key card: the front desk keeps rejecting it.",
            severity=sev,
        )
        variants = {M: misconf}
        if nak_only:
            variants[A] = Variant(
                title=f"A device is sending forged DHCP rejections ({nak_only[0]})",
                summary=f"{nak_only[0]} only sends DHCPNAKs, kicking devices off their addresses.",
                explanation="A device that never hands out addresses keeps telling others their address is invalid, "
                            "which disconnects them and can push them to a rogue server.",
                cause="Forged DHCPNAK messages from a rogue device.",
                fix=["Find the sender in the switch MAC table and disconnect it.", "Enable DHCP snooping on the switch."],
                analogy="Like a stranger at the hotel cancelling guests' bookings.",
                mitre="T1557.003 DHCP Spoofing", severity=Severity.HIGH)
        ev = evidence_of([n[1] for n in self.naks], total=self.nak_total,
                         first_ts=min(n[0] for n in self.naks) if self.naks else None,
                         last_ts=max(n[0] for n in self.naks) if self.naks else None)
        tech = (f"{self.nak_total} NAKs from {', '.join(f'{k} ({v})' for k, v in srv.most_common(3))} to "
                f"{len(clients)} client(s); {recovered} recovered with an ACK"
                + (f"; requested foreign addresses {', '.join(sorted(set(foreign))[:3])}" if foreign else "") + ".")
        metrics = {"naks": self.nak_total, "servers": dict(srv.most_common(5)), "clients": [m for m, _ in clients.most_common(10)],
                   "recovered": recovered, "foreign_requests": sorted(set(foreign))[:10]}
        return make_finding("dhcp.nak", variants, ind, technical=tech, hosts=list(srv)[:5], metrics=metrics,
                            evidence=ev, default=M)

    # -- starvation ---------------------------------------------------------- #
    def _find_starvation(self, ctx: AnalysisContext, scale: float) -> Finding | None:
        thr = max(10, int(round(self.STARVE_MIN * scale)))
        if self.peak < thr:
            return None
        seen = max(1, self.starve_seen)
        mismatch = self.starve_mismatch / seen
        mcast = self.starve_multicast / seen
        nohost = 1 - self.starve_hostname / seen
        top_eth, top_n = self.starve_eth.most_common(1)[0] if self.starve_eth else ("?", 0)
        dur = max(0.001, (self.peak_last or 0) - (self.peak_first or 0))
        rate = self.peak / dur
        completed = sum(1 for s in self.servers.values() for _ in s.acked_clients)
        incomplete = 1 - min(1.0, completed / seen)
        signals = [mismatch >= 0.5, mcast >= 0.1, nohost >= 0.8 and incomplete >= 0.8, rate >= 5,
                   self.peak >= 100 * scale]
        if sum(signals) < 2:
            return None
        A, F = Category.ATTACK, Category.FAULT
        ind = [Indicator(f"{self.peak} different client MACs asked for an address within {dur:.0f} s", A, 2.0)]
        if mismatch >= 0.5:
            ind.append(Indicator(f"{fmt_frac(mismatch)} of the requests claim a client MAC different from the "
                                 f"sender's real MAC (mostly {top_eth})", A, 2.0))
        if mcast >= 0.1:
            ind.append(Indicator(f"{fmt_frac(mcast)} of the client MACs are impossible (multicast bit set): they are "
                                 "randomly generated", A, 2.0))
        if rate >= 5:
            ind.append(Indicator(f"Requests arrive at {rate:.0f} new devices per second", A, 1.0))
        if nohost >= 0.8:
            ind.append(Indicator("Almost none of the requests carry a device name", A, 0.5))
        if self.starve_hostname / seen >= 0.8 and mismatch < 0.2:
            ind.append(Indicator("Most requests carry normal device names, like many real devices booting at once", F, 1.5))
        attack = Variant(
            title="DHCP starvation attack (address pool being exhausted)",
            summary=f"{self.peak} fake devices requested IP addresses within {dur:.0f} seconds.",
            explanation=(
                "A DHCP server has a limited pool of addresses. Here one device pretends to be hundreds of different "
                "devices and asks for an address for each, until the pool runs out and real devices can't join. "
                "Attackers often do this right before starting their own (rogue) DHCP server."),
            cause=f"A starvation tool (yersinia, dhcpstarv, DHCPig) on the device sending from {top_eth}.",
            fix=[f"Find {top_eth} in the switch MAC address table and disconnect that port.",
                 "Enable DHCP snooping with a rate limit and port security (limit MACs per port).",
                 "Clear the bogus leases on the DHCP server, or restart it once the attacker is gone.",
                 "Check for a rogue DHCP server appearing at the same time."],
            analogy="Like someone booking every table in a restaurant under fake names so real guests are turned away.",
            mitre="T1557.003 DHCP Spoofing",
            severity=Severity.HIGH,
        )
        fault = Variant(
            title="Many devices requested addresses at once",
            summary=f"{self.peak} devices asked for addresses within {dur:.0f} s.",
            explanation="Many devices joined at the same time (for example a classroom powering up). This can fill the pool.",
            cause="A burst of legitimate devices joining (mass boot / power restore).",
            fix=["Check the DHCP pool is large enough for all devices.", "Consider shorter lease times."],
            analogy="Like a whole bus of guests arriving at reception at once.",
            severity=Severity.LOW,
        )
        ev = evidence_of(self.starve_frames, total=self.starve_seen, first_ts=self.peak_first, last_ts=self.peak_last)
        tech = (f"Peak {self.peak} new chaddr values in {dur:.1f} s ({rate:.1f}/s); {self.starve_seen} distinct chaddr "
                f"overall; chaddr≠eth_src {mismatch:.2f}; multicast-bit chaddr {mcast:.2f}; no hostname {nohost:.2f}; "
                f"top Ethernet sender {top_eth} ({top_n}).")
        metrics = {"peak_new_macs": self.peak, "window_s": round(dur, 2), "rate_per_s": round(rate, 2),
                   "distinct_chaddr": self.starve_seen, "chaddr_mismatch_ratio": round(mismatch, 3),
                   "multicast_chaddr_ratio": round(mcast, 3), "top_sender": top_eth}
        return make_finding("dhcp.starvation", {A: attack, F: fault}, ind, technical=tech, hosts=[top_eth],
                            metrics=metrics, evidence=ev, default=A)
