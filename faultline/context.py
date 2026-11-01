"""Shared analysis context: host inventory and tunable thresholds.

The HostTable is built in the same streaming pass as the detectors and infers
*roles* (gateway, DNS server, DHCP server). Roles are what let detectors tell
"a printer has the same IP as a laptop" apart from "someone is impersonating
the router".
"""

from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from functools import lru_cache

from .capture.reader import CaptureInfo
from .model import Packet

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
_PLAUSIBLE_TS = 315532800.0  # see capture.reader.PLAUSIBLE_TS


@lru_cache(maxsize=65536)
def is_private(ip: str | None) -> bool:
    """RFC1918 / ULA / link-local / loopback / CGNAT, i.e. "inside" addresses."""
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # NB: deliberately *not* ``a.is_private``: Python counts documentation and
    # benchmarking ranges (192.0.2/24, 198.51.100/24, 203.0.113/24, 2001:db8::/32,
    # 198.18/15 ...) as "private", but on the wire those are routed like public
    # addresses. "Inside" means RFC 1918, CGNAT, ULA, link-local or loopback only.
    nets = _LOCAL_V4 if a.version == 4 else _LOCAL_V6
    return any(a in n for n in nets)


_LOCAL_V4 = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8", "0.0.0.0/8"))
_LOCAL_V6 = tuple(ipaddress.ip_network(n) for n in ("fc00::/7", "fe80::/10", "::1/128", "::/128"))


@lru_cache(maxsize=65536)
def is_multicast_or_broadcast(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_multicast or ip == "255.255.255.255" or ip.endswith(".255")


def is_mac_multicast(mac: str | None) -> bool:
    if not mac or len(mac) < 2:
        return False
    try:
        return bool(int(mac[:2], 16) & 1)
    except ValueError:
        return False


@dataclass
class HostInfo:
    ip: str
    macs: Counter = field(default_factory=Counter)
    first_ts: float = 0.0
    last_ts: float = 0.0
    packets_sent: int = 0
    packets_recv: int = 0
    bytes_sent: int = 0
    roles: set[str] = field(default_factory=set)
    names: set[str] = field(default_factory=set)  # DHCP hostnames (untrusted text)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "macs": [m for m, _ in self.macs.most_common(4)],
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "packets_sent": self.packets_sent,
            "packets_recv": self.packets_recv,
            "bytes_sent": self.bytes_sent,
            "roles": sorted(self.roles),
            "names": sorted(self.names)[:3],
            "local": is_private(self.ip),
        }


class HostTable:
    """IP ↔ MAC inventory with role inference."""

    MAX_HOSTS = 200_000

    def __init__(self) -> None:
        self.hosts: dict[str, HostInfo] = {}
        self.mac_ips: dict[str, set[str]] = defaultdict(set)  # MAC → IPs it *sourced* (L3) - for gateway inference
        self.arp_claims: dict[str, Counter] = defaultdict(Counter)  # IP → Counter(MAC) from ARP sender fields
        self.dhcp_routers: Counter = Counter()  # router option values seen in OFFER/ACK
        self.dhcp_dns: Counter = Counter()
        self.dns_servers: Counter = Counter()  # IPs answering DNS on port 53
        self.dhcp_servers: Counter = Counter()
        self._gw_cache: tuple[set[str], set[str]] | None = None

    def _host(self, ip: str, ts: float) -> HostInfo | None:
        h = self.hosts.get(ip)
        if h is None:
            if len(self.hosts) >= self.MAX_HOSTS:
                return None
            h = self.hosts[ip] = HostInfo(ip=ip, first_ts=ts, last_ts=ts)
        h.last_ts = ts
        return h

    def observe(self, p: Packet) -> None:
        self._gw_cache = None
        if p.arp is not None:
            a = p.arp
            if a.spa and a.spa != "0.0.0.0":
                self.arp_claims[a.spa][a.sha] += 1
                h = self._host(a.spa, p.ts)
                if h is not None:
                    h.macs[a.sha] += 1
            return
        if p.src is None:
            return
        src = self._host(p.src, p.ts)
        if src is not None:
            src.packets_sent += 1
            src.bytes_sent += p.wirelen
            if p.eth_src and is_private(p.src):
                src.macs[p.eth_src] += 1
        if p.eth_src and len(self.mac_ips[p.eth_src]) < 4096:
            self.mac_ips[p.eth_src].add(p.src)
        if p.dst and not is_multicast_or_broadcast(p.dst):
            dst = self._host(p.dst, p.ts)
            if dst is not None:
                dst.packets_recv += 1
        if p.dns is not None and p.dns.qr and p.udp is not None and p.udp.sport == 53:
            self.dns_servers[p.src] += 1
            if src is not None:
                src.roles.add("dns-server")
        if p.dhcp is not None:
            d = p.dhcp
            if d.msg_type in (2, 5, 6):  # OFFER / ACK / NAK come from servers
                sid = d.server_id or p.src
                self.dhcp_servers[sid] += 1
                if src is not None:
                    src.roles.add("dhcp-server")
                for r in (d.routers or [])[:4]:
                    self.dhcp_routers[r] += 1
                for s in (d.dns_servers or [])[:4]:
                    self.dhcp_dns[s] += 1
            if d.hostname and src is not None and len(src.names) < 8:
                src.names.add(d.hostname[:64])

    # ------------------------------------------------------------------ #
    def gateway(self) -> tuple[set[str], set[str]]:
        """Best guess of (gateway IPs, gateway MACs).

        A gateway MAC is the Ethernet source of traffic from *many* distinct
        public IPs. The gateway IP comes from DHCP's router option or from the
        IP that the gateway MAC uses for itself (its private address).
        """
        if self._gw_cache is not None:
            return self._gw_cache
        macs: set[str] = set()
        for mac, ips in self.mac_ips.items():
            public = sum(1 for ip in ips if not is_private(ip))
            if public >= 3:
                macs.add(mac)
        # Trust what the traffic proves (a MAC that really forwards internet traffic)
        # over what DHCP *claims*: a rogue DHCP server can name itself the router.
        ips: set[str] = set()
        for mac in macs:
            for ip in self.mac_ips.get(mac, ()):
                if is_private(ip):
                    ips.add(ip)
            for ip, claims in self.arp_claims.items():
                if claims and claims.most_common(1)[0][0] == mac:
                    ips.add(ip)
        if not ips and self.dhcp_routers:
            ips = {self.dhcp_routers.most_common(1)[0][0]}
        # gateway MAC may never source public traffic in a short LAN-only capture
        for ip in list(ips):
            for mac, _ in self.arp_claims.get(ip, Counter()).most_common(1):
                macs.add(mac)
        self._gw_cache = (ips, macs)
        for ip in ips:
            h = self.hosts.get(ip)
            if h is not None:
                h.roles.add("gateway")
        return self._gw_cache

    def is_gateway_ip(self, ip: str) -> bool:
        return ip in self.gateway()[0]

    def to_list(self, limit: int = 500) -> list[dict]:
        self.gateway()
        # "0.0.0.0" (a DHCP client before it has an address) and broadcast addresses are not devices
        real = [h for h in self.hosts.values()
                if h.ip not in ("0.0.0.0", "255.255.255.255", "::") and not is_multicast_or_broadcast(h.ip)]
        ranked = sorted(real, key=lambda h: (not is_private(h.ip), -(h.packets_sent + h.packets_recv)))
        return [h.to_dict() for h in ranked[:limit]]


@dataclass
class Config:
    """Detection thresholds. ``sensitivity`` scales most count thresholds:
    'low' = fewer alerts, 'high' = more alerts."""

    sensitivity: str = "normal"

    @property
    def scale(self) -> float:
        return {"low": 1.6, "normal": 1.0, "high": 0.6}.get(self.sensitivity, 1.0)


class AnalysisContext:
    def __init__(self, info: CaptureInfo, config: Config | None = None):
        self.info = info
        self.config = config or Config()
        self.hosts = HostTable()
        self.packet_count = 0
        self.malformed = 0
        self.start_ts: float | None = None
        self.end_ts: float | None = None
        self.protocols: Counter = Counter()

    @property
    def duration(self) -> float:
        if self.start_ts is None or self.end_ts is None:
            return 0.0
        return max(0.0, self.end_ts - self.start_ts)

    def observe(self, p: Packet) -> None:
        self.packet_count += 1
        ts = p.ts
        if ts is not None and (ts >= _PLAUSIBLE_TS or self.start_ts is None or self.start_ts < _PLAUSIBLE_TS):
            if self.start_ts is None or ts < self.start_ts or self.start_ts < _PLAUSIBLE_TS <= ts:
                self.start_ts = ts
            if self.end_ts is None or ts > self.end_ts:
                self.end_ts = ts
        if p.malformed:
            self.malformed += 1
        self.protocols[protocol_label(p)] += 1
        self.hosts.observe(p)


def protocol_label(p: Packet) -> str:
    if p.arp is not None:
        return "ARP"
    if p.dhcp is not None:
        return "DHCP"
    if p.dns is not None:
        return "DNS"
    if p.tcp is not None:
        if p.tls is not None:
            return "TLS"
        if p.http is not None:
            return "HTTP"
        return "TCP"
    if p.icmp is not None:
        return "ICMPv6" if p.icmp.v6 else "ICMP"
    if p.udp is not None:
        return "UDP"
    if p.ip_ver == 6:
        return "IPv6"
    if p.ip_ver == 4:
        return "IPv4"
    return "Other"
