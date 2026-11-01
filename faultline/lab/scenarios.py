"""Labelled benign / fault / misconfiguration scenarios -> ``samples/*.pcap`` + ``labels.json``.

Run: ``python -m faultline.lab.scenarios samples/`` (deterministic for a seed).

Every scenario shares the same office LAN (:class:`faultline.lab.craft.Lan`) and
carries benign background traffic (DNS, HTTPS with SNI, ARP, NTP) so detectors
are exercised against realistic noise.  Attack scenarios live in
``faultline.lab.scenarios_attack`` (optional module); :func:`generate_all`
merges its labels when it is present.

labels.json entry::

    "lossy_link.pcap": {"title": ..., "story": ..., "expected": [{"kind": "tcp.retransmissions",
                        "category": "fault"}], "must_not": [...], "clean": false, "malformed": false}
"""

from __future__ import annotations

import gzip
import importlib
import json
import os
import random
import struct
import sys
from typing import Callable

from faultline.lab.craft import (
    BROADCAST_MAC, ZERO_MAC, PROTO_ICMP, PROTO_TCP, PROTO_UDP,
    Capture, Host, Lan, TcpSession,
    arp_frame, dhcp_msg, dns_query, dns_response, ether, http_request, http_response,
    icmp_echo, icmp_time_exceeded, icmp_unreachable, ipv4, ntp_packet, tcp_seg,
    tls_app_data, tls_client_hello, tls_server_hello, udp_dgram,
)

LINK_LOCAL_MAC = "00:00:00:00:00:00"

# ---------------------------------------------------------------------------
# label helpers
# ---------------------------------------------------------------------------

def label(title: str, story: str, expected=(), must_not=(), clean: bool = False, malformed: bool = False) -> dict:
    return {
        "title": title,
        "story": story,
        "expected": [{"kind": k, "category": c} for k, c in expected],
        "must_not": list(must_not),
        "clean": clean,
        "malformed": malformed,
    }


# ---------------------------------------------------------------------------
# reusable traffic snippets
# ---------------------------------------------------------------------------

class Office:
    """Per-scenario state: a Lan, a Capture, a seeded rng and port/qid counters."""

    def __init__(self, seed: int):
        self.lan = Lan()
        self.cap = Capture(self.lan, seed=seed)
        self.rng = self.cap.rng
        self.t0 = self.cap.t0
        self._port = 49152 + self.rng.randrange(0, 4000)
        self._qid = self.rng.randrange(0, 60000)

    def port(self) -> int:
        self._port += 1 + self.rng.randrange(0, 3)
        if self._port > 65000:
            self._port = 49152
        return self._port

    def qid(self) -> int:
        self._qid = (self._qid + 1 + self.rng.randrange(0, 50)) & 0xFFFF
        return self._qid

    # -- L2/L3 one-liners ---------------------------------------------------
    def udp(self, ts: float, src: Host | str, dst: str, sport: int, dport: int, payload: bytes,
            ttl: int = 64, **framekw) -> float:
        sip = src.ip if isinstance(src, Host) else src
        pkt = ipv4(sip, dst, PROTO_UDP, udp_dgram(sip, dst, sport, dport, payload), ttl=ttl,
                   ip_id=self.cap.next_ip_id(sip), df=sip != "0.0.0.0")
        return self.cap.ip(ts, pkt, sip, dst, **framekw)

    def arp_request(self, ts: float, who: Host, target_ip: str) -> float:
        return self.cap.add(ts, arp_frame(1, who.mac, who.ip, ZERO_MAC, target_ip))

    def arp_reply(self, ts: float, owner_mac: str, owner_ip: str, to: Host) -> float:
        return self.cap.add(ts, arp_frame(2, owner_mac, owner_ip, to.mac, to.ip))

    def arp_exchange(self, ts: float, who: Host, target: Host, answered: bool = True) -> float:
        self.arp_request(ts, who, target.ip)
        if answered:
            return self.arp_reply(ts + self.rng.uniform(0.0003, 0.0015), target.mac, target.ip, who)
        return ts

    def gratuitous_arp(self, ts: float, who: Host) -> float:
        self.cap.add(ts, arp_frame(1, who.mac, who.ip, ZERO_MAC, who.ip))
        return self.cap.add(ts + 0.0005, arp_frame(2, who.mac, who.ip, BROADCAST_MAC, who.ip, eth_dst=BROADCAST_MAC))

    def arp_probe(self, ts: float, who_mac: str, ip: str, n: int = 3, announce: bool = True) -> float:
        """RFC 5227 address probing from 0.0.0.0, then announcement."""
        t = ts
        for _ in range(n):
            self.cap.add(t, arp_frame(1, who_mac, "0.0.0.0", ZERO_MAC, ip))
            t += self.rng.uniform(1.0, 2.0)
        if announce:
            self.cap.add(t, arp_frame(1, who_mac, ip, ZERO_MAC, ip))
            t += 0.0005
        return t

    # -- DNS -----------------------------------------------------------------
    def dns(self, ts: float, client: Host, name: str, qtype: str = "A", rcode: int = 0,
            answer_ip: str | None = None, resolver: str | None = None, delay: float | None = None,
            answered: bool = True, ttl: int = 300) -> tuple[float, int, int]:
        """One lookup. Returns (time of last frame, qid, sport)."""
        resolver = resolver or self.lan.dns
        qid, sport = self.qid(), self.port()
        self.udp(ts, client, resolver, sport, 53, dns_query(qid, name, qtype))
        if not answered:
            return ts, qid, sport
        if delay is None:
            delay = self.rng.uniform(0.002, 0.02) if self.lan.on_lan(resolver) else self.rng.uniform(0.012, 0.045)
        if rcode == 0:
            if answer_ip is None:
                answer_ip = self.lan.server(name).ip if qtype == "A" else "2001:db8:abcd::" + str(self.rng.randrange(1, 255))
            answers = [(qtype, answer_ip, ttl)]
        else:
            answers = []
        resp = dns_response(qid, name, qtype, answers, rcode=rcode)
        t = ts + delay
        self.udp(t, resolver, client.ip, 53, sport, resp, ttl=64 if self.lan.on_lan(resolver) else 57)
        return t, qid, sport

    def dns_retry(self, ts: float, client: Host, name: str, qid: int, sport: int, resolver: str | None = None) -> float:
        resolver = resolver or self.lan.dns
        self.udp(ts, client, resolver, sport, 53, dns_query(qid, name, "A"))
        return ts

    # -- NTP / ICMP ----------------------------------------------------------
    def ntp(self, ts: float, client: Host) -> float:
        srv = self.lan.server("pool.ntp.org")
        sport = self.port()
        self.udp(ts, client, srv.ip, sport, 123, ntp_packet(True, ts))
        t = ts + self.rng.uniform(0.015, 0.04)
        self.udp(t, srv.ip, client.ip, 123, sport, ntp_packet(False, t), ttl=54)
        return t

    def ping(self, ts: float, client: Host, target: str, ident: int, seq: int, rtt: float = 0.002,
             ttl_back: int = 64, data: bytes = b"\x08" * 56) -> float:
        req = ipv4(client.ip, target, PROTO_ICMP, icmp_echo(True, ident, seq, data), ip_id=self.cap.next_ip_id(client.ip), df=False)
        self.cap.ip(ts, req, client.ip, target)
        rep = ipv4(target, client.ip, PROTO_ICMP, icmp_echo(False, ident, seq, data), ttl=ttl_back, ip_id=self.cap.next_ip_id(target), df=False)
        return self.cap.ip(ts + self.cap.jitter(rtt, 0.3), rep, target, client.ip)

    # -- TCP app sessions -----------------------------------------------------
    def https(self, ts: float, client: Host, name: str, rtt: float | None = None, nbytes: int | None = None,
              upload: int = 0, lookup: bool = True, close_by: str = "c", rst_after: bool = False,
              **sess_kw) -> TcpSession:
        """DNS lookup (optional) + full TLS 1.3 session with ``nbytes`` of server data."""
        srv = self.lan.server(name)
        rtt = rtt if rtt is not None else self.rng.uniform(0.02, 0.08)
        nbytes = nbytes if nbytes is not None else self.rng.choice([1500, 2200, 4800, 9000, 15000, 30000])
        t = ts
        if lookup:
            t, _, _ = self.dns(ts, client, name)
            t += self.rng.uniform(0.0005, 0.003)
        s = TcpSession(self.cap, client, srv, self.port(), 443, rtt, t, **sess_kw)
        s.handshake()
        s.client_send(tls_client_hello(name, rng=self.rng))
        s.server_send(tls_server_hello(rng=self.rng, extra_len=self.rng.randrange(1800, 3600)))
        s.client_send(tls_app_data(self.rng.randrange(60, 120), self.rng))
        s.server_send(tls_app_data(self.rng.randrange(200, 300), self.rng))
        s.client_send(tls_app_data(self.rng.randrange(150, 900) + upload, self.rng), ack=upload > 0)
        s.server_send(tls_app_data(nbytes, self.rng), think=self.rng.uniform(0.005, 0.06))
        if self.rng.random() < 0.3:
            s.client_send(tls_app_data(self.rng.randrange(100, 400), self.rng), at=s.now + self.rng.uniform(0.05, 0.6), ack=False)
            s.server_send(tls_app_data(self.rng.randrange(600, 6000), self.rng), think=self.rng.uniform(0.005, 0.05))
        s.close(close_by, at=s.now + self.rng.uniform(0.01, 0.5), rst_after=rst_after)
        return s

    def http(self, ts: float, client: Host, name: str, path: str = "/", rtt: float | None = None,
             body: int = 3000, think: float | None = None, status: int = 200, lookup: bool = True,
             requests: int = 1, **sess_kw) -> TcpSession:
        srv = self.lan.server(name)
        rtt = rtt if rtt is not None else self.rng.uniform(0.02, 0.06)
        t = ts
        if lookup:
            t, _, _ = self.dns(ts, client, name)
            t += 0.001
        s = TcpSession(self.cap, client, srv, self.port(), 80, rtt, t, **sess_kw)
        s.handshake()
        for i in range(requests):
            s.client_send(http_request("GET", name, path if i == 0 else f"{path.rstrip('/')}/asset{i}.js"))
            s.server_send(http_response(status, "OK" if status == 200 else "Error", body_len=body),
                          think=think if think is not None else self.rng.uniform(0.003, 0.04))
            if i + 1 < requests:
                s.now += self.rng.uniform(0.01, 0.2)
        s.close("c", at=s.now + self.rng.uniform(0.01, 0.3))
        return s

    def dhcp_dora(self, ts: float, client: Host, server: Host | None = None, lease: int = 86400,
                  hostname: str | None = None, offers_from: list[tuple[Host, str, str, str]] | None = None,
                  choose: int = 0, mask: str = "255.255.255.0") -> float:
        """DISCOVER / OFFER / REQUEST / ACK.  ``offers_from`` = [(server, yiaddr, router, dns)] for
        several servers; ``choose`` picks which offer the client requests."""
        server = server or self.lan.gateway
        xid = self.rng.getrandbits(32)
        hn = hostname or client.name
        bcast = "255.255.255.255"
        disc = dhcp_msg(1, xid, client.mac, 1, hostname=hn, param_req=(1, 3, 6, 15, 26, 28, 51, 58, 59, 119))
        self.udp(ts, "0.0.0.0", bcast, 68, 67, disc, src_mac=client.mac, dst_mac=BROADCAST_MAC)
        offers = offers_from or [(server, client.ip, self.lan.gateway.ip, self.lan.dns)]
        t = ts
        for srv, yi, router, dns in offers:
            t = ts + self.rng.uniform(0.002, 0.08)
            off = dhcp_msg(2, xid, client.mac, 2, yiaddr=yi, siaddr=srv.ip, server_id=srv.ip,
                           routers=[router], dns=[dns], lease=lease, mask=mask)
            self.udp(t, srv, bcast, 67, 68, off, src_mac=srv.mac, dst_mac=BROADCAST_MAC)
        srv, yi, router, dns = offers[choose]
        t += self.rng.uniform(0.001, 0.01)
        req = dhcp_msg(1, xid, client.mac, 3, server_id=srv.ip, requested_ip=yi, hostname=hn,
                       param_req=(1, 3, 6, 15, 26, 28, 51, 58, 59, 119))
        self.udp(t, "0.0.0.0", bcast, 68, 67, req, src_mac=client.mac, dst_mac=BROADCAST_MAC)
        t += self.rng.uniform(0.002, 0.02)
        ack = dhcp_msg(2, xid, client.mac, 5, yiaddr=yi, siaddr=srv.ip, server_id=srv.ip,
                       routers=[router], dns=[dns], lease=lease, mask=mask)
        self.udp(t, srv, bcast, 67, 68, ack, src_mac=srv.mac, dst_mac=BROADCAST_MAC)
        return t

    # -- background ------------------------------------------------------------
    def background(self, start: float, duration: float, rate: float = 0.4, clients: list[Host] | None = None,
                   exclude: set[str] = frozenset()) -> float:
        """Benign traffic: DNS + HTTPS (SNI), occasional HTTP, ARP for the gateway, NTP.

        ``rate`` is the mean number of events per second.  Returns the end time.
        """
        clients = [c for c in (clients or self.lan.clients) if c.ip not in exclude]
        names = ["www.example.com", "docs.example.org", "mail.example.net", "updates.example-cdn.com",
                 "static.example-cdn.com", "api.example.io", "git.example.dev", "chat.example-apps.com",
                 "www.wikipedia-mirror.example", "cdn.video-example.com"]
        t = start
        end = start + duration
        first_arp = {}
        while t < end:
            c = self.rng.choice(clients)
            r = self.rng.random()
            if c.ip not in first_arp:
                first_arp[c.ip] = True
                self.arp_exchange(t - self.rng.uniform(0.001, 0.01), c, self.lan.gateway)
            if r < 0.62:
                self.https(t, c, self.rng.choice(names))
            elif r < 0.78:
                self.dns(t, c, self.rng.choice(names), qtype=self.rng.choice(["A", "A", "AAAA"]))
            elif r < 0.86:
                self.http(t, c, "www.wikipedia-mirror.example", path=self.rng.choice(["/", "/wiki/TCP", "/status"]))
            elif r < 0.94:
                self.arp_exchange(t, c, self.lan.gateway)
            else:
                self.ntp(t, c)
            t += self.rng.expovariate(rate)
        return end


# ---------------------------------------------------------------------------
# scenarios
# ---------------------------------------------------------------------------

def sc_clean_office(o: Office) -> dict:
    t0 = o.t0
    newcomer = o.lan.clients[8]  # intern-laptop
    t = o.dhcp_dora(t0 + 0.5, newcomer)
    o.arp_probe(t + 0.2, newcomer.mac, newcomer.ip, n=1)
    o.arp_exchange(t + 2.4, newcomer, o.lan.gateway)
    o.ntp(t + 2.6, newcomer)
    o.background(t0 + 3, 150, rate=0.35)
    return label("Clean office afternoon", "An ordinary office: a laptop joins by DHCP, people browse, mail and docs sync, nothing is wrong.", clean=True)


def sc_busy_but_healthy(o: Office) -> dict:
    t0 = o.t0
    lan, rng = o.lan, o.rng
    o.gratuitous_arp(t0 + 0.2, lan.clients[3])                 # reception PC boots
    o.background(t0 + 1, 170, rate=1.3)
    # a browser opening 6 parallel connections to one server
    c = lan.clients[1]
    t, _, _ = o.dns(t0 + 20.0, c, "static.example-cdn.com")
    for i in range(6):
        o.https(t + 0.002 + i * 0.0015, c, "static.example-cdn.com", rtt=0.028, nbytes=rng.randrange(8000, 40000), lookup=False)
    # isolated retransmissions among thousands of healthy segments
    s = TcpSession(o.cap, lan.clients[5], lan.server("updates.example-cdn.com"), o.port(), 443, 0.035, t0 + 45.0)
    s.handshake(); s.client_send(tls_client_hello("updates.example-cdn.com", rng=rng)); s.server_send(tls_server_hello(rng=rng, extra_len=2500))
    s.client_send(tls_app_data(80, rng)); s.server_send(tls_app_data(250_000, rng), drop_down={37}); s.close()
    s = TcpSession(o.cap, lan.clients[6], lan.server("cdn.video-example.com"), o.port(), 443, 0.05, t0 + 95.0)
    s.handshake(); s.client_send(tls_client_hello("cdn.video-example.com", rng=rng)); s.server_send(tls_server_hello(rng=rng, extra_len=2500))
    s.client_send(tls_app_data(80, rng)); s.server_send(tls_app_data(200_000, rng), drop_up={120}); s.close()
    # RST right after a normal FIN exchange (browser abort of a closing socket)
    o.https(t0 + 60.0, lan.clients[2], "mail.example.net", rst_after=True)
    # one NXDOMAIN typo
    o.dns(t0 + 72.0, lan.clients[0], "wwww.example.com", rcode=3)
    o.dns(t0 + 72.4, lan.clients[0], "www.example.com")
    # TCP keepalives on a long-lived chat connection
    s = o.https(t0 + 10.0, lan.clients[7], "chat.example-apps.com", nbytes=3000, rtt=0.04)
    s2 = TcpSession(o.cap, lan.clients[7], lan.server("chat.example-apps.com"), o.port(), 443, 0.04, t0 + 12.0)
    s2.handshake(); s2.client_send(tls_client_hello("chat.example-apps.com", rng=rng)); s2.server_send(tls_server_hello(rng=rng, extra_len=2200))
    s2.client_send(tls_app_data(90, rng)); s2.server_send(tls_app_data(500, rng))
    s2.keepalive(at=s2.now + 45.0, n=3, interval=45.0)
    s2.close("s", at=s2.now + 2.0)
    # traceroute to a doc server: UDP 33434+ with increasing TTL, ICMP time exceeded from 3 routers
    tr = lan.clients[4]
    target = lan.server("docs.example.org").ip
    hops = [(lan.gateway.ip, lan.gateway.mac, 0.0012), ("10.20.0.1", lan.gateway.mac, 0.004), ("172.16.5.1", lan.gateway.mac, 0.011)]
    t = t0 + 130.0
    dport = 33434
    for ttl in range(1, 5):
        for probe in range(3):
            sport = 40000 + ttl * 3 + probe
            orig = ipv4(tr.ip, target, PROTO_UDP, udp_dgram(tr.ip, target, sport, dport, b"@" * 32), ttl=ttl, ip_id=o.cap.next_ip_id(tr.ip), df=False)
            o.cap.ip(t, orig, tr.ip, target)
            if ttl <= 3:
                rip, rmac, rt = hops[ttl - 1]
                icmp = ipv4(rip, tr.ip, PROTO_ICMP, icmp_time_exceeded(orig), ttl=64 - (ttl - 1) * 1, ip_id=o.cap.next_ip_id(rip), df=False)
                o.cap.ip(t + o.cap.jitter(rt, 0.3), icmp, rip, tr.ip, src_mac=rmac)
            else:
                icmp = ipv4(target, tr.ip, PROTO_ICMP, icmp_unreachable(3, orig), ttl=52, ip_id=o.cap.next_ip_id(target), df=False)
                o.cap.ip(t + o.cap.jitter(0.03, 0.2), icmp, target, tr.ip)
            dport += 1
            t += rng.uniform(0.02, 0.06)
    return label("Busy but healthy", "A busy afternoon with thousands of healthy flows, including harmless oddities like a lone retransmission, a typo'd domain and a traceroute.",
                 clean=True, must_not=["tcp.retransmissions", "tcp.refused", "dns.errors", "scan.port", "arp.duplicate_ip", "icmp.routing_loop"])


def sc_lossy_link(o: Office) -> dict:
    t0 = o.t0
    o.background(t0, 60, rate=0.3, exclude={o.lan.clients[0].ip})
    c = o.lan.clients[0]
    srv = o.lan.server("docs.example.org")
    t, _, _ = o.dns(t0 + 2.0, c, "docs.example.org")
    for i, (size, down, up) in enumerate([(700_000, 0.04, 0.03), (500_000, 0.035, 0.03)]):
        s = TcpSession(o.cap, c, srv, o.port(), 443, 0.042, t + 0.005 + i * 25.0, jitter=0.2)
        s.handshake(); s.client_send(tls_client_hello("docs.example.org", rng=o.rng))
        s.server_send(tls_server_hello(rng=o.rng, extra_len=2600)); s.client_send(tls_app_data(80, o.rng))
        s.client_send(tls_app_data(300, o.rng))
        s.server_send(tls_app_data(size, o.rng), loss_down=down, loss_up=up, think=0.02)
        s.close("s", at=s.now + 0.2)
    return label("Lossy Wi-Fi link", "A laptop on a flaky Wi-Fi link downloads a large file and loses 5 to 8 percent of the segments in both directions, so TCP keeps retransmitting.",
                 expected=[("tcp.retransmissions", "fault")], must_not=["scan.port", "flood.syn"])


def sc_connection_refused(o: Office) -> dict:
    t0 = o.t0
    db = o.lan.hosts["192.168.1.20"]
    app = o.lan.clients[1]
    o.background(t0, 70, rate=0.3)
    o.arp_exchange(t0 + 1.0, app, db)
    t = t0 + 1.2
    for _ in range(24):
        s = TcpSession(o.cap, app, db, o.port(), 5432, 0.0012, t, jitter=0.3)
        s.syn_refused()
        t += o.rng.uniform(1.5, 3.5)
    return label("Database connection refused", "An application server keeps connecting to a database at 192.168.1.20:5432 whose service is stopped, so every attempt is refused with a reset.",
                 expected=[("tcp.refused", "misconfig")], must_not=["scan.port", "flood.syn"])


def sc_server_down_timeouts(o: Office) -> dict:
    t0 = o.t0
    lan = o.lan
    o.background(t0, 90, rate=0.3)
    dead = Host("198.51.100.7", None, "198.51.100.7")
    for i, c in enumerate(lan.clients[:3]):
        t = t0 + 2.0 + i * 7.0
        for k in range(2):
            s = TcpSession(o.cap, c, dead, o.port(), 443, 0.03, t + k * 32.0)
            s.syn_only(retries=(1.0, 2.0, 4.0, 8.0, 16.0))
    printer_ip = "192.168.1.50"
    for i, c in enumerate(lan.clients[3:5]):
        t = t0 + 5.0 + i * 20.0
        for burst in range(3):
            for k in range(3):
                o.arp_request(t + burst * 10.0 + k * 1.0, c, printer_ip)
    return label("Server down, printer unplugged", "A web service at 198.51.100.7 is down so connection attempts time out with exponential backoff, and the office printer at 192.168.1.50 no longer answers ARP.",
                 expected=[("tcp.syn_timeout", "fault"), ("arp.unanswered", "fault")], must_not=["scan.port", "arp.scan"])


def sc_zero_window(o: Office) -> dict:
    t0 = o.t0
    o.background(t0, 75, rate=0.3, exclude={o.lan.clients[2].ip})
    c = o.lan.clients[2]
    srv = o.lan.server("updates.example-cdn.com")
    t, _, _ = o.dns(t0 + 1.0, c, "updates.example-cdn.com")
    s = TcpSession(o.cap, c, srv, o.port(), 443, 0.03, t + 0.003)
    s.handshake(); s.client_send(tls_client_hello("updates.example-cdn.com", rng=o.rng))
    s.server_send(tls_server_hello(rng=o.rng, extra_len=2400)); s.client_send(tls_app_data(80, o.rng)); s.client_send(tls_app_data(250, o.rng))
    for stall in (3.2, 4.5, 2.8, 6.1, 3.9):
        s.server_send(tls_app_data(120_000, o.rng), think=0.01)
        s.zero_window(stall)
    s.server_send(tls_app_data(60_000, o.rng), think=0.01)
    s.close("c", at=s.now + 0.1)
    return label("Receiver stalls (zero window)", "A slow laptop downloading an update keeps running out of receive buffer, advertising a zero window and stalling the transfer for seconds at a time.",
                 expected=[("tcp.zero_window", "fault")], must_not=["tcp.retransmissions", "latency.high_rtt"])


def sc_slow_server(o: Office) -> dict:
    t0 = o.t0
    o.background(t0, 80, rate=0.3)
    c = o.lan.clients[1]
    t = t0 + 1.0
    for i in range(7):
        s = o.http(t, c, "api.example.io", path=f"/v1/report?id={100 + i}", rtt=0.025, body=4000,
                   think=o.rng.uniform(2.0, 6.0), lookup=(i == 0), jitter=0.08)
        t = s.now + o.rng.uniform(1.0, 4.0)
    return label("Slow application server", "The network is fine (25 ms handshakes) but the API server takes 2 to 6 seconds to send the first byte of every response.",
                 expected=[("latency.slow_server", "fault")], must_not=["latency.high_rtt", "tcp.retransmissions"])


def sc_high_latency(o: Office) -> dict:
    t0 = o.t0
    lan = o.lan
    # LAN-local background still fast; internet is far away for everyone
    for c in lan.clients[:4]:
        o.arp_exchange(t0 + o.rng.uniform(0.1, 2), c, lan.gateway)
    t = t0 + 1.0
    for i in range(8):
        c = lan.clients[i % 5]
        name = ["www.example.com", "docs.example.org", "mail.example.net", "api.example.io"][i % 4]
        rtt = o.rng.uniform(0.6, 0.9)
        o.dns(t, c, name, delay=rtt * 0.95 if i % 2 else None)
        o.https(t + rtt + 0.01, c, name, rtt=rtt, nbytes=o.rng.randrange(4000, 20000), lookup=False, jitter=0.12,
                server_think_time=0.015)
        t += o.rng.uniform(4.0, 9.0)
    return label("Satellite-grade latency", "Every connection takes 600 to 900 ms just to complete its handshake because the uplink is a very high-latency satellite path; the servers themselves answer quickly.",
                 expected=[("latency.high_rtt", "fault")], must_not=["latency.slow_server", "tcp.retransmissions"])


def sc_mtu_blackhole(o: Office) -> dict:
    t0 = o.t0
    o.background(t0, 70, rate=0.25, exclude={o.lan.clients[7].ip})
    c = o.lan.clients[7]
    srv = o.lan.server("git.example.dev")
    t, _, _ = o.dns(t0 + 1.0, c, "git.example.dev")
    for i in range(3):
        s = TcpSession(o.cap, c, srv, o.port(), 443, 0.045, t + 0.004 + i * 20.0)
        s.handshake()
        s.client_send(tls_client_hello("git.example.dev", rng=o.rng))
        s.server_send(tls_server_hello(rng=o.rng, extra_len=1100))      # small segments: ACKed fine
        s.client_send(tls_app_data(80, o.rng))
        s.client_send(tls_app_data(300, o.rng))
        big = tls_app_data(1460 * 4, o.rng)[:1460 * 4]
        tt = s.reply_earliest + 0.01
        seq = s.s_seq
        # the first full-size DF segment and its retransmissions never get through; no ICMP ever arrives
        for k, delay in enumerate([0.0, 0.21, 0.42, 0.85, 1.7, 3.4, 6.8]):
            s.server_segment(tt + delay, "A", big[:1460], seq=seq)
            if k == 0:
                s.server_segment(tt + 0.0002, "A", big[1460:2920], seq=(seq + 1460) & 0xFFFFFFFF)
                # client never saw the first one but gets the second -> dup ACK with SACK
                s.client_segment(tt + 0.0006, "A", sacks=[((seq + 1460) & 0xFFFFFFFF, (seq + 2920) & 0xFFFFFFFF)])
        s.now = tt + 6.8 + 0.5
        s.reset("c", at=s.now)
    return label("Path MTU black hole", "A VPN path silently drops every full-size 1460-byte packet and sends no ICMP, so small packets flow but the server's big data segments are retransmitted again and again and the connection stalls.",
                 expected=[("mtu.blackhole", "misconfig")], must_not=["mtu.frag_needed", "latency.slow_server"])


def sc_mtu_frag_needed(o: Office) -> dict:
    t0 = o.t0
    o.background(t0, 60, rate=0.3, exclude={o.lan.clients[5].ip})
    c = o.lan.clients[5]
    vpn = Host("vpn-peer", None, "198.51.100.30")
    gw = o.lan.gateway
    t = t0 + 1.5
    for i in range(3):
        s = TcpSession(o.cap, c, vpn, o.port(), 443, 0.038, t)
        s.handshake()
        s.client_send(tls_client_hello("vpn.example.net", rng=o.rng))
        s.server_send(tls_server_hello(rng=o.rng, extra_len=900))
        s.client_send(tls_app_data(80, o.rng))
        payload = tls_app_data(1460 * 3 + 300, o.rng)
        seq0 = s.c_seq
        tt = s.now + 0.02
        # full-size DF upload segment; the gateway replies ICMP frag-needed, MTU 1400
        s.client_segment(tt, "A", payload[:1460], seq=seq0)
        pkt_big = ipv4(c.ip, vpn.ip, PROTO_TCP, tcp_seg(c.ip, vpn.ip, s.sport, 443, seq0, s.c_ack, "A", win=2047, payload=payload[:1460], ts=(s.c_last_ts, s.s_last_ts)), ip_id=o.cap.next_ip_id(c.ip))
        s.client_segment(tt + 0.0001, "A", payload[1460:2920], seq=(seq0 + 1460) & 0xFFFFFFFF)
        icmp = ipv4(gw.ip, c.ip, PROTO_ICMP, icmp_unreachable(4, pkt_big, mtu=1400), ip_id=o.cap.next_ip_id(gw.ip), df=False)
        o.cap.ip(tt + 0.0009, icmp, gw.ip, c.ip)
        icmp2_src = ipv4(c.ip, vpn.ip, PROTO_TCP, tcp_seg(c.ip, vpn.ip, s.sport, 443, (seq0 + 1460) & 0xFFFFFFFF, s.c_ack, "A", win=2047, payload=payload[1460:2920], ts=(s.c_last_ts, s.s_last_ts)), ip_id=o.cap.next_ip_id(c.ip))
        o.cap.ip(tt + 0.0011, ipv4(gw.ip, c.ip, PROTO_ICMP, icmp_unreachable(4, icmp2_src, mtu=1400), ip_id=o.cap.next_ip_id(gw.ip), df=False), gw.ip, c.ip)
        # sender adapts: 1360-byte segments (1400 - 40) from now on
        tt += 0.0025
        seq = seq0
        for off in range(0, len(payload), 1360):
            chunk = payload[off:off + 1360]
            s.client_segment(tt, "PA" if off + 1360 >= len(payload) else "A", chunk, seq=seq)
            seq = (seq + len(chunk)) & 0xFFFFFFFF
            tt += 0.00013
        s.c_seq = seq
        s.s_ack = seq
        s.server_segment(tt + s.rtt, "A")
        s.now = tt + s.rtt
        s.server_send(tls_app_data(600, o.rng), segment_size=1360, think=0.03)
        s.close("c", at=s.now + 0.05)
        t = s.now + 12.0
    return label("Fragmentation needed on a VPN path", "The office router tells a laptop that its 1460-byte packets do not fit the 1400-byte VPN tunnel (ICMP fragmentation needed), after which the laptop sends smaller packets.",
                 expected=[("mtu.frag_needed", "misconfig")], must_not=["mtu.blackhole"])


def sc_ip_conflict(o: Office) -> dict:
    t0 = o.t0
    lan, rng = o.lan, o.rng
    printer = Host("printer", "00:80:92:5e:31:7a", "192.168.1.23")      # static IP, old
    laptop = Host("guest-laptop", "f4:5c:89:aa:10:99", "192.168.1.23")  # manually configured, same IP
    lan.add_host(printer, client=False)
    o.background(t0, 90, rate=0.3)
    # the printer's quiet life: it answers ARP and takes print jobs
    o.arp_exchange(t0 + 0.5, lan.clients[3], printer)
    s = TcpSession(o.cap, lan.clients[3], printer, o.port(), 9100, 0.0015, t0 + 0.6)
    s.handshake(); s.client_send(20000); s.close()
    # laptop boots at +20 s: ARP probe for .23, the printer answers (conflict), laptop keeps the address anyway
    t = t0 + 20.0
    o.cap.add(t, arp_frame(1, laptop.mac, "0.0.0.0", ZERO_MAC, laptop.ip))
    o.cap.add(t + 0.0009, arp_frame(2, printer.mac, printer.ip, laptop.mac, "0.0.0.0", eth_dst=laptop.mac))
    o.cap.add(t + 1.1, arp_frame(1, laptop.mac, "0.0.0.0", ZERO_MAC, laptop.ip))
    o.cap.add(t + 2.3, arp_frame(1, laptop.mac, laptop.ip, ZERO_MAC, laptop.ip))             # announcement
    o.cap.add(t + 2.3005, arp_frame(2, laptop.mac, laptop.ip, BROADCAST_MAC, laptop.ip, eth_dst=BROADCAST_MAC))
    # both answer the gateway's ARP for .23
    for k in range(3):
        tq = t + 3.0 + k * 25.0
        o.cap.add(tq, arp_frame(1, lan.gateway.mac, lan.gateway.ip, ZERO_MAC, "192.168.1.23"))
        o.cap.add(tq + 0.0007, arp_frame(2, printer.mac, printer.ip, lan.gateway.mac, lan.gateway.ip))
        o.cap.add(tq + 0.0012, arp_frame(2, laptop.mac, laptop.ip, lan.gateway.mac, lan.gateway.ip))
    # laptop's own traffic from .23 (its MAC), printer traffic from .23 (its MAC)
    lan.hosts[laptop.ip] = laptop
    o.arp_exchange(t + 2.5, laptop, lan.gateway)
    for k in range(4):
        o.https(t + 4.0 + k * 15.0, laptop, ["www.example.com", "docs.example.org", "mail.example.net", "api.example.io"][k])
    lan.hosts[printer.ip] = printer
    s = TcpSession(o.cap, lan.clients[4], printer, o.port(), 9100, 0.0015, t + 30.0)
    o.arp_exchange(t + 29.9, lan.clients[4], printer)
    s.handshake(); s.client_send(35000); s.close()
    o.udp(t + 50.0, printer, lan.gateway.ip, 161, 162, b"\x30\x1a\x02\x01\x01\x04\x06public\xa7\x0d\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x00")
    return label("Two devices share 192.168.1.23", "A printer with a static address and a guest laptop configured by hand both use 192.168.1.23; both answer ARP for it and both send their own normal traffic, so connections to either are unreliable.",
                 expected=[("arp.duplicate_ip", "misconfig")], must_not=["arp.spoofing", "dns.hijack", "dhcp.rogue"])


def sc_dns_failure(o: Office) -> dict:
    t0 = o.t0
    lan, rng = o.lan, o.rng
    o.background(t0, 40, rate=0.5)
    names = ["www.example.com", "docs.example.org", "mail.example.net", "updates.example-cdn.com", "api.example.io", "chat.example-apps.com"]
    secondary = "1.1.1.1"
    t = t0 + 40.0
    end = t0 + 130.0
    while t < end:
        c = rng.choice(lan.clients[:8])
        name = rng.choice(names)
        r = rng.random()
        if r < 0.5:
            # primary dead: 1 s + 3 s timeouts, then secondary
            _, qid, sport = o.dns(t, c, name, answered=False)
            o.dns_retry(t + 1.0, c, name, qid, sport)
            o.dns_retry(t + 4.0, c, name, qid, sport)
            if rng.random() < 0.7:
                o.dns(t + 7.0, c, name, resolver=secondary, delay=rng.uniform(0.015, 0.04))
            else:
                o.dns(t + 7.0, c, name, resolver=secondary, answered=False)
        elif r < 0.7:
            o.dns(t, c, name, rcode=2, delay=rng.uniform(0.8, 2.0))        # SERVFAIL
        elif r < 0.85:
            o.dns(t, c, name, delay=rng.uniform(1.6, 2.6))                 # slow success
        else:
            o.dns(t, c, name)                                               # the odd healthy answer
        if rng.random() < 0.25:
            o.arp_exchange(t + 0.3, c, lan.gateway)
        t += rng.expovariate(0.6)
    return label("Resolver stops answering", "The office DNS resolver at 192.168.1.1 stops responding: lookups time out and are retried, some fail with SERVFAIL, and a few only answer after seconds, so web pages hang.",
                 expected=[("dns.timeout", "fault"), ("dns.errors", "fault")], must_not=["dns.hijack", "dns.tunneling"])


def sc_dhcp_two_routers(o: Office) -> dict:
    t0 = o.t0
    lan, rng = o.lan, o.rng
    home = Host("home-router", "b0:be:76:4c:9a:e1", "192.168.0.1")
    lan.add_host(home, client=False)
    o.background(t0, 100, rate=0.3, clients=lan.clients[6:])
    o.gratuitous_arp(t0 + 0.3, home)
    victims = []
    for i, c in enumerate(lan.clients[:4]):
        t = t0 + 2.0 + i * 9.0
        offers = [(lan.gateway, c.ip, lan.gateway.ip, lan.dns),
                  (home, f"192.168.0.{100 + i}", home.ip, "8.8.8.8")]
        choose = 1 if i in (0, 2) else 0      # two clients take the home router's lease
        o.dhcp_dora(t, c, offers_from=offers, choose=choose, lease=3600 if choose else 86400)
        if choose == 1:
            v = Host(c.name, c.mac, f"192.168.0.{100 + i}")
            lan.add_host(v, client=False)
            victims.append(v)
        else:
            o.arp_exchange(t + 0.5, c, lan.gateway)
            o.https(t + 0.8, c, "www.example.com")
    # victims: ARP for 192.168.0.1 works, but DNS to 8.8.8.8 through it times out and SYNs go unanswered
    for j, v in enumerate(victims):
        t = t0 + 40.0 + j * 6.0
        o.arp_exchange(t, v, home)
        for k in range(4):
            tq = t + 1.0 + k * 6.0
            _, qid, sport = o.dns(tq, v, rng.choice(["www.example.com", "docs.example.org"]), resolver="8.8.8.8", answered=False)
            o.dns_retry(tq + 1.0, v, "www.example.com", qid, sport, resolver="8.8.8.8")
            o.dns_retry(tq + 4.0, v, "www.example.com", qid, sport, resolver="8.8.8.8")
        s = TcpSession(o.cap, v, lan.server("www.example.com"), o.port(), 443, 0.03, t + 26.0)
        s.syn_only(retries=(1.0, 2.0, 4.0))
    return label("Second DHCP server from a home router", "Someone plugged a home router into the office LAN with DHCP enabled; clients now receive two offers and the ones that take the 192.168.0.x lease lose internet and DNS.",
                 expected=[("dhcp.multiple_servers", "misconfig")], must_not=["dns.hijack", "arp.spoofing"])


def sc_dhcp_no_server(o: Office) -> dict:
    t0 = o.t0
    lan, rng = o.lan, o.rng
    o.background(t0, 120, rate=0.25, clients=lan.clients[5:])
    for i, c in enumerate(lan.clients[:4]):
        t = t0 + 1.0 + i * 3.0
        xid = rng.getrandbits(32)
        for d in (0.0, 4.0, 8.0, 16.0, 32.0):
            disc = dhcp_msg(1, xid, c.mac, 1, hostname=c.name, param_req=(1, 3, 6, 15, 51))
            o.udp(t + d * rng.uniform(0.9, 1.1), "0.0.0.0", "255.255.255.255", 68, 67, disc, src_mac=c.mac, dst_mac=BROADCAST_MAC)
        # link-local fallback
        ll = f"169.254.{rng.randrange(1, 254)}.{rng.randrange(1, 254)}"
        tp = o.arp_probe(t + 62.0, c.mac, ll, n=3)
        o.udp(tp + 0.5, Host(c.name, c.mac, ll), "255.255.255.255", 137, 137, b"\x80\x1a\x01\x10\x00\x01\x00\x00\x00\x00\x00\x00 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x20\x00\x01", src_mac=c.mac, dst_mac=BROADCAST_MAC)
        lan.add_host(Host(c.name, c.mac, ll), client=False)
    return label("No DHCP server", "The DHCP server is down: laptops broadcast DISCOVERs with growing backoff, get no offer, and fall back to 169.254.x.x link-local addresses.",
                 expected=[("dhcp.no_server", "fault")], must_not=["dhcp.rogue", "dhcp.multiple_servers", "dhcp.starvation"])


def sc_routing_loop(o: Office) -> dict:
    t0 = o.t0
    lan, rng = o.lan, o.rng
    router_b = Host("router-b", "00:0c:29:7d:51:aa", "192.168.1.254")   # other side is 10.0.0.2
    lan.add_host(router_b, client=False)
    o.background(t0, 60, rate=0.3, exclude={lan.clients[0].ip})
    c = lan.clients[0]
    target = "198.51.100.99"
    o.dns(t0 + 1.0, c, "legacy.example.io", answer_ip=target)
    t = t0 + 1.2
    for n in range(8):
        if n % 2 == 0:
            l4 = icmp_echo(True, 0x4a21, n // 2 + 1, b"\x10" * 56)
            proto = PROTO_ICMP
        else:
            l4 = udp_dgram(c.ip, target, 50000 + n, 5060, b"OPTIONS sip:legacy.example.io SIP/2.0\r\n\r\n")
            proto = PROTO_UDP
        ip_id = o.cap.next_ip_id(c.ip)
        first = ipv4(c.ip, target, proto, l4, ttl=64, ip_id=ip_id, df=proto == PROTO_UDP)
        o.cap.ip(t, first, c.ip, target)
        tt = t + 0.0004
        ttl = 63
        last = first
        while ttl >= 1:
            pkt = ipv4(c.ip, target, proto, l4, ttl=ttl, ip_id=ip_id, df=proto == PROTO_UDP)
            o.cap.ip(tt, pkt, c.ip, target, src_mac=lan.gateway.mac, dst_mac=router_b.mac)
            last = pkt
            tt += rng.uniform(0.0006, 0.0012)
            ttl -= 2
        exc_src = "10.0.0.2"
        exc = ipv4(exc_src, c.ip, PROTO_ICMP, icmp_time_exceeded(last), ttl=63, ip_id=o.cap.next_ip_id(exc_src), df=False)
        o.cap.ip(tt + 0.0005, exc, exc_src, c.ip, src_mac=router_b.mac, dst_mac=c.mac)
        t += rng.uniform(1.0, 1.1)
    return label("Routing loop between two routers", "Packets to 198.51.100.99 bounce between the office router and a second router until their TTL runs out, so the same packet is seen over and over and the sender gets ICMP time exceeded.",
                 expected=[("icmp.routing_loop", "fault")], must_not=["scan.port", "icmp.redirect"])


def sc_pcapng_office(o: Office) -> dict:
    t0 = o.t0
    o.dhcp_dora(t0 + 0.2, o.lan.clients[9])
    o.background(t0 + 1.0, 25, rate=0.5)
    return label("Clean office (pcapng)", "A short healthy office capture saved in pcapng format.", clean=True)


SCENARIOS: list[tuple[str, Callable[[Office], dict], bool]] = [
    ("clean_office.pcap", sc_clean_office, False),
    ("busy_but_healthy.pcap", sc_busy_but_healthy, False),
    ("lossy_link.pcap", sc_lossy_link, False),
    ("connection_refused.pcap", sc_connection_refused, False),
    ("server_down_timeouts.pcap", sc_server_down_timeouts, False),
    ("zero_window.pcap", sc_zero_window, False),
    ("slow_server.pcap", sc_slow_server, False),
    ("high_latency.pcap", sc_high_latency, False),
    ("mtu_blackhole.pcap", sc_mtu_blackhole, False),
    ("mtu_frag_needed.pcap", sc_mtu_frag_needed, False),
    ("ip_conflict.pcap", sc_ip_conflict, False),
    ("dns_failure.pcap", sc_dns_failure, False),
    ("dhcp_misconfig_two_routers.pcap", sc_dhcp_two_routers, False),
    ("dhcp_no_server.pcap", sc_dhcp_no_server, False),
    ("routing_loop.pcap", sc_routing_loop, False),
    ("pcapng_office.pcapng", sc_pcapng_office, True),
]


# ---------------------------------------------------------------------------
# malformed files
# ---------------------------------------------------------------------------

def _pcap_header() -> bytes:
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)


def _rec(ts: float, frame: bytes, caplen: int | None = None, wirelen: int | None = None) -> bytes:
    sec = int(ts)
    usec = int(round((ts - sec) * 1e6))
    caplen = len(frame) if caplen is None else caplen
    wirelen = caplen if wirelen is None else wirelen
    return struct.pack("<IIII", sec, usec, caplen, wirelen) + frame


def generate_malformed(outdir: str, seed: int) -> dict:
    rng = random.Random(seed + 7)
    mdir = os.path.join(outdir, "malformed")
    os.makedirs(mdir, exist_ok=True)
    labels = {}

    def put(name: str, data: bytes, title: str, story: str) -> None:
        with open(os.path.join(mdir, name), "wb") as fh:
            fh.write(data)
        labels[f"malformed/{name}"] = label(title, story, malformed=True)

    # a small valid capture to cut and corrupt
    o = Office(seed + 11)
    o.background(o.t0, 5, rate=2.0)
    frames = o.cap.sorted_frames()
    good = _pcap_header() + b"".join(_rec(ts, fr) for ts, fr in frames)
    put("truncated.pcap", good[: len(good) - len(frames[-1][1]) // 2],
        "Truncated capture", "A valid capture that was cut off in the middle of its last record (for example a crashed sniffer).")
    put("bad_magic.pcap", bytes(rng.getrandbits(8) for _ in range(4096)),
        "Not a capture", "4 KiB of random bytes with a .pcap name.")
    put("huge_caplen.pcap", _pcap_header() + _rec(o.t0, frames[0][1]) + struct.pack("<IIII", int(o.t0), 0, 0x7FFFFFFF, 0x7FFFFFFF) + b"\x00" * 64,
        "Absurd record length", "A record header that claims a 2 GiB packet; the reader must not try to allocate it.")
    put("zero_length.pcap", b"", "Empty file", "A zero-byte file.")

    # frames with broken headers inside a valid file
    lan = Lan()
    c, gw = lan.clients[0], lan.gateway
    bad = []
    ihl_bad = bytearray(ipv4(c.ip, gw.ip, PROTO_UDP, udp_dgram(c.ip, gw.ip, 4000, 53, dns_query(1, "example.com"))))
    ihl_bad[0] = 0x42                                             # IHL = 2 (< 5)
    bad.append(lan.frame(bytes(ihl_bad), c.ip, gw.ip))
    tcp_bad = bytearray(ipv4(c.ip, "93.184.216.34", PROTO_TCP, tcp_seg(c.ip, "93.184.216.34", 5000, 443, 1, 0, "S")))
    tcp_bad[20 + 12] = 0xF0                                        # data offset 15 words = 60 bytes, frame has 20
    bad.append(lan.frame(bytes(tcp_bad), c.ip, "93.184.216.34"))
    self_ptr = struct.pack("!HHHHHH", 7, 0x8180, 1, 1, 0, 0) + b"\xc0\x0c" + struct.pack("!HH", 1, 1) + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x01\x02\x03\x04"
    bad.append(lan.frame(ipv4(gw.ip, c.ip, PROTO_UDP, udp_dgram(gw.ip, c.ip, 53, 4001, self_ptr)), gw.ip, c.ip))
    dh = bytearray(dhcp_msg(2, 1, c.mac, 2, yiaddr=c.ip, server_id=gw.ip, routers=[gw.ip], dns=[gw.ip], lease=3600, mask="255.255.255.0"))
    cut = dh[: 240 + 3]
    cut += bytes([3, 200]) + b"\x00" * 10                        # option 3 claims 200 bytes, only 10 follow
    bad.append(lan.frame(ipv4(gw.ip, "255.255.255.255", PROTO_UDP, udp_dgram(gw.ip, "255.255.255.255", 67, 68, bytes(cut)), df=False), gw.ip, "255.255.255.255"))
    bad.append(arp_frame(1, c.mac, c.ip, ZERO_MAC, gw.ip)[:30])    # truncated ARP
    for _ in range(4):
        bad.append(bytes(rng.getrandbits(8) for _ in range(rng.randrange(14, 120))))
    bad.append(ether(c.mac, gw.mac, 0x0800, b"\x45\x00\x00"))     # IPv4 header cut after 3 bytes
    bad.append(ether(c.mac, gw.mac, 0x86DD, b"\x60" + b"\x00" * 10))  # short IPv6
    good_frames = frames[:6]
    data = _pcap_header()
    t = o.t0
    for i, fr in enumerate(bad):
        if i < len(good_frames):
            data += _rec(t, good_frames[i][1])
            t += 0.01
        data += _rec(t, fr)
        t += 0.01
    put("corrupt_packets.pcap", data, "Corrupt packets inside a valid file",
        "A well-formed pcap whose frames have broken headers: bad IHL, TCP data offset past the end, a DNS compression pointer loop, a DHCP option running off the end, a truncated ARP and random garbage.")

    gz_path = os.path.join(mdir, "compressed_padding.pcap.gz")
    with open(gz_path, "wb") as raw_gz, gzip.GzipFile(fileobj=raw_gz, mode="wb", compresslevel=9, mtime=0, filename="") as gz:  # deterministic bytes
        gz.write(_pcap_header() + _rec(o.t0, frames[0][1]))
        chunk = b"\x00" * (1024 * 1024)
        for _ in range(50):
            gz.write(chunk)
    labels["malformed/compressed_padding.pcap.gz"] = label(
        "Decompression bomb-ish", "A tiny gzip that expands to a valid pcap header followed by 50 MB of zero bytes; the reader must stop at its decompression cap.", malformed=True)
    return labels


# ---------------------------------------------------------------------------
# driver
# ---------------------------------------------------------------------------

def generate(outdir: str, seed: int = 1, only: set[str] | None = None, verbose: bool = True) -> dict:
    """Generate the benign/fault/misconfig scenarios into ``outdir``; returns the labels dict."""
    os.makedirs(outdir, exist_ok=True)
    labels = {}
    for i, (fname, fn, ng) in enumerate(SCENARIOS):
        if only and fname not in only:
            continue
        o = Office(seed * 1000 + i)
        lab = fn(o)
        n = o.cap.write(os.path.join(outdir, fname), pcapng=ng)
        labels[fname] = lab
        if verbose:
            print(f"  {fname:36s} {n:6d} packets  {os.path.getsize(os.path.join(outdir, fname)) / 1024:8.1f} KiB", file=sys.stderr)
    return labels


def generate_all(outdir: str = "samples", seed: int = 1, verbose: bool = True) -> dict:
    """Write every sample (including attack scenarios when available) and ``labels.json``."""
    labels = generate(outdir, seed, verbose=verbose)
    labels.update(generate_malformed(outdir, seed))
    try:
        scenarios_attack = importlib.import_module("faultline.lab.scenarios_attack")
    except ModuleNotFoundError as e:
        if e.name != "faultline.lab.scenarios_attack":
            raise
        scenarios_attack = None
    if scenarios_attack is not None:
        extra = scenarios_attack.generate(outdir, seed)
        if extra:
            labels.update(extra)
    with open(os.path.join(outdir, "labels.json"), "w") as fh:
        json.dump(labels, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return labels


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "samples"
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    labs = generate_all(out, seed)
    print(f"wrote {len(labs)} labelled files to {out}/", file=sys.stderr)
