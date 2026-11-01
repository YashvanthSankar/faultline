"""Labelled *attack-pattern* scenarios for the benchmark and the demo.

These generators write synthetic frames into .pcap files: offline test data
that lets the detectors be checked against known ground truth. Nothing here
opens a socket or sends a packet. Every scenario reuses the office LAN and
benign background traffic from :mod:`faultline.lab.scenarios` so the
detectors have to find the attack inside normal traffic.

Credentials that appear in payloads are obviously fake demo values.
"""

from __future__ import annotations

import base64
import os
import string

from faultline.lab.craft import (
    BROADCAST_MAC, PROTO_ICMP, PROTO_TCP, PROTO_UDP, ZERO_MAC,
    Host, TcpSession,
    arp_frame, dhcp_msg, dns_query, dns_response, http_request, http_response,
    icmp_echo, icmp_unreachable, ipv4, tcp_seg, tls_alert, tls_app_data, tls_client_hello,
    tls_server_hello, udp_dgram,
)
from faultline.lab.scenarios import Office, label

# A device the office does not know about (VirtualBox OUI, typical of a VM)
INTRUDER_MAC = "08:00:27:3a:66:9e"
INTRUDER_IP = "192.168.1.66"
BANK = "login.example-bank.com"
BANK_REAL_IP = "203.0.113.50"


def _intruder(o: Office) -> Host:
    return o.lan.add_host(Host("unknown-device", INTRUDER_MAC, INTRUDER_IP), client=False)


def _tcp(o: Office, ts: float, src: str, dst: str, sport: int, dport: int, flags: str, seq: int = 0, ack: int = 0,
         ttl: int = 64, win: int = 64240, payload: bytes = b"", src_mac=None, dst_mac=None, **opts) -> float:
    seg = tcp_seg(src, dst, sport, dport, seq, ack, flags, win=win, payload=payload, **opts)
    pkt = ipv4(src, dst, PROTO_TCP, seg, ttl=ttl, ip_id=o.cap.next_ip_id(src))
    return o.cap.ip(ts, pkt, src, dst, src_mac=src_mac, dst_mac=dst_mac)


def _udp(o: Office, ts: float, src: str, dst: str, sport: int, dport: int, payload: bytes, ttl: int = 64,
         src_mac=None, dst_mac=None) -> bytes:
    pkt = ipv4(src, dst, PROTO_UDP, udp_dgram(src, dst, sport, dport, payload), ttl=ttl, ip_id=o.cap.next_ip_id(src))
    o.cap.ip(ts, pkt, src, dst, src_mac=src_mac, dst_mac=dst_mac)
    return pkt


# --------------------------------------------------------------------------- #
# scenarios
# --------------------------------------------------------------------------- #


def sc_arp_spoofing(o: Office) -> dict:
    lan, rng, t0 = o.lan, o.rng, o.t0
    intr = _intruder(o)
    victim = lan.clients[3]  # .15
    gw = lan.gateway
    o.background(t0 + 0.5, 150, rate=0.4, exclude={victim.ip})
    # the intruder's own, ordinary presence on the LAN
    o.arp_exchange(t0 + 5.0, intr, gw)
    o.dns(t0 + 5.2, intr, "www.example.com")
    # victim behaves normally first: resolves the router legitimately
    o.arp_exchange(t0 + 8.0, victim, gw)
    o.https(t0 + 9.0, victim, "docs.example.org")
    # poisoning: unsolicited replies to both sides, every ~1.5 s
    t = t0 + 20.0
    end = t0 + 140.0
    while t < end:
        o.cap.add(t, arp_frame(2, intr.mac, gw.ip, victim.mac, victim.ip))  # "router is at <intruder>" → victim
        o.cap.add(t + 0.0004, arp_frame(2, intr.mac, victim.ip, gw.mac, gw.ip))  # "victim is at <intruder>" → router
        t += rng.uniform(1.2, 1.8)
    # the real router still answers when the victim asks (MAC flip-flop)
    for k in range(4):
        o.arp_exchange(t0 + 35.0 + k * 25.0, victim, gw)
    # victim's internet traffic now leaves towards the intruder's MAC
    real_gw_mac = gw.mac
    gw.mac = intr.mac
    try:
        for k, name in enumerate(["mail.example.net", "chat.example-apps.com", "www.example.com", "api.example.io",
                                  "docs.example.org", "git.example.dev"]):
            o.https(t0 + 30.0 + k * 17.0, victim, name)
    finally:
        gw.mac = real_gw_mac
    return label(
        "ARP spoofing of the router (man-in-the-middle)",
        "An unknown device keeps telling one PC that it is the router, and telling the router that it is that PC, "
        "so the PC's traffic flows through the intruder.",
        expected=[("arp.duplicate_ip", "attack")],
    )


def sc_port_scan(o: Office) -> dict:
    lan, rng, t0 = o.lan, o.rng, o.t0
    intr = _intruder(o)
    target = lan.clients[4]  # .20 file server
    o.background(t0 + 0.5, 90, rate=0.4, exclude={target.ip})
    o.arp_exchange(t0 + 29.9, intr, target)
    open_ports = {22, 80, 443, 445}
    ports = list(range(1, 1025))
    rng.shuffle(ports)
    t = t0 + 30.0
    sport = 41234
    for p in ports:
        isn = rng.getrandbits(32)
        _tcp(o, t, intr.ip, target.ip, sport, p, "S", seq=isn, ttl=64, win=1024, mss=1460)
        rt = t + rng.uniform(0.0002, 0.0009)
        if p in open_ports:
            sisn = rng.getrandbits(32)
            _tcp(o, rt, target.ip, intr.ip, p, sport, "SA", seq=sisn, ack=isn + 1, ttl=64, win=64240, mss=1460)
            _tcp(o, rt + 0.0001, intr.ip, target.ip, sport, p, "R", seq=isn + 1, ttl=64, win=0)
        else:
            _tcp(o, rt, target.ip, intr.ip, p, sport, "RA", seq=0, ack=isn + 1, ttl=64, win=0)
        t += rng.uniform(0.002, 0.005)
    # stealth probes: FIN, NULL and Xmas
    t += 1.0
    for flags in ("F", "", "FPU"):
        for p in (21, 22, 23, 25, 80, 110, 139, 443, 445, 3389):
            seq = rng.getrandbits(32)
            _tcp(o, t, intr.ip, target.ip, 51000 + p, p, flags, seq=seq, ttl=64, win=1024)
            if p not in open_ports:
                _tcp(o, t + 0.0004, target.ip, intr.ip, p, 51000 + p, "RA", seq=0, ack=seq + (1 if "F" in flags else 0), ttl=64, win=0)
            t += rng.uniform(0.003, 0.01)
    # UDP scan: closed ports answer with ICMP port unreachable
    t += 1.0
    for p in (53, 67, 69, 111, 123, 137, 161, 500, 514, 520, 1900, 5353):
        q = _udp(o, t, intr.ip, target.ip, 60001, p, b"")
        if p not in (123,):
            un = ipv4(target.ip, intr.ip, PROTO_ICMP, icmp_unreachable(3, q), ttl=64, ip_id=o.cap.next_ip_id(target.ip), df=False)
            o.cap.ip(t + 0.0005, un, target.ip, intr.ip)
        t += rng.uniform(0.05, 0.2)
    return label(
        "Port scan against the file server",
        "An unknown device quickly knocks on 1,024 ports of the office file server (plus stealth FIN/NULL/Xmas and UDP probes) "
        "to find which services are open.",
        expected=[("scan.port", "attack")],
        must_not=["tcp.refused"],
    )


def sc_host_sweep(o: Office) -> dict:
    lan, rng, t0 = o.lan, o.rng, o.t0
    intr = _intruder(o)
    o.background(t0 + 0.5, 80, rate=0.4)
    live = {h.ip: h for h in lan.hosts.values() if h.mac and h.ip != intr.ip}
    t = t0 + 20.0
    for last in range(1, 255):
        ip = f"192.168.1.{last}"
        if ip == intr.ip:
            continue
        o.cap.add(t, arp_frame(1, intr.mac, intr.ip, ZERO_MAC, ip))
        if ip in live:
            h = live[ip]
            o.cap.add(t + rng.uniform(0.0003, 0.002), arp_frame(2, h.mac, h.ip, intr.mac, intr.ip))
        t += rng.uniform(0.004, 0.012)
    t += 0.5
    for i, ip in enumerate(sorted(live, key=lambda s: int(s.rsplit(".", 1)[1]))):
        o.ping(t, intr, ip, 0x4b1d, i + 1, rtt=rng.uniform(0.0005, 0.003))
        t += rng.uniform(0.01, 0.03)
    t += 0.5
    for ip in sorted(live, key=lambda s: int(s.rsplit(".", 1)[1])):
        isn = rng.getrandbits(32)
        sp = 40000 + rng.randrange(0, 20000)
        _tcp(o, t, intr.ip, ip, sp, 445, "S", seq=isn, win=1024, mss=1460)
        if ip.endswith((".20", ".21", ".30")):
            sisn = rng.getrandbits(32)
            _tcp(o, t + 0.0007, ip, intr.ip, 445, sp, "SA", seq=sisn, ack=isn + 1, win=64240, mss=1460)
            _tcp(o, t + 0.0008, intr.ip, ip, sp, 445, "R", seq=isn + 1, win=0)
        else:
            _tcp(o, t + 0.0007, ip, intr.ip, 445, sp, "RA", seq=0, ack=isn + 1, win=0)
        t += rng.uniform(0.005, 0.02)
    return label(
        "Network sweep: mapping every device",
        "An unknown device asks for every address from .1 to .254, pings each device that answers, then checks which ones "
        "have Windows file sharing (port 445) open.",
        expected=[("arp.scan", "attack")],
    )


def sc_dns_hijack(o: Office) -> dict:
    lan, rng, t0 = o.lan, o.rng, o.t0
    intr = _intruder(o)
    gw = lan.gateway
    victims = [lan.clients[0], lan.clients[3], lan.clients[7]]
    o.background(t0 + 0.5, 120, rate=0.4)
    t = t0 + 15.0
    names = [BANK, BANK, "mail.example.net", BANK, "accounts.example-bank.com", BANK]
    for i, name in enumerate(names):
        v = victims[i % len(victims)]
        qid, sport = o.qid(), o.port()
        _udp(o, t, v.ip, gw.ip, sport, 53, dns_query(qid, name, "A"))
        # forged answer: spoofs the resolver's IP but comes from the intruder's NIC, implausibly fast
        forged = dns_response(qid, name, "A", [("A", INTRUDER_IP, 30)], aa=True)
        _udp(o, t + rng.uniform(0.0002, 0.0005), gw.ip, v.ip, 53, sport, forged, src_mac=intr.mac, dst_mac=v.mac)
        # the genuine answer arrives later, with the real address
        real_ip = BANK_REAL_IP if "bank" in name else lan.server(name).ip
        real = dns_response(qid, name, "A", [("A", real_ip, 300)])
        _udp(o, t + rng.uniform(0.012, 0.025), gw.ip, v.ip, 53, sport, real)
        # the victim believes the first answer and connects to the intruder
        if "bank" in name:
            s = TcpSession(o.cap, v, intr, o.port(), 443, 0.0012, t + 0.03)
            s.handshake()
            s.client_send(tls_client_hello(name, rng=rng))
            s.server_send(tls_server_hello(rng=rng, extra_len=2400))
            s.client_send(tls_app_data(600, rng))
            s.server_send(tls_app_data(5000, rng))
            s.close()
        t += rng.uniform(12.0, 18.0)
    # an answer from a server the client never asked
    v = victims[1]
    qid, sport = o.qid(), o.port()
    _udp(o, t, v.ip, gw.ip, sport, 53, dns_query(qid, BANK, "A"))
    _udp(o, t + 0.0003, intr.ip, v.ip, 53, sport, dns_response(qid, BANK, "A", [("A", INTRUDER_IP, 30)]))
    _udp(o, t + 0.018, gw.ip, v.ip, 53, sport, dns_response(qid, BANK, "A", [("A", BANK_REAL_IP, 300)]))
    return label(
        "DNS hijacking: forged answers for the bank",
        "Whenever someone looks up the bank's login site, a forged answer pointing to a device inside the office arrives "
        "before the real one, so people are silently sent to the intruder.",
        expected=[("dns.hijack", "attack")],
    )


def _rogue_dora(o: Office, ts: float, client: Host, rogue: Host, rogue_ip_offer: str) -> float:
    """DISCOVER → rogue OFFER (fast) + legit OFFER (slower) → client takes the rogue lease."""
    rng, gw = o.rng, o.lan.gateway
    xid = rng.getrandbits(32)
    bcast = "255.255.255.255"
    pr = (1, 3, 6, 15, 51, 58, 59)
    _udp(o, ts, "0.0.0.0", bcast, 68, 67, dhcp_msg(1, xid, client.mac, 1, hostname=client.name, param_req=pr),
         src_mac=client.mac, dst_mac=BROADCAST_MAC)
    t_r = ts + rng.uniform(0.0008, 0.002)
    _udp(o, t_r, rogue.ip, bcast, 67, 68,
         dhcp_msg(2, xid, client.mac, 2, yiaddr=rogue_ip_offer, siaddr=rogue.ip, server_id=rogue.ip,
                  routers=[rogue.ip], dns=[rogue.ip], lease=3600, mask="255.255.255.0"),
         src_mac=rogue.mac, dst_mac=BROADCAST_MAC)
    t_l = ts + rng.uniform(0.02, 0.06)
    _udp(o, t_l, gw.ip, bcast, 67, 68,
         dhcp_msg(2, xid, client.mac, 2, yiaddr=client.ip, siaddr=gw.ip, server_id=gw.ip,
                  routers=[gw.ip], dns=[gw.ip], lease=86400, mask="255.255.255.0"),
         src_mac=gw.mac, dst_mac=BROADCAST_MAC)
    t = t_l + rng.uniform(0.001, 0.01)
    _udp(o, t, "0.0.0.0", bcast, 68, 67,
         dhcp_msg(1, xid, client.mac, 3, server_id=rogue.ip, requested_ip=rogue_ip_offer, hostname=client.name, param_req=pr),
         src_mac=client.mac, dst_mac=BROADCAST_MAC)
    t += rng.uniform(0.001, 0.004)
    _udp(o, t, rogue.ip, bcast, 67, 68,
         dhcp_msg(2, xid, client.mac, 5, yiaddr=rogue_ip_offer, siaddr=rogue.ip, server_id=rogue.ip,
                  routers=[rogue.ip], dns=[rogue.ip], lease=3600, mask="255.255.255.0"),
         src_mac=rogue.mac, dst_mac=BROADCAST_MAC)
    return t


def sc_rogue_dhcp(o: Office) -> dict:
    lan, rng, t0 = o.lan, o.rng, o.t0
    rogue = _intruder(o)
    o.background(t0 + 0.5, 120, rate=0.35)
    # a normal lease first (only the real router answers)
    o.dhcp_dora(t0 + 3.0, lan.clients[2])
    t = t0 + 25.0
    for k, c in enumerate((lan.clients[8], lan.clients[9], lan.clients[10])):
        t = _rogue_dora(o, t, c, rogue, f"192.168.1.{150 + k}")
        t += rng.uniform(20.0, 35.0)
    return label(
        "Rogue DHCP server",
        "An unknown device answers address requests faster than the real router and hands out itself as the router and DNS "
        "server, so new laptops send all their traffic through it.",
        expected=[("dhcp.multiple_servers", "attack")],
    )


def sc_syn_flood(o: Office) -> dict:
    lan, rng, t0 = o.lan, o.rng, o.t0
    server = lan.clients[4]  # .20 hosts the intranet web server on :80
    o.background(t0 + 0.5, 60, rate=0.4, exclude={server.ip})
    # healthy intranet visits before the flood
    for k in range(3):
        s = TcpSession(o.cap, lan.clients[k], server, o.port(), 80, 0.0012, t0 + 5.0 + k * 3)
        s.handshake()
        s.client_send(http_request("GET", "intranet.office.lan", "/"))
        s.server_send(http_response(200, "OK", body_len=4000), think=0.01)
        s.close()
    t = t0 + 25.0
    end = t + 8.0
    n = 0
    while t < end:
        src = f"{rng.choice([23, 31, 45, 61, 77, 89, 101, 117, 141, 176, 185, 193, 212])}.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(1, 255)}"
        sp = rng.randrange(1024, 65535)
        isn = rng.getrandbits(32)
        _tcp(o, t, src, server.ip, sp, 80, "S", seq=isn, ttl=rng.randrange(30, 250), win=rng.choice([512, 1024, 5840, 65535]))
        if n % 3 == 0:  # the server only manages to answer some of them
            _tcp(o, t + 0.0002, server.ip, src, 80, sp, "SA", seq=rng.getrandbits(32), ack=isn + 1, win=64240, mss=1460)
        n += 1
        t += rng.expovariate(450.0)
    # a legitimate user during the flood can't connect
    s = TcpSession(o.cap, lan.clients[6], server, o.port(), 80, 0.0012, t0 + 28.0)
    s.syn_only(retries=(1.0, 2.0))
    return label(
        "SYN flood against the intranet server",
        "Thousands of connection requests per second from random, spoofed internet addresses overwhelm the intranet web "
        "server, so real staff can't open it.",
        expected=[("flood.syn", "attack")],
    )


def sc_mitm_chain(o: Office) -> dict:
    lan, rng, t0 = o.lan, o.rng, o.t0
    rogue = _intruder(o)
    victim = lan.clients[8]
    o.background(t0 + 0.5, 110, rate=0.35, exclude={victim.ip})
    t = _rogue_dora(o, t0 + 10.0, victim, rogue, "192.168.1.150")
    vict = Host(victim.name, victim.mac, "192.168.1.150")
    lan.add_host(vict, client=False)
    t += 1.0
    # the victim now asks the intruder for every name
    for name, answer in (("www.example.com", "93.184.216.34"), (BANK, INTRUDER_IP), ("mail.example.net", "203.0.113.25"),
                         (BANK, INTRUDER_IP), ("intranet-portal.example-bank.com", INTRUDER_IP)):
        qid, sport = o.qid(), o.port()
        _udp(o, t, vict.ip, rogue.ip, sport, 53, dns_query(qid, name, "A"))
        _udp(o, t + rng.uniform(0.0004, 0.001), rogue.ip, vict.ip, 53, sport, dns_response(qid, name, "A", [("A", answer, 60)]))
        if answer == INTRUDER_IP:
            s = TcpSession(o.cap, vict, rogue, o.port(), 80, 0.001, t + 0.01)
            s.handshake()
            auth = base64.b64encode(b"alice:hunter2").decode()
            s.client_send(http_request("POST", name, "/login", headers={"Authorization": f"Basic {auth}"}))
            s.server_send(http_response(302, "Found", body_len=0, headers={"Location": "/account"}), think=0.004)
            s.close()
        t += rng.uniform(8.0, 15.0)
    return label(
        "Man-in-the-middle chain: rogue DHCP → fake DNS → stolen login",
        "A rogue DHCP server makes a laptop use it as router and DNS server, then answers the bank's name with its own "
        "address and collects the password sent over plain HTTP.",
        expected=[("dhcp.multiple_servers", "attack"), ("dns.hijack", "attack"), ("cred.cleartext", "misconfig")],
    )


def sc_cleartext_creds(o: Office) -> dict:
    lan, rng, t0 = o.lan, o.rng, o.t0
    o.background(t0 + 0.5, 100, rate=0.4)
    nas = lan.clients[4]
    admin = lan.clients[7]
    # FTP login to the NAS
    s = TcpSession(o.cap, admin, nas, o.port(), 21, 0.001, t0 + 10.0)
    s.handshake()
    s.server_send(b"220 NAS FTP server ready\r\n", think=0.01)
    s.client_send(b"USER alice\r\n")
    s.server_send(b"331 Password required\r\n", think=0.002)
    s.client_send(b"PASS hunter2\r\n")
    s.server_send(b"230 Login successful\r\n", think=0.01)
    s.client_send(b"QUIT\r\n")
    s.close("s")
    # Telnet to the router's management interface
    s = TcpSession(o.cap, admin, lan.gateway, o.port(), 23, 0.001, t0 + 30.0)
    s.handshake()
    s.server_send(b"\r\nOfficeRouter login: ", think=0.02)
    s.client_send(b"admin\r\n")
    s.server_send(b"Password: ", think=0.005)
    s.client_send(b"hunter2\r\n")
    s.server_send(b"\r\nWelcome to OfficeRouter\r\n# ", think=0.05)
    s.close("c", at=s.now + 4.0)
    # HTTP Basic auth to an internal admin panel
    printer = lan.clients[6]
    auth = base64.b64encode(b"alice:hunter2").decode()
    s = TcpSession(o.cap, admin, printer, o.port(), 8080, 0.001, t0 + 55.0)
    s.handshake()
    s.client_send(http_request("GET", "printer.office.lan:8080", "/admin/settings", headers={"Authorization": f"Basic {auth}"}))
    s.server_send(http_response(200, "OK", body_len=3500), think=0.03)
    s.close()
    return label(
        "Passwords sent in plain text",
        "An admin logs in to the NAS over FTP, to the router over Telnet and to the printer's admin page over plain HTTP: "
        "anyone on the network could read those passwords.",
        expected=[("cred.cleartext", "misconfig")],
    )


def _b32(rng, n: int) -> str:
    alphabet = string.ascii_lowercase + "234567"
    return "".join(rng.choice(alphabet) for _ in range(n))


def sc_dns_tunnel(o: Office) -> dict:
    lan, rng, t0 = o.lan, o.rng, o.t0
    o.background(t0 + 0.5, 170, rate=0.4)
    host = lan.clients[9]
    t = t0 + 5.0
    for i in range(360):
        name = f"{_b32(rng, 52)}.{_b32(rng, 12)}.{i:04x}.t.example-c2.net"
        qid, sport = o.qid(), o.port()
        _udp(o, t, host.ip, lan.dns, sport, 53, dns_query(qid, name, "TXT"))
        payload = base64.b64encode(bytes(rng.getrandbits(8) for _ in range(rng.randrange(40, 120)))).decode()
        _udp(o, t + rng.uniform(0.03, 0.06), lan.dns, host.ip, 53, sport, dns_response(qid, name, "TXT", [("TXT", payload, 0)]))
        t += rng.uniform(0.35, 0.55)
    return label(
        "Data hidden inside DNS lookups (DNS tunnelling)",
        "One PC sends hundreds of lookups for long random-looking names under one domain, at a steady rhythm: the "
        "typical sign of malware smuggling data out through DNS.",
        expected=[("dns.tunneling", "attack")],
    )


def sc_outage_vs_attack(o: Office) -> dict:
    lan, rng, t0 = o.lan, o.rng, o.t0
    intr = _intruder(o)
    o.background(t0 + 0.5, 30, rate=0.4)
    # DNS outage: the resolver stops answering for ~70 s
    t = t0 + 35.0
    while t < t0 + 105.0:
        c = rng.choice(lan.clients)
        name = rng.choice(["www.example.com", "docs.example.org", "mail.example.net", "api.example.io"])
        _, qid, sport = o.dns(t, c, name, answered=False)
        o.dns_retry(t + 1.0, c, name, qid, sport)
        o.dns_retry(t + 3.0, c, name, qid, sport)
        t += rng.uniform(1.5, 3.5)
    o.background(t0 + 110.0, 40, rate=0.4)
    # meanwhile, a quick port scan of the file server
    target = lan.clients[4]
    tt = t0 + 60.0
    for p in rng.sample(range(1, 2000), 300):
        isn = rng.getrandbits(32)
        _tcp(o, tt, intr.ip, target.ip, 45555, p, "S", seq=isn, win=1024, mss=1460)
        _tcp(o, tt + 0.0004, target.ip, intr.ip, p, 45555, "RA", seq=0, ack=isn + 1, win=0)
        tt += rng.uniform(0.003, 0.006)
    return label(
        "An outage and an attack at the same time",
        "The DNS server stops answering (a genuine fault) while, unrelated, an unknown device scans the file server "
        "(an attack): two different problems that look like one to users.",
        expected=[("dns.timeout", "fault"), ("scan.port", "attack")],
    )


def sc_tls_failures(o: Office) -> dict:
    lan, rng, t0 = o.lan, o.rng, o.t0
    o.background(t0 + 0.5, 100, rate=0.35)
    srv = lan.server("intranet-legacy.example.org")
    t = t0 + 12.0
    for k in range(5):
        c = lan.clients[k]
        s = TcpSession(o.cap, c, srv, o.port(), 443, 0.03, t)
        s.handshake()
        s.client_send(tls_client_hello("intranet-legacy.example.org", rng=rng))
        s.server_send(tls_server_hello(version=0x0303, selected=0x0303, rng=rng, extra_len=2600))
        # the client rejects the server's certificate (expired)
        s.client_send(tls_alert(2, 45))
        s.close("c", at=s.now + 0.002)
        t += rng.uniform(9.0, 16.0)
    return label(
        "Secure connections failing: expired certificate",
        "Every attempt to open the legacy intranet site is aborted by the browser because the site's certificate has expired.",
        expected=[("tls.failure", "misconfig")],
    )


def sc_web_bruteforce(o: Office) -> dict:
    lan, rng, t0 = o.lan, o.rng, o.t0
    intr = _intruder(o)
    o.background(t0 + 0.5, 90, rate=0.35)
    portal = lan.clients[4]
    t = t0 + 20.0
    for i in range(45):
        s = TcpSession(o.cap, intr, portal, o.port(), 80, 0.001, t)
        s.handshake()
        s.client_send(http_request("POST", "intranet.office.lan", "/login",
                                   headers={"Content-Type": "application/x-www-form-urlencoded"}, body=b"user=admin&pass=guess"))
        s.server_send(http_response(401, "Unauthorized", body_len=180), think=0.004)
        s.close()
        t = s.now + rng.uniform(0.2, 0.6)
    return label(
        "Password guessing against the intranet login",
        "One device tries to log in to the intranet 45 times in a row and is refused every time: a password-guessing attack.",
        expected=[("http.errors", "attack")],
    )


def sc_xss_payload(o: Office) -> dict:
    """Well-formed packets whose *text fields* carry HTML/JS, to prove reports escape them."""
    lan, rng, t0 = o.lan, o.rng, o.t0
    o.background(t0 + 0.5, 60, rate=0.4)
    c = lan.clients[2]
    o.dns(t0 + 10.0, c, "<script>alert(1)<\\/script>.example.com")
    o.dns(t0 + 11.0, c, "<img src=x onerror=alert(1)>.example.com")
    o.dhcp_dora(t0 + 20.0, lan.clients[5], hostname='"><img src=x onerror=alert(1)>')
    s = TcpSession(o.cap, c, lan.server("www.example.com"), o.port(), 80, 0.03, t0 + 30.0)
    s.handshake()
    s.client_send(http_request("GET", "<svg/onload=alert(1)>", "/<script>alert(2)</script>"))
    s.server_send(http_response(200, "OK", body_len=500), think=0.01)
    s.close()
    s = TcpSession(o.cap, c, lan.server("www.example.com"), o.port(), 443, 0.03, t0 + 40.0)
    s.handshake()
    s.client_send(tls_client_hello("x</script><script>alert(3)</script>", rng=rng))
    s.server_send(tls_server_hello(rng=rng, extra_len=2000))
    s.close()
    return label(
        "Hostile text inside packets (XSS test)",
        "Normal traffic, except that names inside DNS, DHCP, HTTP and TLS packets contain HTML/JavaScript; reports must "
        "show them as plain text and never run them.",
        clean=True,
    )


SCENARIOS = {
    "arp_spoofing.pcap": (sc_arp_spoofing, 101),
    "port_scan.pcap": (sc_port_scan, 102),
    "host_sweep.pcap": (sc_host_sweep, 103),
    "dns_hijack.pcap": (sc_dns_hijack, 104),
    "rogue_dhcp.pcap": (sc_rogue_dhcp, 105),
    "syn_flood.pcap": (sc_syn_flood, 106),
    "mitm_chain.pcap": (sc_mitm_chain, 107),
    "cleartext_creds.pcap": (sc_cleartext_creds, 108),
    "dns_tunnel.pcap": (sc_dns_tunnel, 109),
    "outage_vs_attack_mixed.pcap": (sc_outage_vs_attack, 110),
    "tls_failures.pcap": (sc_tls_failures, 111),
    "web_bruteforce.pcap": (sc_web_bruteforce, 112),
    "xss_payload.pcap": (sc_xss_payload, 113),
}


def generate(outdir: str, seed: int = 1, only: set[str] | None = None, verbose: bool = False) -> dict:
    os.makedirs(outdir, exist_ok=True)
    labels: dict = {}
    for name, (fn, offset) in SCENARIOS.items():
        if only and name not in only:
            continue
        o = Office(seed * 1000 + offset)
        lab = fn(o)
        if name == "xss_payload.pcap":
            lab["hostile_strings"] = True
        n = o.cap.write(os.path.join(outdir, name))
        labels[name] = lab
        if verbose:
            print(f"  {name:<32} {n:>6} packets")
    return labels
