"""Byte-level packet builders for the Faultline test-capture lab.

Everything here produces plain ``bytes`` and never touches a socket.  Frames
are collected into a :class:`Capture` and written to a ``.pcap`` file with
:class:`faultline.capture.writer.PcapWriter`.  Standard library only.

Layers (each returns ``bytes``; checksums are computed for you):

* L2:   :func:`ether`, :func:`arp_frame`
* L3:   :func:`ipv4`, :func:`ipv6`
* L4:   :func:`tcp_seg`, :func:`udp_dgram`, :func:`icmp_msg` (+ ICMP helpers)
* L7:   :func:`dns_query`, :func:`dns_response`, :func:`dhcp_msg`,
        :func:`http_request`, :func:`http_response`, :func:`tls_client_hello`,
        :func:`tls_server_hello`, :func:`tls_alert`, :func:`tls_app_data`,
        :func:`ntp_packet`
* Model: :class:`Host`, :class:`Lan` (the standard office LAN),
        :class:`Capture` (timeline + writer), :class:`TcpSession`
        (seq/ack tracking, loss injection, zero windows, resets).

Quick example::

    from faultline.lab.craft import Lan, Capture, TcpSession, tls_client_hello

    lan = Lan()
    cap = Capture(lan, seed=1)
    web = lan.server("www.example.com")               # 93.184.216.34
    s = TcpSession(cap, lan.clients[0], web, 51000, 443, rtt=0.03, start_ts=cap.t0)
    s.handshake()
    s.client_send(tls_client_hello("www.example.com"))
    s.server_send(3200)
    s.close()
    cap.write("out.pcap")

Timing convention: the capture point sits next to the client.  A client frame
is seen when the client sends it; the server's answer is seen about one RTT
later (plus jitter / think time).  All helpers keep timestamps causal.
"""

from __future__ import annotations

import ipaddress
import random
import struct
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from faultline.capture.writer import PcapNgWriter, PcapWriter

__all__ = [
    "mac_bytes", "ip_bytes", "inet_checksum",
    "ether", "arp_frame", "ipv4", "ipv6", "tcp_seg", "udp_dgram",
    "icmp_msg", "icmp_echo", "icmp_unreachable", "icmp_time_exceeded", "icmp_redirect",
    "dns_query", "dns_response", "dhcp_msg",
    "http_request", "http_response", "tls_client_hello", "tls_server_hello",
    "tls_alert", "tls_app_data", "ntp_packet",
    "Host", "Lan", "Capture", "TcpSession",
    "ETH_IPV4", "ETH_IPV6", "ETH_ARP", "BROADCAST_MAC",
]

ETH_IPV4 = 0x0800
ETH_ARP = 0x0806
ETH_IPV6 = 0x86DD
ETH_VLAN = 0x8100
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMPV6 = 58


# --------------------------------------------------------------------------
# primitives
# --------------------------------------------------------------------------

def mac_bytes(mac: str | bytes) -> bytes:
    """``"aa:bb:cc:dd:ee:ff"`` -> 6 bytes (bytes pass through)."""
    if isinstance(mac, (bytes, bytearray)):
        return bytes(mac)
    return bytes(int(p, 16) for p in mac.replace("-", ":").split(":"))


def ip_bytes(ip: str | bytes) -> bytes:
    """``"192.168.1.1"`` -> 4 bytes, ``"2001:db8::1"`` -> 16 bytes."""
    if isinstance(ip, (bytes, bytearray)):
        return bytes(ip)
    return ipaddress.ip_address(ip).packed


def inet_checksum(data: bytes) -> int:
    """RFC 1071 one's-complement checksum of ``data`` (odd length is padded)."""
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


# --------------------------------------------------------------------------
# L2
# --------------------------------------------------------------------------

def ether(src_mac: str, dst_mac: str, ethertype: int, payload: bytes, vlan: int | None = None) -> bytes:
    """Ethernet II frame. ``vlan`` adds an 802.1Q tag.

    >>> f = ether("00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff", 0x0800, b"x")
    >>> len(f)
    15
    """
    hdr = mac_bytes(dst_mac) + mac_bytes(src_mac)
    if vlan is not None:
        hdr += struct.pack("!HH", ETH_VLAN, vlan & 0x0FFF)
    return hdr + struct.pack("!H", ethertype) + payload


def arp_frame(op: int, sha: str, spa: str, tha: str, tpa: str,
              eth_src: str | None = None, eth_dst: str | None = None) -> bytes:
    """Complete Ethernet+ARP frame. ``op`` 1=request, 2=reply.

    Requests default to a broadcast Ethernet destination; replies are unicast
    to ``tha``.  ``arp_frame(1, mac, "192.168.1.10", "00:00:00:00:00:00", "192.168.1.1")``
    """
    body = struct.pack("!HHBBH", 1, ETH_IPV4, 6, 4, op)
    body += mac_bytes(sha) + ip_bytes(spa) + mac_bytes(tha) + ip_bytes(tpa)
    if eth_src is None:
        eth_src = sha
    if eth_dst is None:
        eth_dst = BROADCAST_MAC if op == 1 or tha == ZERO_MAC else tha
    return ether(eth_src, eth_dst, ETH_ARP, body)


# --------------------------------------------------------------------------
# L3
# --------------------------------------------------------------------------

def ipv4(src: str, dst: str, proto: int, payload: bytes, ttl: int = 64, ip_id: int = 0,
         df: bool = True, mf: bool = False, frag_off: int = 0, tos: int = 0) -> bytes:
    """IPv4 packet (20-byte header, checksum filled). ``frag_off`` in bytes.

    ``ipv4("10.0.0.1", "10.0.0.2", 17, udp_bytes, ttl=64, ip_id=0x1234)``
    """
    flags = (0x4000 if df else 0) | (0x2000 if mf else 0) | ((frag_off // 8) & 0x1FFF)
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, tos & 0xFF, total, ip_id & 0xFFFF, flags,
                      ttl & 0xFF, proto, 0, ip_bytes(src), ip_bytes(dst))
    csum = inet_checksum(hdr)
    hdr = hdr[:10] + struct.pack("!H", csum) + hdr[12:]
    return hdr + payload


def ipv6(src: str, dst: str, nh: int, payload: bytes, hlim: int = 64) -> bytes:
    """IPv6 packet (no extension headers). ``nh`` is the next-header number."""
    hdr = struct.pack("!IHBB", 0x60000000, len(payload), nh, hlim) + ip_bytes(src) + ip_bytes(dst)
    return hdr + payload


def _pseudo_header(src: str, dst: str, proto: int, length: int) -> bytes:
    s, d = ip_bytes(src), ip_bytes(dst)
    if len(s) == 4:
        return s + d + struct.pack("!BBH", 0, proto, length)
    return s + d + struct.pack("!IBBBB", length, 0, 0, 0, proto)


# --------------------------------------------------------------------------
# L4
# --------------------------------------------------------------------------

_TCP_FLAG_BITS = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10, "U": 0x20, "E": 0x40, "C": 0x80}


def tcp_flags(flags: str) -> int:
    """``"SA"`` -> 0x12.  Letters: S A P F R U (E, C for ECN)."""
    v = 0
    for ch in flags.upper():
        v |= _TCP_FLAG_BITS[ch]
    return v


def tcp_seg(src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: str,
            win: int = 65535, payload: bytes = b"", mss: int | None = None,
            wscale: int | None = None, sack_perm: bool = False,
            sacks: Sequence[tuple[int, int]] | None = None,
            ts: tuple[int, int] | None = None, urg: int = 0) -> bytes:
    """TCP segment (header + options + payload) with a correct pseudo-header checksum.

    ``flags`` is a string of letters (``"S"``, ``"SA"``, ``"PA"``, ``"FA"``, ``"R"``, ``""``).
    Options are emitted in Linux order: MSS, SACK-permitted, timestamps, NOP,
    window scale; SACK blocks ``[(left, right), ...]`` follow timestamps.

    ``tcp_seg("192.168.1.10", "93.184.216.34", 51000, 443, 1000, 0, "S", mss=1460, wscale=7, sack_perm=True)``
    """
    opts = b""
    if mss is not None:
        opts += struct.pack("!BBH", 2, 4, mss)
    if sack_perm:
        opts += b"\x04\x02"
    if ts is not None:
        if mss is None and not sack_perm:
            opts += b"\x01\x01"
        opts += struct.pack("!BBII", 8, 10, ts[0] & 0xFFFFFFFF, ts[1] & 0xFFFFFFFF)
    if wscale is not None:
        opts += struct.pack("!BBBB", 1, 3, 3, wscale)
    if sacks:
        blocks = list(sacks)[:4]
        if ts is None:
            opts += b"\x01\x01"
        opts += struct.pack("!BB", 5, 2 + 8 * len(blocks))
        for left, right in blocks:
            opts += struct.pack("!II", left & 0xFFFFFFFF, right & 0xFFFFFFFF)
    while len(opts) % 4:
        opts += b"\x01"
    doff = 5 + len(opts) // 4
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                      doff << 4, tcp_flags(flags), win & 0xFFFF, 0, urg) + opts
    seg = hdr + payload
    csum = inet_checksum(_pseudo_header(src, dst, PROTO_TCP, len(seg)) + seg)
    return seg[:16] + struct.pack("!H", csum) + seg[18:]


def udp_dgram(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    """UDP datagram with checksum.  ``udp_dgram(c, s, 53123, 53, dns_query(1, "example.com"))``"""
    length = 8 + len(payload)
    hdr = struct.pack("!HHHH", sport, dport, length, 0)
    proto = PROTO_UDP
    csum = inet_checksum(_pseudo_header(src, dst, proto, length) + hdr + payload)
    if csum == 0:
        csum = 0xFFFF
    return hdr[:6] + struct.pack("!H", csum) + payload


def icmp_msg(type: int, code: int, rest_of_header: bytes, body: bytes) -> bytes:
    """Generic ICMPv4 message: type, code, checksum, 4 bytes ``rest_of_header``, ``body``."""
    rest = (rest_of_header + b"\x00" * 4)[:4]
    msg = struct.pack("!BBH", type, code, 0) + rest + body
    return msg[:2] + struct.pack("!H", inet_checksum(msg)) + msg[4:]


def icmp_echo(req: bool, ident: int, seq: int, data: bytes = b"") -> bytes:
    """Echo request (``req=True``, type 8) or reply (type 0)."""
    return icmp_msg(8 if req else 0, 0, struct.pack("!HH", ident & 0xFFFF, seq & 0xFFFF), data)


def _quote(original_ip_packet: bytes) -> bytes:
    """IP header + first 8 bytes of its payload, as classic routers quote."""
    ihl = (original_ip_packet[0] & 0x0F) * 4 if original_ip_packet else 20
    return original_ip_packet[: ihl + 8]


def icmp_unreachable(code: int, original_ip_packet: bytes, mtu: int | None = None) -> bytes:
    """Destination unreachable (type 3). ``code`` 1 host, 3 port, 4 frag-needed (set ``mtu``)."""
    rest = struct.pack("!HH", 0, mtu) if mtu is not None else b"\x00" * 4
    return icmp_msg(3, code, rest, _quote(original_ip_packet))


def icmp_time_exceeded(original_ip_packet: bytes, code: int = 0) -> bytes:
    """Time exceeded (type 11, code 0 = TTL expired in transit)."""
    return icmp_msg(11, code, b"\x00" * 4, _quote(original_ip_packet))


def icmp_redirect(gateway_ip: str, original_ip_packet: bytes, code: int = 1) -> bytes:
    """Redirect (type 5, code 1 = redirect for host) pointing at ``gateway_ip``."""
    return icmp_msg(5, code, ip_bytes(gateway_ip), _quote(original_ip_packet))


# --------------------------------------------------------------------------
# DNS
# --------------------------------------------------------------------------

DNS_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "ANY": 255}


def dns_name(name: str) -> bytes:
    """``"www.example.com"`` -> wire-format label sequence (root-terminated)."""
    out = b""
    for label in name.rstrip(".").split("."):
        if label:
            lb = label.encode()
            out += bytes([len(lb)]) + lb
    return out + b"\x00"


def dns_query(qid: int, qname: str, qtype: int | str = 1, rd: bool = True) -> bytes:
    """Standard query with one question.  ``dns_query(0x1a2b, "example.com", "AAAA")``"""
    if isinstance(qtype, str):
        qtype = DNS_TYPES[qtype]
    flags = 0x0100 if rd else 0
    return struct.pack("!HHHHHH", qid & 0xFFFF, flags, 1, 0, 0, 0) + dns_name(qname) + struct.pack("!HH", qtype, 1)


def dns_response(qid: int, qname: str, qtype: int | str = 1,
                 answers: Sequence[tuple[str, object, int]] = (), rcode: int = 0,
                 aa: bool = False, ra: bool = True, rd: bool = True) -> bytes:
    """Response with name compression (answers point at the question name).

    ``answers`` is ``[(rtype, data, ttl), ...]`` where rtype is ``"A"``, ``"AAAA"``,
    ``"CNAME"``, ``"NS"`` or ``"TXT"`` and data is an IP string, a name or text.
    ``rcode`` 0 NOERROR, 2 SERVFAIL, 3 NXDOMAIN, 5 REFUSED.

    ``dns_response(1, "example.com", "A", [("A", "93.184.216.34", 300)])``
    """
    if isinstance(qtype, str):
        qtype = DNS_TYPES[qtype]
    flags = 0x8000 | (0x0100 if rd else 0) | (0x0080 if ra else 0) | (0x0400 if aa else 0) | (rcode & 0xF)
    out = struct.pack("!HHHHHH", qid & 0xFFFF, flags, 1, len(answers), 0, 0)
    out += dns_name(qname) + struct.pack("!HH", qtype, 1)
    ptr = struct.pack("!H", 0xC000 | 12)
    for rtype, data, ttl in answers:
        rt = DNS_TYPES[rtype] if isinstance(rtype, str) else rtype
        if rt == 1:
            rdata = ip_bytes(data)
        elif rt == 28:
            rdata = ip_bytes(data)
        elif rt in (2, 5, 12):
            rdata = dns_name(data)
        elif rt == 16:
            txt = data.encode() if isinstance(data, str) else bytes(data)
            rdata = b"".join(bytes([len(txt[i:i + 255])]) + txt[i:i + 255] for i in range(0, max(len(txt), 1), 255))
        else:
            rdata = bytes(data)
        out += ptr + struct.pack("!HHIH", rt, 1, ttl, len(rdata)) + rdata
    return out


# --------------------------------------------------------------------------
# DHCP
# --------------------------------------------------------------------------

DHCP_DISCOVER, DHCP_OFFER, DHCP_REQUEST, DHCP_DECLINE, DHCP_ACK, DHCP_NAK, DHCP_RELEASE = 1, 2, 3, 4, 5, 6, 7


def dhcp_msg(op: int, xid: int, chaddr: str, msg_type: int, ciaddr: str = "0.0.0.0",
             yiaddr: str = "0.0.0.0", siaddr: str = "0.0.0.0", server_id: str | None = None,
             requested_ip: str | None = None, routers: Iterable[str] = (), dns: Iterable[str] = (),
             lease: int | None = None, mask: str | None = None, hostname: str | None = None,
             param_req: Iterable[int] = (), broadcast: bool = False, giaddr: str = "0.0.0.0") -> bytes:
    """BOOTP/DHCP payload (UDP body): header, magic cookie, options, END, padded to >= 300 bytes.

    ``op`` 1 = BOOTREQUEST (client), 2 = BOOTREPLY (server).  ``msg_type`` 1 DISCOVER,
    2 OFFER, 3 REQUEST, 5 ACK, 6 NAK.

    ``dhcp_msg(1, 0xabcd, mac, 1, hostname="laptop", param_req=(1, 3, 6, 15))``
    """
    hdr = struct.pack("!BBBBIHH", op, 1, 6, 0, xid & 0xFFFFFFFF, 0, 0x8000 if broadcast else 0)
    hdr += ip_bytes(ciaddr) + ip_bytes(yiaddr) + ip_bytes(siaddr) + ip_bytes(giaddr)
    hdr += mac_bytes(chaddr) + b"\x00" * 10 + b"\x00" * 64 + b"\x00" * 128
    opts = b"\x63\x82\x53\x63" + bytes([53, 1, msg_type])
    if op == 1:
        opts += bytes([61, 7, 1]) + mac_bytes(chaddr)
    if server_id:
        opts += bytes([54, 4]) + ip_bytes(server_id)
    if requested_ip:
        opts += bytes([50, 4]) + ip_bytes(requested_ip)
    if mask:
        opts += bytes([1, 4]) + ip_bytes(mask)
    routers = list(routers)
    if routers:
        opts += bytes([3, 4 * len(routers)]) + b"".join(ip_bytes(r) for r in routers)
    dns = list(dns)
    if dns:
        opts += bytes([6, 4 * len(dns)]) + b"".join(ip_bytes(d) for d in dns)
    if lease is not None:
        opts += bytes([51, 4]) + struct.pack("!I", lease)
        opts += bytes([58, 4]) + struct.pack("!I", lease // 2)
        opts += bytes([59, 4]) + struct.pack("!I", lease * 7 // 8)
    if hostname:
        hn = hostname.encode()
        opts += bytes([12, len(hn)]) + hn
    param_req = list(param_req)
    if param_req:
        opts += bytes([55, len(param_req)]) + bytes(param_req)
    opts += b"\xff"
    msg = hdr + opts
    if len(msg) < 300:
        msg += b"\x00" * (300 - len(msg))
    return msg


# --------------------------------------------------------------------------
# application payloads
# --------------------------------------------------------------------------

def http_request(method: str, host: str, path: str = "/", headers: dict | None = None, body: bytes = b"") -> bytes:
    """HTTP/1.1 request bytes.  ``http_request("GET", "example.com", "/index.html")``"""
    h = {"Host": host, "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Faultline-Lab/1.0",
         "Accept": "*/*", "Connection": "keep-alive"}
    if body:
        h["Content-Length"] = str(len(body))
    if headers:
        h.update(headers)
    lines = [f"{method} {path} HTTP/1.1"] + [f"{k}: {v}" for k, v in h.items()]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def http_response(status: int, reason: str, body_len: int = 0, headers: dict | None = None,
                  body: bytes | None = None, content_type: str = "text/html; charset=utf-8") -> bytes:
    """HTTP/1.1 response.  ``body`` defaults to ``body_len`` filler bytes.

    ``http_response(200, "OK", body_len=1200)``
    """
    if body is None:
        body = (b"<html><body>" + b"x" * max(body_len - 26, 0) + b"</body></html>")[:body_len] if body_len else b""
    h = {"Server": "nginx/1.24.0", "Date": "Sat, 31 Oct 2026 16:00:00 GMT",
         "Content-Type": content_type, "Content-Length": str(len(body)), "Connection": "keep-alive"}
    if headers:
        h.update(headers)
    lines = [f"HTTP/1.1 {status} {reason}"] + [f"{k}: {v}" for k, v in h.items()]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def _tls_ext(etype: int, body: bytes) -> bytes:
    return struct.pack("!HH", etype, len(body)) + body


def _tls_record(ctype: int, version: int, body: bytes) -> bytes:
    return struct.pack("!BHH", ctype, version, len(body)) + body


def _tls_handshake(htype: int, body: bytes) -> bytes:
    return bytes([htype]) + len(body).to_bytes(3, "big") + body


def tls_client_hello(sni: str, versions: Sequence[int] = (0x0304, 0x0303), rng: random.Random | None = None,
                     alpn: Sequence[str] = ("h2", "http/1.1")) -> bytes:
    """TLS record carrying a ClientHello with SNI, supported_versions, ALPN, key_share etc.

    ``tls_client_hello("www.example.com")`` -> ~250-byte record (type 0x16).
    """
    rng = rng or random.Random(hash(sni) & 0xFFFF)
    rnd = bytes(rng.getrandbits(8) for _ in range(32))
    sid = bytes(rng.getrandbits(8) for _ in range(32))
    suites = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0x009C, 0x009D, 0x002F, 0x0035]
    body = struct.pack("!H", 0x0303) + rnd + bytes([32]) + sid
    body += struct.pack("!H", 2 * len(suites)) + b"".join(struct.pack("!H", s) for s in suites) + b"\x01\x00"
    name = sni.encode()
    exts = _tls_ext(0x0000, struct.pack("!HBH", len(name) + 3, 0, len(name)) + name)   # server_name
    exts += _tls_ext(0x0017, b"")                                                      # extended_master_secret
    exts += _tls_ext(0xFF01, b"\x00")                                                  # renegotiation_info
    groups = [0x001D, 0x0017, 0x0018]
    exts += _tls_ext(0x000A, struct.pack("!H", 2 * len(groups)) + b"".join(struct.pack("!H", g) for g in groups))
    exts += _tls_ext(0x000B, b"\x01\x00")                                              # ec_point_formats
    if alpn:
        al = b"".join(bytes([len(a)]) + a.encode() for a in alpn)
        exts += _tls_ext(0x0010, struct.pack("!H", len(al)) + al)
    exts += _tls_ext(0x0005, b"\x01\x00\x00\x00\x00")                                  # status_request
    sigs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
    exts += _tls_ext(0x000D, struct.pack("!H", 2 * len(sigs)) + b"".join(struct.pack("!H", s) for s in sigs))
    key = bytes(rng.getrandbits(8) for _ in range(32))
    exts += _tls_ext(0x0033, struct.pack("!HHH", 36, 0x001D, 32) + key)                 # key_share
    exts += _tls_ext(0x002D, b"\x01\x01")                                              # psk_key_exchange_modes
    vers = b"".join(struct.pack("!H", v) for v in versions)
    exts += _tls_ext(0x002B, bytes([len(vers)]) + vers)                                # supported_versions
    body += struct.pack("!H", len(exts)) + exts
    return _tls_record(0x16, 0x0301, _tls_handshake(1, body))


def tls_server_hello(version: int = 0x0303, selected: int = 0x0304, rng: random.Random | None = None,
                     cipher: int = 0x1301, extra_len: int = 0) -> bytes:
    """ServerHello record (+ ChangeCipherSpec + ``extra_len`` bytes of encrypted handshake).

    ``selected`` goes into supported_versions when it is TLS 1.3 (0x0304).
    """
    rng = rng or random.Random(7)
    rnd = bytes(rng.getrandbits(8) for _ in range(32))
    sid = bytes(rng.getrandbits(8) for _ in range(32))
    body = struct.pack("!H", version) + rnd + bytes([32]) + sid + struct.pack("!HB", cipher, 0)
    exts = b""
    if selected == 0x0304:
        exts += _tls_ext(0x002B, struct.pack("!H", 0x0304))
        key = bytes(rng.getrandbits(8) for _ in range(32))
        exts += _tls_ext(0x0033, struct.pack("!HH", 0x001D, 32) + key)
    else:
        exts += _tls_ext(0xFF01, b"\x00") + _tls_ext(0x0017, b"") + _tls_ext(0x000B, b"\x01\x00")
    body += struct.pack("!H", len(exts)) + exts
    out = _tls_record(0x16, version, _tls_handshake(2, body))
    out += _tls_record(0x14, version, b"\x01")
    if extra_len > 0:
        out += tls_app_data(extra_len, rng, version=version)
    return out


def tls_alert(level: int, desc: int, version: int = 0x0303) -> bytes:
    """Alert record. ``tls_alert(2, 40)`` = fatal handshake_failure; (2, 70) protocol_version."""
    return _tls_record(0x15, version, bytes([level, desc]))


def tls_app_data(nbytes: int, rng: random.Random | None = None, version: int = 0x0303, max_record: int = 16384) -> bytes:
    """``nbytes`` of application-data records (type 0x17) filled with pseudo-random bytes."""
    rng = rng or random.Random(nbytes)
    out = b""
    left = nbytes
    while left > 0:
        n = min(left, max_record)
        body = max(n - 5, 1)
        out += _tls_record(0x17, version, bytes(rng.getrandbits(8) for _ in range(body)))
        left -= body + 5
    return out


def ntp_packet(client: bool = True, ts: float = 0.0) -> bytes:
    """48-byte NTPv4 packet: client request (mode 3) or server reply (mode 4)."""
    li_vn_mode = (0 << 6) | (4 << 3) | (3 if client else 4)
    ntp_ts = int((ts + 2208988800) * (1 << 32)) & 0xFFFFFFFFFFFFFFFF if ts else 0
    stratum = 0 if client else 2
    hdr = struct.pack("!BBbbIII", li_vn_mode, stratum, 0 if client else 6, -23, 0, 0,
                      0 if client else 0x47505300)
    return hdr + struct.pack("!QQQQ", 0, 0, 0 if client else ntp_ts, ntp_ts)


# --------------------------------------------------------------------------
# network model
# --------------------------------------------------------------------------

@dataclass
class Host:
    """A network endpoint. ``mac`` is None for off-LAN (internet) hosts.

    ``Host("laptop", "f4:5c:89:aa:10:01", "192.168.1.10")``
    """
    name: str
    mac: str | None
    ip: str
    ipv6: str | None = None

    def __str__(self) -> str:
        return f"{self.name}({self.ip})"


_VENDOR_PREFIXES = ["f4:5c:89", "3c:22:fb", "a4:83:e7", "dc:a6:32", "b8:27:eb", "00:1a:a0", "28:d2:44",
                    "f0:18:98", "8c:85:90", "e4:5f:01", "c8:e2:65", "9c:b6:d0", "d8:bb:c1", "48:2a:e3"]

_CLIENT_NAMES = ["anita-laptop", "dev-ws01", "dev-ws02", "reception-pc", "finance-pc", "marketing-mac",
                 "lab-pi", "cto-laptop", "intern-laptop", "hr-pc", "sales-tablet", "conf-room-pc"]

_SERVERS = {
    "www.example.com": "93.184.216.34",
    "example.com": "93.184.216.34",
    "docs.example.org": "203.0.113.10",
    "mail.example.net": "203.0.113.25",
    "updates.example-cdn.com": "203.0.113.80",
    "static.example-cdn.com": "203.0.113.81",
    "api.example.io": "198.51.100.20",
    "git.example.dev": "198.51.100.44",
    "chat.example-apps.com": "198.51.100.60",
    "pool.ntp.org": "203.0.113.123",
    "www.wikipedia-mirror.example": "198.51.100.5",
    "cdn.video-example.com": "203.0.113.200",
}


class Lan:
    """The standard office LAN used by every scenario.

    * subnet 192.168.1.0/24, gateway + DNS resolver 192.168.1.1 (MAC 3c:84:6a:12:34:01)
    * 12 clients at 192.168.1.10 .. .60 (``lan.clients``), realistic vendor MACs
    * internet servers in documentation ranges (``lan.server("docs.example.org")``)

    ``lan.frame(ip_packet, src_ip, dst_ip)`` wraps an IP packet in Ethernet, using
    the gateway MAC for any address outside the subnet.
    """

    def __init__(self, subnet: str = "192.168.1.0/24", gateway_ip: str = "192.168.1.1",
                 gateway_mac: str = "3c:84:6a:12:34:01"):
        self.net = ipaddress.ip_network(subnet)
        self.gateway = Host("gateway", gateway_mac, gateway_ip)
        self.dns = gateway_ip
        self.hosts: dict[str, Host] = {gateway_ip: self.gateway}
        self.clients: list[Host] = []
        ips = [10, 11, 12, 15, 20, 21, 30, 31, 40, 45, 55, 60]
        for i, (name, last) in enumerate(zip(_CLIENT_NAMES, ips)):
            mac = f"{_VENDOR_PREFIXES[i % len(_VENDOR_PREFIXES)]}:{(0x10 + i):02x}:{(0xa0 + last):02x}:{(0x01 + i * 7) & 0xff:02x}"
            self.add_host(Host(name, mac, f"192.168.1.{last}"))
        self.servers: dict[str, Host] = {name: Host(name, None, ip) for name, ip in _SERVERS.items()}

    def add_host(self, host: Host, client: bool = True) -> Host:
        """Register a host so its MAC is used when framing; ``client=False`` keeps it out of ``lan.clients``."""
        self.hosts[host.ip] = host
        if client and host.ip != self.gateway.ip and host not in self.clients:
            self.clients.append(host)
        return host

    def server(self, name: str) -> Host:
        """Internet server by name (``"docs.example.org"``). Unknown names get a new 203.0.113.x address."""
        if name not in self.servers:
            ip = f"203.0.113.{100 + len(self.servers) % 150}"
            self.servers[name] = Host(name, None, ip)
        return self.servers[name]

    def resolve(self, ip: str) -> Host | None:
        if ip in self.hosts:
            return self.hosts[ip]
        for h in self.servers.values():
            if h.ip == ip:
                return h
        return None

    def on_lan(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip) in self.net
        except ValueError:
            return False

    def mac_for(self, ip: str) -> str:
        """MAC used on this LAN for ``ip``: the host's own MAC, or the gateway's when off-LAN."""
        h = self.hosts.get(ip)
        if h is not None and h.mac:
            return h.mac
        if ip.startswith("169.254.") and h is not None and h.mac:
            return h.mac
        return self.gateway.mac

    def frame(self, ip_packet: bytes, src_ip: str, dst_ip: str, src_mac: str | None = None,
              dst_mac: str | None = None) -> bytes:
        """Ethernet-wrap an IPv4/IPv6 packet between ``src_ip`` and ``dst_ip`` as seen on this LAN."""
        if ip_packet and (ip_packet[0] >> 4) == 6:
            et = ETH_IPV6
        else:
            et = ETH_IPV4
        if src_mac is None:
            src_mac = self.mac_for(src_ip)
        if dst_mac is None:
            if dst_ip == "255.255.255.255" or dst_ip.startswith("224.") or dst_ip.startswith("239."):
                dst_mac = BROADCAST_MAC
            else:
                dst_mac = self.mac_for(dst_ip)
        return ether(src_mac, dst_mac, et, ip_packet)


# --------------------------------------------------------------------------
# capture builder
# --------------------------------------------------------------------------

class Capture:
    """Collects ``(ts, frame)`` from many generators, sorts by time, writes a pcap.

    ``cap = Capture(lan, seed=1, t0=1793549400.0)`` then ``cap.add(ts, frame)``,
    ``cap.ip(ts, ip_packet, src, dst)`` (wraps via the Lan), ``cap.write(path)``.
    ``cap.rng`` is a seeded :class:`random.Random` for deterministic jitter.
    """

    #: 2026-10-31 21:30:00 IST (UTC+5:30) as epoch seconds
    DEFAULT_T0 = 1793462400.0

    def __init__(self, lan: Lan | None = None, seed: int = 1, t0: float = DEFAULT_T0):
        self.lan = lan or Lan()
        self.rng = random.Random(seed)
        self.t0 = float(t0)
        self.items: list[tuple[float, int, bytes]] = []
        self._n = 0
        self._ip_id = {}

    def add(self, ts: float, frame: bytes) -> float:
        """Append a raw Ethernet frame at time ``ts`` (float epoch). Returns ``ts``."""
        self.items.append((float(ts), self._n, bytes(frame)))
        self._n += 1
        return ts

    def ip(self, ts: float, ip_packet: bytes, src_ip: str, dst_ip: str, **kw) -> float:
        """Ethernet-wrap ``ip_packet`` via :meth:`Lan.frame` and add it."""
        return self.add(ts, self.lan.frame(ip_packet, src_ip, dst_ip, **kw))

    def next_ip_id(self, src_ip: str) -> int:
        """Per-source incrementing IPv4 identification (starts at a seeded random value)."""
        v = self._ip_id.get(src_ip)
        if v is None:
            v = self.rng.randrange(1, 60000)
        self._ip_id[src_ip] = (v + 1) & 0xFFFF
        return v

    def jitter(self, base: float, frac: float = 0.15) -> float:
        """``base`` scaled by a random factor in [1-frac, 1+frac]."""
        return base * (1.0 + self.rng.uniform(-frac, frac))

    def sorted_frames(self) -> list[tuple[float, bytes]]:
        return [(ts, fr) for ts, _, fr in sorted(self.items, key=lambda x: (x[0], x[1]))]

    def __len__(self) -> int:
        return len(self.items)

    @property
    def last_ts(self) -> float:
        return max((ts for ts, _, _ in self.items), default=self.t0)

    def write(self, path: str, pcapng: bool = False, snaplen: int = 262144) -> int:
        """Write all frames (time-sorted) to ``path``. Returns the packet count."""
        frames = self.sorted_frames()
        cls = PcapNgWriter if pcapng else PcapWriter
        with cls(path, snaplen=snaplen) as w:
            for ts, fr in frames:
                w.write(ts, fr)
        return len(frames)


# --------------------------------------------------------------------------
# TCP session model
# --------------------------------------------------------------------------

class TcpSession:
    """A TCP connection between a LAN ``client`` and a ``server`` with seq/ack tracking.

    Parameters: ``cap`` (Capture), ``client`` (Host on the LAN), ``server`` (Host or
    IP string), ``sport``, ``dport``, ``rtt`` (handshake round-trip seconds as seen
    at the capture point), ``start_ts``, ``mss``, ``wscale``, ``server_think_time``
    (seconds between a request's arrival and the first response byte),
    ``jitter`` (fraction of RTT), ``rtt_up``/``rtt_down`` to make the two
    directions asymmetric (they default to rtt/2 each).

    Methods: :meth:`handshake`, :meth:`client_send`, :meth:`server_send`,
    :meth:`ack`, :meth:`close`, :meth:`reset`, :meth:`zero_window`,
    :meth:`keepalive`, and low-level :meth:`client_segment` /
    :meth:`server_segment` for hand-built corner cases.  ``s.now`` is the
    capture timestamp of the last frame; ``s.c_seq``/``s.s_seq`` are the next
    sequence numbers of each side.

    Loss injection in :meth:`server_send`: ``loss_down`` / ``loss_up`` are per-segment
    probabilities (or pass explicit index sets ``drop_down`` / ``drop_up``).
    *down* = the original is seen at the capture point but lost on the way to
    the client; *up* = lost before the capture point (a gap appears, and the
    retransmission is the first copy seen).  The client answers with duplicate
    ACKs carrying SACK blocks; after 3 dup ACKs the server fast-retransmits,
    otherwise it waits for an RTO.

    Example::

        s = TcpSession(cap, lan.clients[0], lan.server("docs.example.org"), 50123, 443, 0.03, cap.t0)
        s.handshake(); s.client_send(tls_client_hello("docs.example.org"))
        s.server_send(200_000, loss_down=0.03, loss_up=0.03); s.close()
    """

    def __init__(self, cap: Capture, client: Host, server: Host | str, sport: int, dport: int,
                 rtt: float, start_ts: float, mss: int = 1460, wscale: int = 7,
                 server_think_time: float = 0.0, jitter: float = 0.1,
                 rtt_up: float | None = None, rtt_down: float | None = None,
                 client_win: int = 65535 * 4, server_win: int = 65535 * 4,
                 timestamps: bool = True, local_delay: float = 0.0005):
        self.cap = cap
        self.lan = cap.lan
        self.rng = cap.rng
        self.client = client
        self.server = server if isinstance(server, Host) else (cap.lan.resolve(server) or Host(server, None, server))
        self.c_ip, self.s_ip = client.ip, self.server.ip
        self.sport, self.dport = sport, dport
        self.rtt = rtt
        self.rtt_up = rtt_up if rtt_up is not None else rtt / 2
        self.rtt_down = rtt_down if rtt_down is not None else rtt / 2
        self.jit = jitter
        self.now = float(start_ts)
        self.mss = mss
        self.wscale = wscale
        self.think = server_think_time
        self.client_win = client_win
        self.server_win = server_win
        self.use_ts = timestamps
        self.local_delay = local_delay
        self.c_isn = self.rng.getrandbits(32)
        self.s_isn = self.rng.getrandbits(32)
        self.c_seq = self.c_isn      # next seq the client will send
        self.s_seq = self.s_isn      # next seq the server will send
        self.c_ack = 0               # what the client acknowledges (server bytes received)
        self.s_ack = 0               # what the server acknowledges
        self.c_ts0 = self.rng.getrandbits(31)
        self.s_ts0 = self.rng.getrandbits(31)
        self.c_last_ts, self.s_last_ts = 0, 0
        self.cwnd = 10
        self.max_cwnd = 60
        self.rto = max(0.2, 3 * rtt)
        self.open = False
        self.frames = 0
        self.pace = 0.00012          # ~100 Mbit/s per full segment at the capture point
        self.reply_earliest = float(start_ts)   # earliest capture time a server reply can appear

    # -- internals -------------------------------------------------------
    def _rtt(self, which: str = "full") -> float:
        base = {"full": self.rtt, "up": self.rtt_up, "down": self.rtt_down}[which]
        return max(0.0001, base * (1.0 + self.rng.uniform(-self.jit, self.jit)))

    def _tsopt(self, side: str, ts: float):
        if not self.use_ts:
            return None
        ms = int((ts - self.cap.t0) * 1000) & 0xFFFFFFFF
        if side == "c":
            self.c_last_ts = (self.c_ts0 + ms) & 0xFFFFFFFF
            return (self.c_last_ts, self.s_last_ts)
        self.s_last_ts = (self.s_ts0 + ms) & 0xFFFFFFFF
        return (self.s_last_ts, self.c_last_ts)

    def _win(self, side: str, raw: int | None = None) -> int:
        w = raw if raw is not None else (self.client_win if side == "c" else self.server_win)
        return min(0xFFFF, w >> self.wscale) if self.wscale else min(0xFFFF, w)

    def _emit(self, ts: float, side: str, seq: int, ack: int, flags: str, payload: bytes = b"",
              win: int | None = None, sacks=None, **opts) -> float:
        if side == "c":
            src, dst, sp, dp = self.c_ip, self.s_ip, self.sport, self.dport
        else:
            src, dst, sp, dp = self.s_ip, self.c_ip, self.dport, self.sport
        tsopt = self._tsopt(side, ts) if "tsopt" not in opts else opts.pop("tsopt")
        raw_win = (win if win is not None else 65535) if "S" in flags else self._win(side, win)
        seg = tcp_seg(src, dst, sp, dp, seq, ack, flags, win=raw_win, payload=payload,
                      sacks=sacks, ts=tsopt, **opts)
        ttl = 64 if side == "c" or self.lan.on_lan(self.s_ip) else 50 + (self.rng.randrange(0, 3))
        pkt = ipv4(src, dst, PROTO_TCP, seg, ttl=ttl, ip_id=self.cap.next_ip_id(src))
        self.cap.ip(ts, pkt, src, dst)
        self.frames += 1
        self.now = max(self.now, ts)
        return ts

    # -- public primitives ------------------------------------------------
    def client_segment(self, ts: float, flags: str, payload: bytes = b"", seq: int | None = None,
                       ack: int | None = None, win: int | None = None, sacks=None, **opts) -> float:
        """Emit one client->server segment at ``ts`` (defaults to current seq/ack). Does not advance seq.

        Extra keywords go to :func:`tcp_seg` (``mss``, ``wscale``, ``sack_perm``); pass
        ``tsopt=None`` to omit the timestamp option (RST segments)."""
        return self._emit(ts, "c", self.c_seq if seq is None else seq, self.c_ack if ack is None else ack,
                          flags, payload, win=win, sacks=sacks, **opts)

    def server_segment(self, ts: float, flags: str, payload: bytes = b"", seq: int | None = None,
                       ack: int | None = None, win: int | None = None, sacks=None, **opts) -> float:
        """Emit one server->client segment at ``ts``. Does not advance seq."""
        return self._emit(ts, "s", self.s_seq if seq is None else seq, self.s_ack if ack is None else ack,
                          flags, payload, win=win, sacks=sacks, **opts)

    # -- connection lifecycle -----------------------------------------------
    def handshake(self, at: float | None = None, server_mss: int | None = None,
                  syn_retries: Sequence[float] = ()) -> float:
        """SYN / SYN-ACK / ACK. ``syn_retries`` are extra unanswered SYN delays before success.

        Returns the time of the final ACK and leaves ``s.now`` there.
        """
        t = self.now if at is None else at
        synopts = dict(mss=self.mss, sack_perm=True, wscale=self.wscale)
        t = self.client_segment(t, "S", win=65535 if self.wscale else self.client_win, **synopts)
        for d in syn_retries:
            t = self.client_segment(t + d, "S", win=65535, **synopts)
        t2 = t + self._rtt()
        self.s_ack = (self.c_isn + 1) & 0xFFFFFFFF
        self.server_segment(t2, "SA", win=65535, mss=server_mss or self.mss, sack_perm=True, wscale=self.wscale)
        self.c_seq = (self.c_isn + 1) & 0xFFFFFFFF
        self.c_ack = (self.s_isn + 1) & 0xFFFFFFFF
        self.s_seq = (self.s_isn + 1) & 0xFFFFFFFF
        t3 = t2 + self.local_delay * (1 + self.rng.random())
        self.client_segment(t3, "A")
        self.open = True
        self.now = t3
        self.reply_earliest = t3 + self.rtt
        return t3

    def syn_only(self, at: float | None = None, retries: Sequence[float] = (1.0, 2.0, 4.0, 8.0)) -> float:
        """SYN plus exponential-backoff retries that are never answered (server down / filtered)."""
        t = self.now if at is None else at
        t = self.client_segment(t, "S", win=65535, mss=self.mss, sack_perm=True, wscale=self.wscale)
        for d in retries:
            t = self.client_segment(t + d * (1 + self.rng.uniform(-0.02, 0.02)), "S", win=65535,
                                    mss=self.mss, sack_perm=True, wscale=self.wscale)
        self.now = t
        return t

    def syn_refused(self, at: float | None = None) -> float:
        """SYN answered by RST/ACK (nothing listening). Returns time of the RST."""
        t = self.now if at is None else at
        self.client_segment(t, "S", win=65535, mss=self.mss, sack_perm=True, wscale=self.wscale)
        t2 = t + self._rtt()
        self.server_segment(t2, "RA", seq=0, ack=(self.c_isn + 1) & 0xFFFFFFFF, win=0, tsopt=None)
        self.now = t2
        return t2

    def client_send(self, data: bytes | int, at: float | None = None, ack: bool = True,
                    psh: bool = True) -> float:
        """Client sends ``data`` (bytes, or a byte count filled with pseudo-random bytes).

        Splits into MSS-sized segments; the server's pure ACK arrives one RTT later
        when ``ack=True``.  Returns the time of the last frame.
        """
        payload = self._fill(data)
        t = self.now if at is None else at
        segs = [payload[i:i + self.mss] for i in range(0, len(payload), self.mss)] or [b""]
        for i, chunk in enumerate(segs):
            flags = "PA" if (psh and i == len(segs) - 1) else "A"
            self.client_segment(t, flags, chunk)
            self.c_seq = (self.c_seq + len(chunk)) & 0xFFFFFFFF
            t += self.pace * len(chunk) / self.mss if chunk else 0
        self.now = t
        self.reply_earliest = t + self._rtt()
        if ack:
            self.s_ack = self.c_seq
            self.server_segment(self.reply_earliest, "A")
            self.now = self.reply_earliest
        else:
            self.s_ack = self.c_seq
        return self.now

    def ack(self, side: str = "c", at: float | None = None) -> float:
        """Pure ACK from ``side`` ('c' client or 's' server) at ``at`` (default now + tiny delay)."""
        t = (self.now + self.local_delay) if at is None else at
        if side == "c":
            return self.client_segment(t, "A")
        self.s_ack = self.c_seq
        return self.server_segment(t, "A")

    def server_send(self, nbytes: int | bytes, at: float | None = None, segment_size: int | None = None,
                    loss_down: float = 0.0, loss_up: float = 0.0,
                    drop_down: Iterable[int] = (), drop_up: Iterable[int] = (),
                    think: float | None = None, psh: bool = True, ack_every: int = 2,
                    df: bool = True) -> float:
        """Server sends ``nbytes`` (or payload) toward the client, ACK-clocked in windows.

        First byte appears ``think`` (default ``server_think_time``) after the server
        could have seen the client's last segment.  Returns the time of the last
        frame (normally the client's final ACK).  See the class doc for loss knobs.
        """
        payload = self._fill(nbytes)
        seg_size = segment_size or self.mss
        think = self.think if think is None else think
        start = (max(self.now, self.reply_earliest) if at is None else at) + think
        segs = []
        off = 0
        while off < len(payload):
            segs.append(payload[off:off + seg_size])
            off += seg_size
        if not segs:
            return self.now
        n = len(segs)
        drop_down, drop_up = set(drop_down), set(drop_up)
        fate = {}
        for i in range(n):
            if i in drop_down or (loss_down and self.rng.random() < loss_down):
                fate[i] = "down"
            elif i in drop_up or (loss_up and self.rng.random() < loss_up):
                fate[i] = "up"
        seq0 = self.s_seq
        seqs = []
        s = seq0
        for chunk in segs:
            seqs.append(s)
            s = (s + len(chunk)) & 0xFFFFFFFF
        end_seq = s

        received = [False] * n
        rcv_next = 0                     # index of the first segment not yet received in order
        t = start
        next_new = 0
        cwnd = self.cwnd
        last_ack_time = t
        pending_holes: dict[int, dict] = {}   # idx -> {"sent": time, "dupacks": int, "retx_at": time|None}
        acks_since_last = 0
        last_t_round = t

        def client_sack_blocks() -> list[tuple[int, int]]:
            blocks = []
            i = rcv_next
            while i < n:
                if received[i]:
                    j = i
                    while j + 1 < n and received[j + 1]:
                        j += 1
                    blocks.append((seqs[i], (seqs[j] + len(segs[j])) & 0xFFFFFFFF))
                    i = j + 1
                else:
                    i += 1
            blocks.reverse()
            return blocks[:3]

        def client_ack(at_time: float, sack: bool = True) -> None:
            self.c_ack = seqs[rcv_next] if rcv_next < n else end_seq
            blocks = client_sack_blocks() if sack else None
            self.client_segment(at_time, "A", sacks=blocks or None)

        def deliver(idx: int, at_time: float, is_retx: bool) -> None:
            nonlocal rcv_next, acks_since_last, last_ack_time
            received[idx] = True
            advanced = False
            while rcv_next < n and received[rcv_next]:
                rcv_next += 1
                advanced = True
            ta = max(at_time + self.local_delay * 0.6, last_ack_time + 0.00002)
            if not advanced:
                # out-of-order: immediate dup ACK with SACK
                client_ack(ta)
                last_ack_time = ta
                for h in pending_holes.values():
                    if h["retx_at"] is None:
                        h["dupacks"] += 1
                        if h["dupacks"] >= 3:
                            h["retx_at"] = ta + self._rtt()
                acks_since_last = 0
            else:
                acks_since_last += 1
                if is_retx or acks_since_last >= ack_every or rcv_next == n:
                    client_ack(ta, sack=rcv_next < n)
                    last_ack_time = ta
                    acks_since_last = 0

        def send_original(idx: int, at_time: float) -> None:
            f = fate.get(idx)
            flags = "PA" if (psh and idx == n - 1) else "A"
            if f != "up":
                self.server_segment(at_time, flags, segs[idx], seq=seqs[idx])
            if f is None:
                deliver(idx, at_time + self.local_delay, False)
            else:
                pending_holes[idx] = {"sent": at_time, "dupacks": 0, "retx_at": None}

        while next_new < n or pending_holes:
            # 1. retransmissions whose time has come, or RTO
            fired = False
            for idx in sorted(pending_holes):
                h = pending_holes[idx]
                when = h["retx_at"]
                if when is None and (next_new >= n or t - h["sent"] >= self.rto):
                    when = h["sent"] + self.rto
                if when is not None and (when <= t or next_new >= n):
                    flags = "PA" if idx == n - 1 or h["dupacks"] >= 3 else "A"
                    self.server_segment(when, flags, segs[idx], seq=seqs[idx])
                    del pending_holes[idx]
                    deliver(idx, when + self.local_delay, True)
                    t = max(t, when + self.pace)
                    fired = True
            if fired and next_new >= n:
                continue
            if next_new >= n:
                # only holes left with scheduled times in the future
                t = min(h["retx_at"] or (h["sent"] + self.rto) for h in pending_holes.values())
                continue
            # 2. send a window of new data
            win_segs = min(cwnd, n - next_new)
            round_start = t
            for _ in range(win_segs):
                send_original(next_new, t)
                next_new += 1
                t += self.pace * (0.8 + 0.4 * self.rng.random())
            # next window is ACK-clocked
            t = max(t, round_start + self._rtt())
            cwnd = min(self.max_cwnd, cwnd * 2 if cwnd < 32 else cwnd + 4)

        self.s_seq = end_seq
        self.c_ack = end_seq
        self.cwnd = max(10, cwnd // 2) if fate else cwnd
        self.now = max(self.now, last_ack_time)
        self.reply_earliest = self.now
        return self.now

    def zero_window(self, stall: float = 3.0, at: float | None = None, probes: bool = True) -> float:
        """Client advertises a zero receive window for ``stall`` seconds.

        Emits the zero-window ACK, the server's zero-window probes (1 byte at
        ``s_seq``, backing off from 0.3 s) answered with window=0 ACKs, then the
        client's window update.  Returns the time of the window update.
        """
        t = (self.now + self.local_delay) if at is None else at
        self.client_segment(t, "A", win=0)
        end = t + stall
        probe_dt = 0.3
        pt = t + self._rtt("up") + probe_dt
        probe = self._fill(1)
        while probes and pt < end:
            self.server_segment(pt, "A", probe, seq=self.s_seq)
            self.client_segment(pt + self.local_delay, "A", win=0)
            probe_dt = min(probe_dt * 2, 60)
            pt += probe_dt
        self.client_segment(end, "A")
        self.now = end
        return end

    def keepalive(self, at: float | None = None, n: int = 1, interval: float = 75.0) -> float:
        """Client keepalive probes (ACK with seq-1, zero/one byte) answered by the server."""
        t = (self.now + interval) if at is None else at
        for _ in range(n):
            self.client_segment(t, "A", seq=(self.c_seq - 1) & 0xFFFFFFFF)
            self.server_segment(t + self._rtt(), "A")
            t += interval
        self.now = t - interval + self.rtt
        return self.now

    def close(self, initiator: str = "c", at: float | None = None, rst_after: bool = False) -> float:
        """Graceful close: FIN/ACK from ``initiator`` ('c' or 's'), ACK, FIN/ACK back, final ACK."""
        t = (self.now + self.local_delay) if at is None else at
        a, b = (("c", "s") if initiator == "c" else ("s", "c"))
        emit_a = self.client_segment if a == "c" else self.server_segment
        emit_b = self.server_segment if a == "c" else self.client_segment
        emit_a(t, "FA")
        if a == "c":
            self.c_seq = (self.c_seq + 1) & 0xFFFFFFFF
            self.s_ack = self.c_seq
        else:
            self.s_seq = (self.s_seq + 1) & 0xFFFFFFFF
            self.c_ack = self.s_seq
        t2 = t + (self._rtt() if a == "c" else self.local_delay)
        emit_b(t2, "A")
        t3 = t2 + (self.local_delay * 2 if a == "c" else 0.0003) + (0.0 if a == "c" else 0)
        if a == "c":
            t3 = t2 + self.rng.uniform(0.0002, 0.002)
        emit_b(t3, "FA")
        if a == "c":
            self.s_seq = (self.s_seq + 1) & 0xFFFFFFFF
            self.c_ack = self.s_seq
        else:
            self.c_seq = (self.c_seq + 1) & 0xFFFFFFFF
            self.s_ack = self.c_seq
        t4 = t3 + (self.local_delay if a == "c" else self._rtt())
        emit_a(t4, "A")
        if rst_after:
            t4 = emit_a(t4 + self.local_delay, "R", tsopt=None)
        self.open = False
        self.now = t4
        return t4

    def reset(self, from_side: str = "c", at: float | None = None, ack_flag: bool = True) -> float:
        """Abortive close: RST (or RST/ACK) from ``from_side``."""
        t = (self.now + self.local_delay) if at is None else at
        flags = "RA" if ack_flag else "R"
        if from_side == "c":
            self.client_segment(t, flags, tsopt=None)
        else:
            self.server_segment(t, flags, tsopt=None)
        self.open = False
        self.now = t
        return t

    # -- helpers -------------------------------------------------------------
    def _fill(self, data: bytes | int) -> bytes:
        if isinstance(data, (bytes, bytearray)):
            return bytes(data)
        n = int(data)
        return bytes(self.rng.getrandbits(8) for _ in range(n)) if n <= 4096 else \
            (self.rng.getrandbits(8 * 4096).to_bytes(4096, "big") * (n // 4096 + 1))[:n]
