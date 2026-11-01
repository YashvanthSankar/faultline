"""Hand-written L2-L7 packet decoder (standard library only).

Entry point: :func:`decode` turns a :class:`Frame` into a :class:`Packet`.
It never raises: every layer validates its lengths against the bytes actually
present, bounds every loop, and on the first problem records a short reason in
``Packet.malformed`` while keeping the layers already decoded.

Privacy: payload bytes are never stored on the Packet; credential protocols
only set ``Packet.cred`` to a protocol label.
"""

from __future__ import annotations

import socket
import struct

from faultline.capture.reader import (
    LINKTYPE_ETHERNET,
    LINKTYPE_IPV4,
    LINKTYPE_IPV6,
    LINKTYPE_LINUX_SLL,
    LINKTYPE_LINUX_SLL2,
    LINKTYPE_LOOP,
    LINKTYPE_NULL,
    LINKTYPE_RAW,
    Frame,
)
from faultline.model import Arp, Dhcp, Dns, DnsRR, Http, Icmp, IcmpInner, Packet, Tcp, Tls, Udp

__all__ = ["decode", "decode_bytes"]

# --------------------------------------------------------------------------- #
# Constants and precompiled structs
# --------------------------------------------------------------------------- #

ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
ETH_P_IPV6 = 0x86DD
VLAN_ETHERTYPES = frozenset((0x8100, 0x88A8, 0x9100, 0x9200))
MAX_VLAN_TAGS = 4

AF_INET = 2
AF_INET6_VALUES = frozenset((24, 28, 30))

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58
IPV6_EXT_HEADERS = frozenset((0, 43, 44, 60, 51))  # hop-by-hop, routing, fragment, dst opts, AH
MAX_IPV6_EXT = 8

DNS_PORTS = frozenset((53, 5353, 5355))
DHCP_PORTS = frozenset((67, 68))
DNS_MAX_NAME = 255
DNS_MAX_LABEL = 63
DNS_MAX_JUMPS = 32
DNS_MAX_ANSWERS = 32
DNS_MAX_SECTION_RRS = 512  # skip cap when walking past question/answer records
DHCP_MAGIC = b"\x63\x82\x53\x63"
DHCP_MAX_OPTIONS = 255

TLS_MAX_RECORD = 18432
TLS_MAX_RECORDS = 16
TLS_MAX_EXTENSIONS = 64
TLS_MAX_SNI = 253
TLS_HANDSHAKE, TLS_ALERT = 22, 21

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ")
HTTP_MAX_SCAN = 4096
HTTP_MAX_HEADERS = 40
TCP_MAX_OPTIONS = 40

_ETH = struct.Struct("!6s6sH")
_SLL = struct.Struct("!HHH8sH")
_SLL2 = struct.Struct("!HHIHBB8s")
_ARP = struct.Struct("!HHBBH6s4s6s4s")
_IPV4 = struct.Struct("!BBHHHBBH4s4s")
_IPV6 = struct.Struct("!IHBB16s16s")
_TCP = struct.Struct("!HHIIBBHHH")
_UDP = struct.Struct("!HHHH")
_ICMP = struct.Struct("!BBH")
_DNS_HDR = struct.Struct("!HHHHHH")
_DNS_RR = struct.Struct("!HHIH")
_BOOTP = struct.Struct("!BBBBIHH4s4s4s4s16s")
_U16 = struct.Struct("!H")
_U32 = struct.Struct("!I")
_TLS_REC = struct.Struct("!BHH")

_inet_ntop = socket.inet_ntop
_AF_INET, _AF_INET6 = socket.AF_INET, socket.AF_INET6


class _Malformed(Exception):
    """Internal: a layer failed with a short reason; decoding stops there."""


def _ip4(b: bytes) -> str:
    return _inet_ntop(_AF_INET, b)


def _ip6(b: bytes) -> str:
    return _inet_ntop(_AF_INET6, b)


def _printable(s: str, cap: int) -> str:
    """Keep printable ASCII only (strips control chars), capped at ``cap``."""
    return "".join(c for c in s[:cap] if 0x20 <= ord(c) < 0x7F)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def decode(frame: Frame) -> Packet:
    """Decode one frame. Never raises."""
    pkt = Packet(frame.no, frame.ts, frame.caplen, frame.wirelen, frame.linktype)
    data = frame.data
    try:
        _decode_link(pkt, data, frame.linktype)
    except _Malformed as e:
        pkt.malformed = str(e)
    except (struct.error, IndexError, ValueError, UnicodeDecodeError, TypeError) as e:
        pkt.malformed = f"truncated: {type(e).__name__}"
    except Exception as e:  # last-resort safety net: decoding must never crash the engine
        pkt.malformed = f"internal: {type(e).__name__}"
    return pkt


def decode_bytes(data: bytes, linktype: int = LINKTYPE_ETHERNET, no: int = 1, ts: float = 0.0) -> Packet:
    """Convenience for tests: decode raw frame bytes."""
    return decode(Frame(no, ts, len(data), linktype, bytes(data)))


# --------------------------------------------------------------------------- #
# Link layer
# --------------------------------------------------------------------------- #


def _decode_link(pkt: Packet, data: bytes, linktype: int) -> None:
    if linktype == LINKTYPE_ETHERNET:
        _decode_ethernet(pkt, data)
    elif linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
        _decode_raw_ip(pkt, data, 0)
    elif linktype == LINKTYPE_LINUX_SLL:
        _decode_sll(pkt, data)
    elif linktype == LINKTYPE_LINUX_SLL2:
        _decode_sll2(pkt, data)
    elif linktype in (LINKTYPE_NULL, LINKTYPE_LOOP):
        _decode_null(pkt, data)
    # unknown link type: a Packet with no layers, not malformed


def _decode_ethernet(pkt: Packet, data: bytes) -> None:
    if len(data) < 14:
        raise _Malformed("eth: short header")
    dst, src, etype = _ETH.unpack_from(data, 0)
    pkt.eth_dst = dst.hex(":")
    pkt.eth_src = src.hex(":")
    off = 14
    tags = 0
    while etype in VLAN_ETHERTYPES:
        if tags >= MAX_VLAN_TAGS:
            raise _Malformed("eth: too many vlan tags")
        if len(data) < off + 4:
            raise _Malformed("eth: short vlan tag")
        tci = _U16.unpack_from(data, off)[0]
        if pkt.vlan is None:
            pkt.vlan = tci & 0x0FFF
        etype = _U16.unpack_from(data, off + 2)[0]
        off += 4
        tags += 1
    pkt.ethertype = etype
    _dispatch_ethertype(pkt, data, off, etype)


def _dispatch_ethertype(pkt: Packet, data: bytes, off: int, etype: int) -> None:
    if etype == ETH_P_IP:
        _decode_ipv4(pkt, data, off)
    elif etype == ETH_P_IPV6:
        _decode_ipv6(pkt, data, off)
    elif etype == ETH_P_ARP:
        _decode_arp(pkt, data, off)


def _decode_raw_ip(pkt: Packet, data: bytes, off: int) -> None:
    if len(data) <= off:
        raise _Malformed("ip: empty")
    ver = data[off] >> 4
    if ver == 4:
        _decode_ipv4(pkt, data, off)
    elif ver == 6:
        _decode_ipv6(pkt, data, off)
    else:
        raise _Malformed(f"ip: bad version {ver}")


def _decode_sll(pkt: Packet, data: bytes) -> None:
    if len(data) < 16:
        raise _Malformed("sll: short header")
    _ptype, arphrd, alen, addr, proto = _SLL.unpack_from(data, 0)
    if arphrd == 1 and alen == 6:  # ARPHRD_ETHER
        pkt.eth_src = addr[:6].hex(":")
    pkt.ethertype = proto
    _dispatch_ethertype(pkt, data, 16, proto)


def _decode_sll2(pkt: Packet, data: bytes) -> None:
    if len(data) < 20:
        raise _Malformed("sll2: short header")
    proto, _res, _ifidx, arphrd, _ptype, alen, addr = _SLL2.unpack_from(data, 0)
    if arphrd == 1 and alen == 6:
        pkt.eth_src = addr[:6].hex(":")
    pkt.ethertype = proto
    _dispatch_ethertype(pkt, data, 20, proto)


def _decode_null(pkt: Packet, data: bytes) -> None:
    if len(data) < 4:
        raise _Malformed("null: short header")
    af_le = int.from_bytes(data[0:4], "little")
    af_be = int.from_bytes(data[0:4], "big")
    af = af_le if af_le < 0x10000 else af_be
    if af == AF_INET:
        _decode_ipv4(pkt, data, 4)
    elif af in AF_INET6_VALUES:
        _decode_ipv6(pkt, data, 4)
    # other address families are left undecoded


def _decode_arp(pkt: Packet, data: bytes, off: int) -> None:
    if len(data) < off + 8:
        raise _Malformed("arp: short header")
    htype, ptype, hlen, plen = struct.unpack_from("!HHBB", data, off)
    if htype != 1 or ptype != ETH_P_IP or hlen != 6 or plen != 4:
        return  # not Ethernet/IPv4 ARP: leave undecoded
    if len(data) < off + _ARP.size:
        raise _Malformed("arp: truncated")
    _h, _p, _hl, _pl, op, sha, spa, tha, tpa = _ARP.unpack_from(data, off)
    pkt.arp = Arp(op, sha.hex(":"), _ip4(spa), tha.hex(":"), _ip4(tpa))


# --------------------------------------------------------------------------- #
# IP
# --------------------------------------------------------------------------- #


def _decode_ipv4(pkt: Packet, data: bytes, off: int) -> None:
    avail = len(data) - off
    if avail < 20:
        raise _Malformed("ipv4: short header")
    vhl, _tos, total_len, ip_id, frag, ttl, proto, _csum, src, dst = _IPV4.unpack_from(data, off)
    if vhl >> 4 != 4:
        raise _Malformed("ipv4: bad version")
    ihl = (vhl & 0x0F) * 4
    if ihl < 20:
        raise _Malformed("ipv4: bad ihl")
    pkt.ip_ver = 4
    pkt.src = _ip4(src)
    pkt.dst = _ip4(dst)
    pkt.ttl = ttl
    pkt.ip_id = ip_id
    pkt.df = bool(frag & 0x4000)
    pkt.mf = bool(frag & 0x2000)
    pkt.frag_off = (frag & 0x1FFF) * 8
    pkt.proto = proto
    if ihl > avail:
        raise _Malformed("ipv4: ihl beyond capture")
    if total_len < ihl:
        pkt.ip_len = 0
        raise _Malformed("ipv4: total length < header")
    pkt.ip_len = total_len - ihl  # L3 payload length on the wire
    end = off + min(total_len, avail)  # ignore Ethernet padding; tolerate snaplen
    if pkt.frag_off == 0:
        _decode_l4(pkt, data, off + ihl, end, pkt.ip_len, proto)


def _decode_ipv6(pkt: Packet, data: bytes, off: int) -> None:
    avail = len(data) - off
    if avail < 40:
        raise _Malformed("ipv6: short header")
    vtcfl, plen, nh, hlim, src, dst = _IPV6.unpack_from(data, off)
    if vtcfl >> 28 != 6:
        raise _Malformed("ipv6: bad version")
    pkt.ip_ver = 6
    pkt.src = _ip6(src)
    pkt.dst = _ip6(dst)
    pkt.ttl = hlim
    end = off + 40 + min(plen, avail - 40)
    pos = off + 40
    remaining = plen  # upper-layer length, shrinks as ext headers are consumed
    count = 0
    while nh in IPV6_EXT_HEADERS:
        count += 1
        if count > MAX_IPV6_EXT:
            pkt.proto = nh
            raise _Malformed("ipv6: too many extension headers")
        if pos + 8 > end:
            pkt.proto = nh
            raise _Malformed("ipv6: truncated extension header")
        if nh == 44:  # fragment header: fixed 8 bytes
            fo = _U16.unpack_from(data, pos + 2)[0]
            pkt.frag_off = (fo & 0xFFF8)
            pkt.mf = bool(fo & 1)
            pkt.ip_id = _U32.unpack_from(data, pos + 4)[0]
            hlen = 8
        elif nh == 51:  # AH: length in 4-byte words minus 2
            hlen = (data[pos + 1] + 2) * 4
        else:
            hlen = (data[pos + 1] + 1) * 8
        nh = data[pos]
        pos += hlen
        remaining -= hlen
        if pos > end or remaining < 0:
            pkt.proto = nh
            raise _Malformed("ipv6: extension header beyond payload")
    pkt.proto = nh
    pkt.ip_len = max(remaining, 0)
    if pkt.frag_off == 0:
        _decode_l4(pkt, data, pos, end, pkt.ip_len, nh)


# --------------------------------------------------------------------------- #
# L4
# --------------------------------------------------------------------------- #


def _decode_l4(pkt: Packet, data: bytes, off: int, end: int, ip_len: int, proto: int) -> None:
    """Dispatch on IP protocol. ``end`` bounds the IP payload actually captured."""
    if proto == IPPROTO_TCP:
        _decode_tcp(pkt, data, off, end, ip_len)
    elif proto == IPPROTO_UDP:
        _decode_udp(pkt, data, off, end, ip_len)
    elif proto == IPPROTO_ICMP:
        _decode_icmp(pkt, data, off, end, False)
    elif proto == IPPROTO_ICMPV6:
        _decode_icmp(pkt, data, off, end, True)


def _decode_tcp(pkt: Packet, data: bytes, off: int, end: int, ip_len: int) -> None:
    if end - off < 20:
        raise _Malformed("tcp: short header")
    sport, dport, seq, ack, doff_byte, flags, win, _csum, _urg = _TCP.unpack_from(data, off)
    hlen = (doff_byte >> 4) * 4
    plen = ip_len - hlen
    tcp = Tcp(sport, dport, seq, ack, flags, win, hlen, max(plen, 0))
    pkt.tcp = tcp
    if hlen < 20:
        raise _Malformed("tcp: bad data offset")
    if off + hlen > end:
        raise _Malformed("tcp: header beyond capture")
    if plen < 0:
        raise _Malformed("tcp: header longer than ip payload")
    pkt.payload_len = plen
    if hlen > 20:
        _decode_tcp_options(pkt, tcp, data, off + 20, off + hlen)
    pstart = off + hlen
    if pstart < end:
        _decode_tcp_payload(pkt, tcp, data, pstart, end)


def _decode_tcp_options(pkt: Packet, tcp: Tcp, data: bytes, pos: int, end: int) -> None:
    n = 0
    while pos < end and n < TCP_MAX_OPTIONS:
        n += 1
        kind = data[pos]
        if kind == 0:  # EOL
            return
        if kind == 1:  # NOP
            pos += 1
            continue
        if pos + 1 >= end:
            pkt.malformed = pkt.malformed or "tcp: truncated option"
            return
        olen = data[pos + 1]
        if olen < 2 or pos + olen > end:
            pkt.malformed = pkt.malformed or "tcp: bad option length"
            return
        if kind == 2 and olen == 4:
            tcp.mss = _U16.unpack_from(data, pos + 2)[0]
        elif kind == 3 and olen == 3:
            tcp.wscale = data[pos + 2]
        elif kind == 4 and olen == 2:
            tcp.sack_perm = True
        elif kind == 5 and olen >= 10 and (olen - 2) % 8 == 0:
            tcp.sacks = [
                struct.unpack_from("!II", data, pos + 2 + 8 * i) for i in range((olen - 2) // 8)
            ]
        elif kind == 8 and olen == 10:
            tcp.tsval, tcp.tsecr = struct.unpack_from("!II", data, pos + 2)
        pos += olen


_PRINTABLE = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


_SHELL_MARKERS = (b"Microsoft Windows", b"C:\\", b"uid=", b"/bin/sh", b"/bin/bash", b"root@", b"Volume in drive")


def _text_kind(data: bytes, start: int, end: int) -> str:
    """Classify readable text found on the DNS port (marker search only; the payload itself is never kept)."""
    chunk = bytes(data[start:min(end, start + 512)])
    return "shell on DNS port" if any(m in chunk for m in _SHELL_MARKERS) else "text on DNS port"


def _looks_like_text(data: bytes, start: int, end: int) -> bool:
    """True if a payload is human-readable text (DNS messages are binary, so text on port 53 is a red flag)."""
    chunk = data[start:min(end, start + 128)]
    if len(chunk) < 4:
        return False
    printable = sum(1 for b in chunk if b in _PRINTABLE)
    return printable / len(chunk) >= 0.9


def _decode_tcp_payload(pkt: Packet, tcp: Tcp, data: bytes, pos: int, end: int) -> None:
    """Application-layer sniffing over a TCP segment's captured payload."""
    sport, dport = tcp.sport, tcp.dport
    if sport in DNS_PORTS or dport in DNS_PORTS:
        if end - pos >= 2:
            mlen = _U16.unpack_from(data, pos)[0]
            if pos + 2 + mlen <= end and mlen >= 12:
                _decode_dns(pkt, data, pos + 2, pos + 2 + mlen, "tcp")
        if pkt.dns is None and (sport == 53 or dport == 53) and _looks_like_text(data, pos, end):
            pkt.app_anomaly = _text_kind(data, pos, end)
        return
    first = data[pos]
    if 20 <= first <= 23 and end - pos >= 5:
        if _decode_tls(pkt, data, pos, end):
            return
    if _decode_http(pkt, data, pos, end):
        return
    _detect_cleartext_cred(pkt, sport, dport, data, pos, end)


def _decode_udp(pkt: Packet, data: bytes, off: int, end: int, ip_len: int) -> None:
    if end - off < 8:
        raise _Malformed("udp: short header")
    sport, dport, ulen, _csum = _UDP.unpack_from(data, off)
    if ulen < 8:
        pkt.udp = Udp(sport, dport, 0)
        raise _Malformed("udp: bad length")
    if ulen > ip_len:
        pkt.udp = Udp(sport, dport, max(ip_len - 8, 0))
        raise _Malformed("udp: length exceeds ip payload")
    plen = ulen - 8
    pkt.udp = Udp(sport, dport, plen)
    pkt.payload_len = plen
    pstart = off + 8
    pend = min(end, pstart + plen)
    if pend <= pstart:
        return
    if sport in DNS_PORTS or dport in DNS_PORTS:
        _decode_dns(pkt, data, pstart, pend, "udp")
        if pkt.dns is None and (sport == 53 or dport == 53) and _looks_like_text(data, pstart, pend):
            pkt.app_anomaly = _text_kind(data, pstart, pend)
    elif sport in DHCP_PORTS or dport in DHCP_PORTS:
        _decode_dhcp(pkt, data, pstart, pend)


# --------------------------------------------------------------------------- #
# ICMP
# --------------------------------------------------------------------------- #

ICMP4_ERRORS = frozenset((3, 4, 5, 11, 12))
ICMP6_ERRORS = frozenset((1, 2, 3, 4))


def _decode_icmp(pkt: Packet, data: bytes, off: int, end: int, v6: bool) -> None:
    if end - off < 4:
        raise _Malformed("icmp: short header")
    typ, code, _csum = _ICMP.unpack_from(data, off)
    icmp = Icmp(v6, typ, code)
    pkt.icmp = icmp
    pkt.payload_len = max(end - off - 8, 0)
    body = off + 4
    if end - body < 4:
        return
    if not v6:
        if typ in (8, 0):
            icmp.echo_id, icmp.echo_seq = struct.unpack_from("!HH", data, body)
        elif typ == 3 and code == 4:
            icmp.mtu = _U16.unpack_from(data, body + 2)[0]
        elif typ == 5:
            icmp.gateway = _ip4(data[body:body + 4])
        if typ in ICMP4_ERRORS:
            icmp.inner = _decode_inner(data, body + 4, end, False)
    else:
        if typ in (128, 129):
            icmp.echo_id, icmp.echo_seq = struct.unpack_from("!HH", data, body)
        elif typ == 2:
            icmp.mtu = _U32.unpack_from(data, body)[0]
        if typ in ICMP6_ERRORS:
            icmp.inner = _decode_inner(data, body + 4, end, True)


def _decode_inner(data: bytes, off: int, end: int, v6: bool):
    """Best-effort decode of the datagram quoted in an ICMP error."""
    try:
        if v6:
            if end - off < 40:
                return None
            _v, _pl, proto, hlim, src, dst = _IPV6.unpack_from(data, off)
            inner = IcmpInner(_ip6(src), _ip6(dst), proto, ttl=hlim)
            l4 = off + 40
        else:
            if end - off < 20:
                return None
            vhl, _t, _tl, ip_id, _f, ttl, proto, _c, src, dst = _IPV4.unpack_from(data, off)
            ihl = (vhl & 0x0F) * 4
            if vhl >> 4 != 4 or ihl < 20:
                return None
            inner = IcmpInner(_ip4(src), _ip4(dst), proto, ip_id=ip_id, ttl=ttl)
            l4 = off + ihl
        if proto in (IPPROTO_TCP, IPPROTO_UDP) and end - l4 >= 4:
            inner.sport, inner.dport = struct.unpack_from("!HH", data, l4)
        return inner
    except (struct.error, IndexError, ValueError):
        return None


# --------------------------------------------------------------------------- #
# DNS
# --------------------------------------------------------------------------- #


def _dns_label_text(raw: bytes) -> str:
    out = []
    for b in raw:
        if 0x21 <= b < 0x7F and b != 0x2E:  # printable, not '.'
            out.append(chr(b))
        else:
            out.append(f"\\x{b:02x}")
    return "".join(out)


def _dns_name(data: bytes, pos: int, start: int, end: int) -> tuple[str, int]:
    """Read a (possibly compressed) name at ``pos``.

    Returns (name, position after the name in the *original* stream).
    ``start`` is the DNS message start (pointer base). Pointers must point
    backwards (to an offset lower than the current one), which rules out loops.
    """
    labels: list[str] = []
    total = 0
    jumps = 0
    after = -1
    while True:
        if pos >= end:
            raise _Malformed("dns: name beyond message")
        length = data[pos]
        if length == 0:
            pos += 1
            break
        kind = length & 0xC0
        if kind == 0xC0:
            if pos + 1 >= end:
                raise _Malformed("dns: truncated pointer")
            target = start + (((length & 0x3F) << 8) | data[pos + 1])
            if target >= pos or target < start:
                raise _Malformed("dns: bad compression pointer")
            jumps += 1
            if jumps > DNS_MAX_JUMPS:
                raise _Malformed("dns: pointer loop")
            if after < 0:
                after = pos + 2
            pos = target
            continue
        if kind != 0:
            raise _Malformed("dns: unsupported label type")
        if length > DNS_MAX_LABEL:
            raise _Malformed("dns: label too long")
        total += length + 1
        if total > DNS_MAX_NAME:
            raise _Malformed("dns: name too long")
        if pos + 1 + length > end:
            raise _Malformed("dns: label beyond message")
        labels.append(_dns_label_text(data[pos + 1:pos + 1 + length]))
        pos += 1 + length
    if after < 0:
        after = pos
    return ".".join(labels).lower(), after


def _dns_rdata(data: bytes, rtype: int, pos: int, rdlen: int, start: int, end: int) -> str:
    if rtype == 1 and rdlen == 4:
        return _ip4(data[pos:pos + 4])
    if rtype == 28 and rdlen == 16:
        return _ip6(data[pos:pos + 16])
    if rtype in (5, 2, 12):  # CNAME, NS, PTR
        return _dns_name(data, pos, start, pos + rdlen)[0]
    if rtype == 16:  # TXT: sequence of <len><chars>
        parts = []
        p, stop, n = pos, pos + rdlen, 0
        while p < stop and n < 64:
            n += 1
            ln = data[p]
            chunk = data[p + 1:min(p + 1 + ln, stop)]
            parts.append("".join(chr(b) if 0x20 <= b < 0x7F else f"\\x{b:02x}" for b in chunk))
            p += 1 + ln
        return "".join(parts)[:255]
    return ""


def _decode_dns(pkt: Packet, data: bytes, start: int, end: int, transport: str) -> None:
    try:
        if end - start < 12:
            raise _Malformed("dns: short header")
        dns = Dns()
        dns.transport = transport
        dns.id, flags, qd, an, ns, ar = _DNS_HDR.unpack_from(data, start)
        dns.qr = bool(flags & 0x8000)
        dns.opcode = (flags >> 11) & 0xF
        dns.aa = bool(flags & 0x0400)
        dns.tc = bool(flags & 0x0200)
        dns.rd = bool(flags & 0x0100)
        dns.ra = bool(flags & 0x0080)
        dns.rcode = flags & 0xF
        dns.ancount, dns.nscount, dns.arcount = an, ns, ar
        pos = start + 12
        for i in range(min(qd, DNS_MAX_SECTION_RRS)):
            name, pos = _dns_name(data, pos, start, end)
            if pos + 4 > end:
                raise _Malformed("dns: truncated question")
            qtype = _U16.unpack_from(data, pos)[0]
            pos += 4
            if i == 0:
                dns.qname, dns.qtype = name, qtype
        for i in range(min(an, DNS_MAX_ANSWERS)):
            name, pos = _dns_name(data, pos, start, end)
            if pos + 10 > end:
                raise _Malformed("dns: truncated answer")
            rtype, _rclass, ttl, rdlen = _DNS_RR.unpack_from(data, pos)
            pos += 10
            if pos + rdlen > end:
                raise _Malformed("dns: rdata beyond message")
            rdata = _dns_rdata(data, rtype, pos, rdlen, start, end)
            pos += rdlen
            dns.answers.append(DnsRR(name, rtype, ttl, rdata))
        pkt.dns = dns
    except _Malformed as e:
        pkt.dns = None
        pkt.malformed = str(e)
    except (struct.error, IndexError, ValueError):
        pkt.dns = None
        pkt.malformed = "dns: truncated"


# --------------------------------------------------------------------------- #
# DHCP
# --------------------------------------------------------------------------- #


def _decode_dhcp(pkt: Packet, data: bytes, start: int, end: int) -> None:
    try:
        if end - start < 240:
            raise _Malformed("dhcp: short header")
        op, htype, hlen, _hops, xid, _secs, _flags, ciaddr, yiaddr, siaddr, _giaddr, chaddr = _BOOTP.unpack_from(
            data, start
        )
        if data[start + 236:start + 240] != DHCP_MAGIC:
            raise _Malformed("dhcp: bad magic cookie")
        d = Dhcp()
        d.op, d.xid = op, xid
        d.ciaddr, d.yiaddr, d.siaddr = _ip4(ciaddr), _ip4(yiaddr), _ip4(siaddr)
        d.chaddr = chaddr[:6].hex(":") if hlen == 6 else chaddr[:min(hlen, 16)].hex(":")
        pos = start + 240
        n = 0
        while pos < end and n < DHCP_MAX_OPTIONS:
            n += 1
            code = data[pos]
            if code == 255:
                break
            if code == 0:
                pos += 1
                continue
            if pos + 1 >= end:
                pkt.malformed = pkt.malformed or "dhcp: truncated option"
                break
            olen = data[pos + 1]
            vpos = pos + 2
            if vpos + olen > end:
                pkt.malformed = pkt.malformed or "dhcp: option beyond message"
                break
            val = data[vpos:vpos + olen]
            if code == 53 and olen >= 1:
                d.msg_type = val[0]
            elif code == 54 and olen == 4:
                d.server_id = _ip4(val)
            elif code == 50 and olen == 4:
                d.requested_ip = _ip4(val)
            elif code == 3 and olen >= 4:
                d.routers = [_ip4(val[i:i + 4]) for i in range(0, olen - olen % 4, 4)]
            elif code == 6 and olen >= 4:
                d.dns_servers = [_ip4(val[i:i + 4]) for i in range(0, olen - olen % 4, 4)]
            elif code == 51 and olen == 4:
                d.lease_time = _U32.unpack(val)[0]
            elif code == 1 and olen == 4:
                d.subnet_mask = _ip4(val)
            elif code == 12 and olen >= 1:
                d.hostname = _printable(val.decode("latin-1"), 64)
            pos = vpos + olen
        pkt.dhcp = d
    except _Malformed as e:
        pkt.malformed = str(e)
    except (struct.error, IndexError, ValueError):
        pkt.malformed = "dhcp: truncated"


# --------------------------------------------------------------------------- #
# TLS
# --------------------------------------------------------------------------- #


def _decode_tls(pkt: Packet, data: bytes, pos: int, end: int) -> bool:
    """Parse TLS records in a segment. Returns False if it does not look like TLS."""
    ctype, version, rlen = _TLS_REC.unpack_from(data, pos)
    if not (20 <= ctype <= 23 and 0x0300 <= version <= 0x0304 and rlen <= TLS_MAX_RECORD):
        return False
    tls = Tls()
    pkt.tls = tls
    n = 0
    try:
        while end - pos >= 5 and n < TLS_MAX_RECORDS:
            n += 1
            ctype, version, rlen = _TLS_REC.unpack_from(data, pos)
            if not (20 <= ctype <= 23 and 0x0300 <= version <= 0x0304 and rlen <= TLS_MAX_RECORD):
                break  # not a record boundary any more (e.g. mid-stream data)
            body = pos + 5
            bend = min(body + rlen, end)  # partial record: parse what we have
            if ctype == TLS_HANDSHAKE:
                tls.record_version = version
                _decode_tls_handshake(tls, data, body, bend)
            elif ctype == TLS_ALERT and rlen == 2 and bend - body == 2:
                tls.alerts.append((data[body], data[body + 1]))
            if body + rlen > end:
                break  # continues in the next segment
            pos = body + rlen
    except (struct.error, IndexError, ValueError):
        pkt.malformed = pkt.malformed or "tls: truncated"
    return True


def _decode_tls_handshake(tls: Tls, data: bytes, pos: int, end: int) -> None:
    n = 0
    while end - pos >= 4 and n < 8:
        n += 1
        htype = data[pos]
        hlen = int.from_bytes(data[pos + 1:pos + 4], "big")
        tls.handshake_types.append(htype)
        body = pos + 4
        bend = min(body + hlen, end)
        if htype == 1:
            _decode_hello(tls, data, body, bend, client=True)
        elif htype == 2:
            _decode_hello(tls, data, body, bend, client=False)
        pos = body + hlen


def _decode_hello(tls: Tls, data: bytes, pos: int, end: int, client: bool) -> None:
    if end - pos < 2 + 32 + 1:
        return
    legacy_version = _U16.unpack_from(data, pos)[0]
    if client:
        tls.client_version = legacy_version
    pos += 34
    sid_len = data[pos]
    pos += 1 + sid_len
    if client:
        if pos + 2 > end:
            return
        cs_len = _U16.unpack_from(data, pos)[0]
        pos += 2 + cs_len
        if pos + 1 > end:
            return
        pos += 1 + data[pos]  # compression methods
    else:
        pos += 2 + 1  # cipher suite + compression method
    if pos + 2 > end:
        return
    ext_total = _U16.unpack_from(data, pos)[0]
    pos += 2
    ext_end = min(pos + ext_total, end)
    n = 0
    while ext_end - pos >= 4 and n < TLS_MAX_EXTENSIONS:
        n += 1
        etype, elen = struct.unpack_from("!HH", data, pos)
        epos = pos + 4
        if epos + elen > ext_end:
            break
        if etype == 0 and client:
            _decode_sni(tls, data, epos, epos + elen)
        elif etype == 43:
            if client:
                if elen >= 1:
                    ll = data[epos]
                    vals = data[epos + 1:epos + 1 + min(ll, elen - 1)]
                    tls.supported_versions = [
                        _U16.unpack_from(vals, i)[0] for i in range(0, len(vals) - len(vals) % 2, 2)
                    ][:16]
            elif elen == 2:
                tls.supported_versions = [_U16.unpack_from(data, epos)[0]]
        pos = epos + elen


def _decode_sni(tls: Tls, data: bytes, pos: int, end: int) -> None:
    if end - pos < 5:
        return
    pos += 2  # server name list length
    ntype = data[pos]
    nlen = _U16.unpack_from(data, pos + 1)[0]
    pos += 3
    if ntype != 0 or pos + nlen > end:
        return
    name = data[pos:pos + min(nlen, TLS_MAX_SNI)]
    tls.sni = _printable(name.decode("ascii", "replace"), TLS_MAX_SNI) or None


# --------------------------------------------------------------------------- #
# HTTP and cleartext credential protocols
# --------------------------------------------------------------------------- #


def _decode_http(pkt: Packet, data: bytes, pos: int, end: int) -> bool:
    head = data[pos:min(end, pos + HTTP_MAX_SCAN)]
    is_req = head.startswith(HTTP_METHODS)
    if not is_req and not head.startswith(b"HTTP/1."):
        return False
    http = Http()
    http.is_request = is_req
    lines = head.split(b"\r\n", HTTP_MAX_HEADERS + 1)
    first = lines[0].split(b"\n", 1)[0]
    parts = first.split(b" ", 2)
    try:
        if is_req:
            http.method = parts[0].decode("ascii")
            if len(parts) > 1:
                path = parts[1].split(b"?", 1)[0].split(b"#", 1)[0]
                http.path = _printable(path.decode("latin-1"), 200)
        else:
            if len(parts) < 2 or not parts[1].isdigit() or len(parts[1]) != 3:
                pkt.http = http
                pkt.malformed = pkt.malformed or "http: bad status line"
                return True
            http.status = int(parts[1])
            http.reason = _printable(parts[2].decode("latin-1"), 60) if len(parts) > 2 else ""
        for line in lines[1:HTTP_MAX_HEADERS + 1]:
            if not line:
                break
            colon = line.find(b":")
            if colon <= 0:
                continue
            name = line[:colon].strip().lower()
            if name == b"host":
                http.host = _printable(line[colon + 1:].strip().decode("latin-1"), 100)
            elif name == b"user-agent":
                http.user_agent = _printable(line[colon + 1:].strip().decode("latin-1"), 120)
            elif name in (b"authorization", b"proxy-authorization"):
                scheme = line[colon + 1:].strip().split(b" ", 1)[0].lower()
                if scheme == b"basic":
                    pkt.cred = "HTTP Basic"  # the credential itself is never stored
    except (UnicodeDecodeError, ValueError):
        pkt.malformed = pkt.malformed or "http: bad encoding"
    pkt.http = http
    return True


def _detect_cleartext_cred(pkt: Packet, sport: int, dport: int, data: bytes, pos: int, end: int) -> None:
    """Flag cleartext authentication by protocol label only; never store the secret."""
    head = data[pos:min(end, pos + 64)]
    if dport == 21 and head.startswith(b"PASS "):
        pkt.cred = "FTP"
    elif dport == 110 and head.startswith(b"PASS "):
        pkt.cred = "POP3"
    elif dport == 143:
        parts = head.split(b" ", 2)
        if len(parts) >= 2 and parts[1].upper() == b"LOGIN":
            pkt.cred = "IMAP"
    elif dport in (25, 587):
        up = head.upper()
        if up.startswith(b"AUTH PLAIN") or up.startswith(b"AUTH LOGIN"):
            pkt.cred = "SMTP AUTH"
    elif sport == 23 or dport == 23:
        # server->client prompt: the server side is the one speaking from port 23
        if sport == 23:
            low = data[pos:min(end, pos + 512)].lower()
            if b"login:" in low or b"password:" in low:
                pkt.cred = "Telnet"
