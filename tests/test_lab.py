"""Tests for the synthetic capture lab: craft.py builders, scenarios and sample files."""

from __future__ import annotations

import json
import os
import struct

import pytest

from faultline.lab import craft, scenarios
from faultline.lab.craft import (
    Capture, Lan, TcpSession, inet_checksum, ipv4, tcp_seg, udp_dgram, dns_query, dns_response,
    dhcp_msg, tls_client_hello, arp_frame, icmp_unreachable,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(ROOT, "samples")

VALID_KINDS = {
    "tcp.retransmissions", "tcp.refused", "tcp.syn_timeout", "tcp.zero_window", "arp.unanswered",
    "arp.duplicate_ip", "latency.slow_server", "latency.high_rtt", "mtu.blackhole", "mtu.frag_needed",
    "dns.timeout", "dns.errors", "dhcp.multiple_servers", "dhcp.no_server", "icmp.routing_loop",
    # attack-pattern scenarios (faultline/lab/scenarios_attack.py)
    "scan.port", "scan.host_sweep", "dns.hijack", "dns.tunneling", "flood.syn", "cred.cleartext",
    "tls.failure", "http.errors",
}


# ---------------------------------------------------------------------------
# a tiny pcap reader + checksum verifier, independent of the product code
# ---------------------------------------------------------------------------

def read_pcap(path: str):
    with open(path, "rb") as fh:
        data = fh.read()
    magic = data[:4]
    assert magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"), f"bad magic in {path}"
    ver_major, ver_minor, _, _, snaplen, linktype = struct.unpack("<HHiIII", data[4:24])
    assert (ver_major, ver_minor) == (2, 4) and linktype == 1
    off = 24
    out = []
    while off < len(data):
        sec, frac, caplen, wirelen = struct.unpack("<IIII", data[off:off + 16])
        off += 16
        frame = data[off:off + caplen]
        assert len(frame) == caplen, f"truncated record in {path}"
        out.append((sec + frac / 1e6, frame))
        off += caplen
    return out


def read_pcapng(path: str):
    with open(path, "rb") as fh:
        data = fh.read()
    assert data[:4] == b"\x0a\x0d\x0d\x0a"
    off = 0
    out = []
    while off < len(data):
        btype, blen = struct.unpack("<II", data[off:off + 8])
        assert blen >= 12 and struct.unpack("<I", data[off + blen - 4:off + blen])[0] == blen
        if btype == 6:
            _, hi, lo, caplen, wirelen = struct.unpack("<IIIII", data[off + 8:off + 28])
            out.append((((hi << 32) | lo) / 1e6, data[off + 28:off + 28 + caplen]))
        off += blen
    return out


def verify_frame(frame: bytes) -> list[str]:
    """Return a list of checksum problems in an Ethernet/IPv4 frame (empty = ok)."""
    problems = []
    et = struct.unpack("!H", frame[12:14])[0]
    off = 14
    if et == 0x8100:
        et = struct.unpack("!H", frame[16:18])[0]
        off = 18
    if et != 0x0800:
        return problems
    ip = frame[off:]
    ihl = (ip[0] & 0xF) * 4
    total = struct.unpack("!H", ip[2:4])[0]
    if inet_checksum(ip[:ihl]) != 0:
        problems.append("ipv4")
    proto = ip[9]
    src, dst = ip[12:16], ip[16:20]
    l4 = ip[ihl:total]
    pseudo = src + dst + struct.pack("!BBH", 0, proto, len(l4))
    if proto == 6:
        if inet_checksum(pseudo + l4) != 0:
            problems.append("tcp")
    elif proto == 17:
        if struct.unpack("!H", l4[6:8])[0] != 0 and inet_checksum(pseudo + l4) != 0:
            problems.append("udp")
    elif proto == 1:
        if inet_checksum(l4) != 0:
            problems.append("icmp")
    return problems


# ---------------------------------------------------------------------------
# builders
# ---------------------------------------------------------------------------

def test_primitive_checksums():
    lan = Lan()
    c, gw = lan.clients[0], lan.gateway
    frames = [
        lan.frame(ipv4(c.ip, gw.ip, 17, udp_dgram(c.ip, gw.ip, 4000, 53, dns_query(1, "example.com"))), c.ip, gw.ip),
        lan.frame(ipv4(c.ip, "93.184.216.34", 6, tcp_seg(c.ip, "93.184.216.34", 5000, 443, 1, 0, "S", mss=1460,
                                                        wscale=7, sack_perm=True, ts=(1, 0))), c.ip, "93.184.216.34"),
        lan.frame(ipv4(c.ip, "93.184.216.34", 6, tcp_seg(c.ip, "93.184.216.34", 5000, 443, 1, 1, "A",
                                                        sacks=[(10, 20), (30, 40)], ts=(1, 2))), c.ip, "93.184.216.34"),
        lan.frame(ipv4(gw.ip, c.ip, 1, icmp_unreachable(4, ipv4(c.ip, gw.ip, 6, b"\x00" * 40), mtu=1400)), gw.ip, c.ip),
    ]
    for f in frames:
        assert verify_frame(f) == []
    # UDP payload with odd length
    f = lan.frame(ipv4(c.ip, gw.ip, 17, udp_dgram(c.ip, gw.ip, 4000, 53, b"abc")), c.ip, gw.ip)
    assert verify_frame(f) == []


def test_tcp_options_and_lengths():
    seg = tcp_seg("1.1.1.1", "2.2.2.2", 1, 2, 0, 0, "S", mss=1460, wscale=7, sack_perm=True, ts=(5, 0))
    doff = (seg[12] >> 4) * 4
    assert doff == 40 and len(seg) == 40
    assert seg[13] == 0x02
    seg = tcp_seg("1.1.1.1", "2.2.2.2", 1, 2, 0, 0, "PA", payload=b"hi")
    assert (seg[12] >> 4) == 5 and seg[13] == 0x18 and seg[-2:] == b"hi"


def test_dns_and_dhcp_shapes():
    r = dns_response(7, "www.example.com", "A", [("CNAME", "edge.example.net", 60), ("A", "93.184.216.34", 300)])
    assert struct.unpack("!HHHH", r[:8]) == (7, 0x8180, 1, 2)
    assert b"\xc0\x0c" in r
    d = dhcp_msg(1, 1, "00:11:22:33:44:55", 1, hostname="x")
    assert len(d) >= 300 and d[236:240] == b"\x63\x82\x53\x63" and d[240:243] == bytes([53, 1, 1])
    assert b"\xff" in d[240:]


def test_tls_client_hello_lengths():
    rec = tls_client_hello("docs.example.org")
    assert rec[0] == 0x16
    rec_len = struct.unpack("!H", rec[3:5])[0]
    assert rec_len == len(rec) - 5
    assert rec[5] == 1 and int.from_bytes(rec[6:9], "big") == rec_len - 4
    assert b"docs.example.org" in rec


def test_arp_frame_broadcast_and_unicast():
    req = arp_frame(1, "00:11:22:33:44:55", "192.168.1.10", "00:00:00:00:00:00", "192.168.1.1")
    assert req[:6] == b"\xff" * 6 and len(req) == 42
    rep = arp_frame(2, "aa:bb:cc:dd:ee:ff", "192.168.1.1", "00:11:22:33:44:55", "192.168.1.10")
    assert rep[:6] == craft.mac_bytes("00:11:22:33:44:55")


# ---------------------------------------------------------------------------
# TcpSession consistency
# ---------------------------------------------------------------------------

def _tcp_view(frames):
    """Yield (ts, src_ip, sport, seq, ack, flags, payload_len) for TCP frames."""
    for ts, f in frames:
        if struct.unpack("!H", f[12:14])[0] != 0x0800:
            continue
        ip = f[14:]
        ihl = (ip[0] & 0xF) * 4
        if ip[9] != 6:
            continue
        total = struct.unpack("!H", ip[2:4])[0]
        tcp = ip[ihl:total]
        sport, dport, seq, ack, doff_flags, flags = struct.unpack("!HHIIBB", tcp[:14])
        doff = (doff_flags >> 4) * 4
        yield ts, ".".join(map(str, ip[12:16])), sport, seq, ack, flags, len(tcp) - doff


def test_tcpsession_seq_ack_consistency():
    lan = Lan()
    cap = Capture(lan, seed=5)
    c = lan.clients[0]
    srv = lan.server("docs.example.org")
    s = TcpSession(cap, c, srv, 51000, 443, 0.03, cap.t0)
    s.handshake()
    s.client_send(b"x" * 500)
    s.server_send(50_000, loss_down=0.05, loss_up=0.05)
    s.zero_window(1.0)
    s.server_send(10_000)
    s.close()
    frames = cap.sorted_frames()
    tss = [ts for ts, _ in frames]
    assert tss == sorted(tss)
    seen = list(_tcp_view(frames))
    client = [x for x in seen if x[1] == c.ip]
    server = [x for x in seen if x[1] == srv.ip]
    c_isn, s_isn = client[0][3], server[0][3]
    # byte coverage of server data is contiguous and acknowledged exactly
    s_bytes = set()
    for _, _, _, seq, _, flags, plen in server:
        for i in range(plen):
            s_bytes.add((seq + i - s_isn - 1) & 0xFFFFFFFF)
    assert s_bytes == set(range(60_000))              # 50_000 + 10_000; the zero-window probe byte is the next data byte
    final_ack = max(ack for _, _, _, _, ack, flags, _ in client if flags & 0x10)
    assert (final_ack - s_isn) & 0xFFFFFFFF == 60_000 + 1 + 1   # data + SYN + FIN
    # ACKs never run ahead of what the peer has sent
    hi_server = max(((seq + plen) - s_isn) & 0xFFFFFFFF for _, _, _, seq, _, _, plen in server)
    for _, _, _, _, ack, flags, _ in client:
        if flags & 0x10:
            assert ((ack - s_isn) & 0xFFFFFFFF) <= hi_server + 1
    # client data: 500 bytes, acknowledged by the server
    hi_client = max(((seq + plen) - c_isn) & 0xFFFFFFFF for _, _, _, seq, _, _, plen in client)
    assert hi_client == 500 + 1 + 1
    assert max(ack for *_, ack, flags, _ in [(x[0], x[4], x[5], x[6]) for x in server] if flags & 0x10) - c_isn == 502
    # the download really contains retransmissions (duplicated seq numbers)
    seqs = [seq for _, _, _, seq, _, _, plen in server if plen > 1]
    assert len(seqs) > len(set(seqs))
    for _, f in frames:
        assert verify_frame(f) == []


def test_capture_timing_causal():
    lan = Lan()
    cap = Capture(lan, seed=2)
    s = TcpSession(cap, lan.clients[1], lan.server("www.example.com"), 50000, 443, 0.05, cap.t0)
    t_syn = cap.t0
    t_done = s.handshake()
    assert 0.045 <= t_done - t_syn <= 0.06
    t_req = s.now
    s.client_send(100)
    s.server_send(2000, think=1.0)
    first_data = min(ts for ts, _, _, _, _, fl, plen in _tcp_view(cap.sorted_frames()) if plen > 100)
    assert 1.04 <= first_data - t_req <= 1.07


# ---------------------------------------------------------------------------
# scenarios and sample files
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def generated(tmp_path_factory):
    out = str(tmp_path_factory.mktemp("samples"))
    labels = scenarios.generate_all(out, seed=1, verbose=False)
    return out, labels


def test_generated_files_valid_and_checksums(generated):
    out, labels = generated
    for fname, lab in labels.items():
        path = os.path.join(out, fname)
        assert os.path.exists(path), fname
        if lab["malformed"]:
            continue
        frames = read_pcapng(path) if fname.endswith(".pcapng") else read_pcap(path)
        assert len(frames) > 50, fname
        tss = [ts for ts, _ in frames]
        assert tss == sorted(tss), f"non-monotonic timestamps in {fname}"
        assert abs(tss[0] - Capture.DEFAULT_T0) < 5.0
        bad = [verify_frame(f) for _, f in frames]
        assert not any(bad), f"checksum problems in {fname}: {[b for b in bad if b][:3]}"


def test_labels_well_formed(generated):
    _, labels = generated
    assert len(labels) >= 22
    for fname, lab in labels.items():
        assert {"title", "story", "expected", "must_not", "clean", "malformed"} <= set(lab), fname
        assert lab["story"].endswith(".") and len(lab["story"].split()) >= 3
        for e in lab["expected"]:
            assert e["kind"] in VALID_KINDS, (fname, e)
            assert e["category"] in ("fault", "misconfig", "attack")
        if lab["clean"] or lab["malformed"]:
            assert lab["expected"] == []
        else:
            assert lab["expected"], fname
    expected_files = {name for name, _, _ in scenarios.SCENARIOS}
    assert expected_files <= set(labels)


def test_determinism(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    only = {"routing_loop.pcap", "lossy_link.pcap", "pcapng_office.pcapng"}
    scenarios.generate(str(a), seed=1, only=only, verbose=False)
    scenarios.generate(str(b), seed=1, only=only, verbose=False)
    for f in only:
        assert (a / f).read_bytes() == (b / f).read_bytes(), f
    scenarios.generate(str(tmp_path / "c"), seed=2, only={"routing_loop.pcap"}, verbose=False)
    assert (tmp_path / "c" / "routing_loop.pcap").read_bytes() != (a / "routing_loop.pcap").read_bytes()


def test_malformed_files(generated):
    out, _ = generated
    m = os.path.join(out, "malformed")
    assert os.path.getsize(os.path.join(m, "zero_length.pcap")) == 0
    with open(os.path.join(m, "huge_caplen.pcap"), "rb") as fh:
        data = fh.read()
    assert struct.pack("<I", 0x7FFFFFFF) in data
    assert os.path.getsize(os.path.join(m, "compressed_padding.pcap.gz")) < 200_000
    with open(os.path.join(m, "bad_magic.pcap"), "rb") as fh:
        assert fh.read(4) not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a")


def test_repo_samples_present_and_small():
    """The committed samples/ directory must exist for judges and stay under 15 MB."""
    if not os.path.isdir(SAMPLES) or not os.path.exists(os.path.join(SAMPLES, "labels.json")):
        pytest.skip("samples/ not generated")
    with open(os.path.join(SAMPLES, "labels.json")) as fh:
        labels = json.load(fh)
    total = 0
    for fname in labels:
        p = os.path.join(SAMPLES, fname)
        assert os.path.exists(p), fname
        total += os.path.getsize(p)
    assert total < 15 * 1024 * 1024
