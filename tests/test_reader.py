"""Hardening tests for faultline.capture.reader (pcap / pcapng / gzip)."""

from __future__ import annotations

import gzip
import io
import os
import stat
import struct
import time

import pytest

from faultline.capture.reader import (
    LINKTYPE_ETHERNET,
    LINKTYPE_LINUX_SLL,
    LINKTYPE_RAW,
    CaptureError,
    CaptureReader,
    Limits,
    read_frames,
)
from faultline.capture.writer import PcapNgWriter, PcapWriter

# --------------------------------------------------------------------------- #
# builders
# --------------------------------------------------------------------------- #

FRAME = bytes.fromhex("ffffffffffff001122334455 0806 0001080006040001 001122334455 c0a80101 000000000000 c0a80102".replace(" ", ""))


def pcap_bytes(frames, *, endian="<", nanos=False, linktype=LINKTYPE_ETHERNET, snaplen=65535, version=(2, 4)):
    magic = 0xA1B23C4D if nanos else 0xA1B2C3D4
    out = struct.pack(endian + "IHHiIII", magic, version[0], version[1], 0, 0, snaplen, linktype)
    for i, fr in enumerate(frames):
        ts_s, ts_f = divmod(fr[0], 1) if isinstance(fr, tuple) else (1_700_000_000 + i, 0.25)
        data = fr[1] if isinstance(fr, tuple) else fr
        frac = int(round(ts_f * (1e9 if nanos else 1e6)))
        out += struct.pack(endian + "IIII", int(ts_s), frac, len(data), len(data)) + data
    return out


def ng_opt(code, value, endian="<"):
    return struct.pack(endian + "HH", code, len(value)) + value + b"\x00" * ((4 - len(value) % 4) % 4)


def ng_block(btype, body, endian="<", trailer=None):
    total = 12 + len(body)
    return struct.pack(endian + "II", btype, total) + body + struct.pack(endian + "I", trailer if trailer is not None else total)


def shb(endian="<", opts=b""):
    bom = 0x1A2B3C4D
    body = struct.pack(endian + "IHHq", bom, 1, 0, -1) + opts
    return ng_block(0x0A0D0D0A, body, endian)


def idb(linktype=LINKTYPE_ETHERNET, endian="<", tsresol=None, tsoffset=None, snaplen=65535, extra_opts=b""):
    opts = ng_opt(2, b"eth0", endian) + extra_opts
    if tsresol is not None:
        opts += ng_opt(9, bytes([tsresol]), endian)
    if tsoffset is not None:
        opts += ng_opt(14, struct.pack(endian + "q", tsoffset), endian)
    opts += ng_opt(0, b"", endian)
    return ng_block(1, struct.pack(endian + "HHI", linktype, 0, snaplen) + opts, endian)


def epb(ifid, ts_units, data, endian="<", caplen=None, origlen=None):
    caplen = len(data) if caplen is None else caplen
    origlen = len(data) if origlen is None else origlen
    body = struct.pack(endian + "IIIII", ifid, (ts_units >> 32) & 0xFFFFFFFF, ts_units & 0xFFFFFFFF, caplen, origlen)
    body += data + b"\x00" * ((4 - len(data) % 4) % 4)
    return ng_block(6, body, endian)


def spb(data, endian="<", origlen=None):
    body = struct.pack(endian + "I", len(data) if origlen is None else origlen) + data + b"\x00" * ((4 - len(data) % 4) % 4)
    return ng_block(3, body, endian)


def obsolete_pb(ifid, ts_units, data, endian="<"):
    body = struct.pack(endian + "HHIIII", ifid, 0, (ts_units >> 32) & 0xFFFFFFFF, ts_units & 0xFFFFFFFF, len(data), len(data))
    body += data + b"\x00" * ((4 - len(data) % 4) % 4)
    return ng_block(2, body, endian)


def simple_pcapng(n=3, endian="<"):
    out = shb(endian) + idb(endian=endian, tsresol=6)
    for i in range(n):
        out += epb(0, (1_700_000_000 + i) * 1_000_000 + 500, FRAME, endian)
    return out


def write(tmp_path, name, data: bytes) -> str:
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def read_all(path, limits=None):
    r = CaptureReader(path, limits)
    frames = list(r)
    return frames, r.info


# --------------------------------------------------------------------------- #
# pcap
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("nanos", [False, True])
def test_pcap_variants(tmp_path, endian, nanos):
    frames_in = [(1_700_000_000.123456, FRAME), (1_700_000_001.5, FRAME[:20])]
    p = write(tmp_path, "a.pcap", pcap_bytes(frames_in, endian=endian, nanos=nanos))
    frames, info = read_all(p)
    assert [f.data for f in frames] == [FRAME, FRAME[:20]]
    assert [f.no for f in frames] == [1, 2]
    assert frames[0].ts == pytest.approx(1_700_000_000.123456, abs=1e-6)
    assert frames[1].caplen == 20 and frames[1].wirelen == 20 and frames[1].linktype == LINKTYPE_ETHERNET
    assert info.format == ("pcap (ns)" if nanos else "pcap")
    assert info.packets == 2 and info.bytes_captured == len(FRAME) + 20
    assert info.truncated is False and info.limited is False and info.warnings == []
    assert info.to_dict()["duration"] == pytest.approx(1.376544, abs=1e-5)


def test_pcap_via_writer_roundtrip(tmp_path):
    p = tmp_path / "w.pcap"
    with PcapWriter(str(p), linktype=LINKTYPE_RAW, nanos=True) as w:
        for i in range(10):
            w.write(1.0 + i, bytes([i]) * 40, wirelen=1500)
    frames, info = read_all(str(p))
    assert len(frames) == 10 and frames[3].data == b"\x03" * 40 and frames[3].wirelen == 1500
    assert info.linktypes == {LINKTYPE_RAW}


def test_pcap_wirelen_never_below_caplen(tmp_path):
    hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    rec = struct.pack("<IIII", 1, 0, 40, 10) + b"\x00" * 40  # orig < caplen (hostile)
    frames, info = read_all(write(tmp_path, "w.pcap", hdr + rec))
    assert frames[0].wirelen == 40


def test_pcap_bad_subsecond_clamped_and_version_warn(tmp_path):
    hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 3, 0, 0, 0, 65535, 1)
    rec = struct.pack("<IIII", 100, 5_000_000, 4, 4) + b"abcd"
    frames, info = read_all(write(tmp_path, "w.pcap", hdr + rec))
    assert frames[0].ts == 100.0
    assert any("unusual pcap version" in w for w in info.warnings)
    assert any("sub-second" in w for w in info.warnings)


def test_pcap_truncation_every_offset(tmp_path):
    data = pcap_bytes([FRAME, FRAME, FRAME])
    for i in range(len(data) + 1):
        p = write(tmp_path, f"t{i}.pcap", data[:i])
        if i < 24:
            with pytest.raises(CaptureError):
                list(CaptureReader(p))
            continue
        frames, info = read_all(p)
        complete = (i - 24) % (16 + len(FRAME)) == 0
        assert len(frames) == (i - 24) // (16 + len(FRAME))
        assert info.truncated is (not complete), i
        assert bool(info.warnings) is (not complete), i


def test_pcap_hostile_caplen(tmp_path):
    hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    good = struct.pack("<IIII", 1, 0, len(FRAME), len(FRAME)) + FRAME
    for incl in (0x7FFFFFFF, 0xFFFFFFFF, 256 * 1024 + 1):
        bad = struct.pack("<IIII", 1, 0, incl, incl) + b"\x00" * 64
        frames, info = read_all(write(tmp_path, f"c{incl}.pcap", hdr + good + bad + good))
        assert len(frames) == 1, incl
        assert info.truncated and any("hostile" in w for w in info.warnings)


def test_pcap_caplen_within_limit_but_file_short(tmp_path):
    hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    bad = struct.pack("<IIII", 1, 0, 200_000, 200_000) + b"\x00" * 64
    frames, info = read_all(write(tmp_path, "s.pcap", hdr + bad))
    assert frames == [] and info.truncated and any("cut short" in w for w in info.warnings)


def test_pcap_zero_length_records(tmp_path):
    hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    frames, info = read_all(write(tmp_path, "z.pcap", hdr + struct.pack("<IIII", 1, 0, 0, 0) * 5))
    assert len(frames) == 5 and all(f.data == b"" for f in frames)


# --------------------------------------------------------------------------- #
# pcapng
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("endian", ["<", ">"])
def test_pcapng_basic(tmp_path, endian):
    frames, info = read_all(write(tmp_path, "a.pcapng", simple_pcapng(3, endian)))
    assert len(frames) == 3 and info.format == "pcapng"
    assert frames[0].ts == pytest.approx(1_700_000_000.0005)
    assert frames[2].no == 3 and frames[2].data == FRAME and info.warnings == []


def test_pcapng_via_writer(tmp_path):
    p = tmp_path / "w.pcapng"
    with PcapNgWriter(str(p), nanos=True) as w:
        w.write(1234.000000001, FRAME)
        w.write(1235.5, FRAME[:30], wirelen=99)
    frames, info = read_all(str(p))
    assert len(frames) == 2
    assert frames[0].ts == pytest.approx(1234.000000001, abs=1e-9)
    assert frames[1].wirelen == 99 and frames[1].caplen == 30


def test_pcapng_multiple_interfaces_and_linktypes(tmp_path):
    data = shb() + idb(LINKTYPE_ETHERNET) + idb(LINKTYPE_RAW, tsresol=3) + idb(LINKTYPE_LINUX_SLL)
    data += epb(0, 10_000_000, FRAME) + epb(1, 10_000, b"\x45" * 20) + epb(2, 10_000_000, b"\x00" * 16)
    data += epb(7, 1, FRAME)  # unknown interface -> skipped
    frames, info = read_all(write(tmp_path, "m.pcapng", data))
    assert [f.linktype for f in frames] == [LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_LINUX_SLL]
    assert frames[0].ts == pytest.approx(10.0) and frames[1].ts == pytest.approx(10.0)
    assert info.linktypes == {LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_LINUX_SLL}
    assert any("unknown interface" in w for w in info.warnings)


def test_pcapng_tsresol_power_of_two_and_tsoffset(tmp_path):
    data = shb() + idb(tsresol=0x80 | 10, tsoffset=1_000_000)  # 2^-10 s units, +1e6 s
    data += epb(0, 2048, FRAME)
    frames, _ = read_all(write(tmp_path, "r.pcapng", data))
    assert frames[0].ts == pytest.approx(1_000_000 + 2.0)
    # absurd resolution is ignored (falls back to microseconds)
    data = shb() + idb(tsresol=99) + epb(0, 3_000_000, FRAME)
    frames, _ = read_all(write(tmp_path, "r2.pcapng", data))
    assert frames[0].ts == pytest.approx(3.0)
    # nanosecond via writer-style option
    data = shb() + idb(tsresol=9) + epb(0, 1_500_000_000, FRAME)
    frames, _ = read_all(write(tmp_path, "r3.pcapng", data))
    assert frames[0].ts == pytest.approx(1.5)


def test_pcapng_idb_option_edge_cases(tmp_path):
    # option whose declared length runs past the block: ignored, no crash
    bad_opt = struct.pack("<HH", 9, 400) + b"\x09\x00\x00\x00"
    data = shb() + ng_block(1, struct.pack("<HHI", 1, 0, 65535) + bad_opt) + epb(0, 2_000_000, FRAME)
    frames, _ = read_all(write(tmp_path, "o.pcapng", data))
    assert len(frames) == 1 and frames[0].ts == pytest.approx(2.0)
    # 1000 options (iteration cap)
    many = ng_opt(1, b"c") * 1000 + ng_opt(9, b"\x03") + ng_opt(0, b"")
    data = shb() + ng_block(1, struct.pack("<HHI", 1, 0, 65535) + many) + epb(0, 2_000, FRAME)
    frames, _ = read_all(write(tmp_path, "o2.pcapng", data))
    assert len(frames) == 1  # ts unit may be ignored past the cap; still readable


def test_pcapng_simple_and_obsolete_packet_blocks(tmp_path):
    data = shb() + idb() + epb(0, 5_000_000, FRAME) + spb(FRAME[:30]) + obsolete_pb(0, 7_000_000, FRAME[:16])
    data += spb(FRAME, origlen=0x7FFFFFFF)  # hostile origlen on SPB
    frames, info = read_all(write(tmp_path, "s.pcapng", data))
    assert len(frames) == 4
    assert frames[1].ts == pytest.approx(5.0) and frames[1].data == FRAME[:30]
    assert frames[2].ts == pytest.approx(7.0) and frames[2].data == FRAME[:16]
    assert frames[3].data[: len(FRAME)] == FRAME and frames[3].wirelen == 0x7FFFFFFF
    # SPB before any IDB is dropped
    frames, _ = read_all(write(tmp_path, "s2.pcapng", shb() + spb(FRAME) + idb() + epb(0, 1, FRAME)))
    assert len(frames) == 1


def test_pcapng_unknown_and_custom_blocks_skipped(tmp_path):
    data = shb() + ng_block(5, b"\x00" * 16) + idb() + ng_block(4, b"\x00" * 8) + ng_block(0x0BAD, b"\x00" * 4)
    data += epb(0, 1, FRAME) + ng_block(0x40000BAD, b"x" * 20) + epb(0, 2, FRAME)
    frames, info = read_all(write(tmp_path, "u.pcapng", data))
    assert len(frames) == 2 and info.warnings == []


def test_pcapng_multiple_sections_reset_interfaces(tmp_path):
    data = simple_pcapng(2) + shb(">") + idb(LINKTYPE_RAW, endian=">") + epb(0, 9_000_000, b"\x45" * 20, endian=">")
    frames, info = read_all(write(tmp_path, "ms.pcapng", data))
    assert len(frames) == 3 and frames[2].linktype == LINKTYPE_RAW and frames[2].ts == pytest.approx(9.0)
    # second section with an EPB before its IDB -> unknown interface, skipped
    data = simple_pcapng(1) + shb() + epb(0, 1, FRAME)
    frames, info = read_all(write(tmp_path, "ms2.pcapng", data))
    assert len(frames) == 1 and any("unknown interface" in w for w in info.warnings)


def test_pcapng_truncation_every_offset(tmp_path):
    data = simple_pcapng(2)
    first_shb_len = len(shb())
    for i in range(len(data) + 1):
        p = write(tmp_path, f"t{i}.pcapng", data[:i])
        if i < first_shb_len:
            with pytest.raises(CaptureError):
                list(CaptureReader(p))
            continue
        frames, info = read_all(p)
        boundaries = {first_shb_len, first_shb_len + len(idb(tsresol=6))}
        epb_len = len(epb(0, 1, FRAME))
        boundaries |= {first_shb_len + len(idb(tsresol=6)) + k * epb_len for k in (1, 2)}
        complete = i in boundaries
        assert info.truncated is (not complete), i
        assert len(frames) <= 2


def test_pcapng_hostile_block_lengths(tmp_path):
    base = shb() + idb()
    good = epb(0, 1, FRAME)
    cases = {
        "zero": struct.pack("<II", 6, 0),
        "eight": struct.pack("<II", 6, 8),
        "unaligned": struct.pack("<II", 6, 13) + b"\x00" * 5,
        "huge": struct.pack("<II", 6, 0xFFFFFFFF) + b"\x00" * 32,
        "over_cap": struct.pack("<II", 6, 16 * 1024 * 1024 + 4) + b"\x00" * 32,
        "trailer_mismatch": ng_block(6, good[8:-4], trailer=12),
        "bad_caplen": epb(0, 1, FRAME, caplen=0x7FFFFFFF),
        "short_epb": ng_block(6, b"\x00" * 8),
        "short_idb": ng_block(1, b"\x00" * 4),
    }
    for name, bad in cases.items():
        frames, info = read_all(write(tmp_path, f"{name}.pcapng", base + good + bad + good))
        assert frames and frames[0].data == FRAME, name
        if name in ("bad_caplen", "short_epb", "short_idb"):
            assert len(frames) == 2 and info.warnings, name  # block skipped, reading continues
        else:
            assert len(frames) == 1 and info.truncated, name


def test_pcapng_bad_section_header(tmp_path):
    bad_bom = ng_block(0x0A0D0D0A, struct.pack("<IHHq", 0xDEADBEEF, 1, 0, -1))
    with pytest.raises(CaptureError, match="byte-order"):
        list(CaptureReader(write(tmp_path, "b.pcapng", bad_bom)))
    for blen in (0, 8, 12, 30, 0x7FFFFFFF):
        data = struct.pack("<II", 0x0A0D0D0A, blen) + struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + b"\x00" * 16
        with pytest.raises(CaptureError, match="invalid length"):
            list(CaptureReader(write(tmp_path, f"l{blen}.pcapng", data)))
    # a later corrupt section must not throw away the frames already read
    data = simple_pcapng(2) + bad_bom
    frames, info = read_all(write(tmp_path, "later.pcapng", data))
    assert len(frames) == 2 and info.truncated and any("byte-order" in w for w in info.warnings)
    data = simple_pcapng(2) + struct.pack("<II", 0x0A0D0D0A, 7) + struct.pack("<I", 0x1A2B3C4D)
    frames, info = read_all(write(tmp_path, "later2.pcapng", data))
    assert len(frames) == 2 and info.truncated


def test_pcapng_too_many_skipped_blocks(tmp_path):
    lim = Limits(max_skipped_blocks=10)
    data = shb() + idb() + ng_block(5, b"") * 11 + epb(0, 1, FRAME)
    frames, info = read_all(write(tmp_path, "sk.pcapng", data), lim)
    assert frames == [] and any("hostile" in w for w in info.warnings)


def test_pcapng_too_many_interfaces(tmp_path):
    lim = Limits(max_interfaces=2)
    data = shb() + idb() * 3 + epb(2, 1, FRAME) + epb(1, 1, FRAME)
    frames, info = read_all(write(tmp_path, "if.pcapng", data), lim)
    assert len(frames) == 1 and any("too many interfaces" in w for w in info.warnings)


# --------------------------------------------------------------------------- #
# gzip
# --------------------------------------------------------------------------- #

def test_gzip_pcap_and_pcapng(tmp_path):
    for name, raw in (("a.pcap.gz", pcap_bytes([FRAME, FRAME])), ("b.pcapng.gz", simple_pcapng(2))):
        frames, info = read_all(write(tmp_path, name, gzip.compress(raw)))
        assert len(frames) == 2 and info.compressed is True and info.warnings == []


def test_gzip_truncated_and_corrupt(tmp_path):
    raw = pcap_bytes([bytes([i % 256]) * 60 for i in range(2000)])
    gz = gzip.compress(raw)
    frames, info = read_all(write(tmp_path, "t.pcap.gz", gz[: len(gz) // 2]))
    assert 0 < len(frames) < 2000 and info.truncated and any("corrupt" in w for w in info.warnings)
    # corrupt deflate body (zlib.error path)
    bad = bytearray(gz)
    for i in range(len(bad) // 2, len(bad) // 2 + 40):
        bad[i] ^= 0xFF
    frames, info = read_all(write(tmp_path, "c.pcap.gz", bytes(bad)))
    assert info.truncated or info.packets == 2000
    # garbage after the gzip header
    with pytest.raises(CaptureError):
        list(CaptureReader(write(tmp_path, "g.pcap.gz", b"\x1f\x8b\x08\x00" + b"\xff" * 64)))
    with pytest.raises(CaptureError):
        list(CaptureReader(write(tmp_path, "h.pcap.gz", b"\x1f\x8b")))


def test_gzip_bomb_cap(tmp_path):
    raw = pcap_bytes([b"\x00" * 1000] * 200)  # ~200 KB, compresses to ~1 KB
    lim = Limits(max_decompressed_bytes=50_000)
    frames, info = read_all(write(tmp_path, "bomb.pcap.gz", gzip.compress(raw)), lim)
    assert info.limited and any("decompression bomb" in w for w in info.warnings)
    assert 0 < len(frames) < 200
    assert info.bytes_captured <= 50_000


def test_gzip_not_a_capture_inside(tmp_path):
    with pytest.raises(CaptureError, match="not a pcap"):
        list(CaptureReader(write(tmp_path, "x.gz", gzip.compress(b"hello world, not a capture"))))


# --------------------------------------------------------------------------- #
# path / format validation
# --------------------------------------------------------------------------- #

def test_invalid_magic_and_empty(tmp_path):
    with pytest.raises(CaptureError, match="not a pcap"):
        list(CaptureReader(write(tmp_path, "bad.pcap", b"\x00\x01\x02\x03" + b"\x00" * 40)))
    with pytest.raises(CaptureError, match="empty"):
        CaptureReader(write(tmp_path, "empty.pcap", b""))
    with pytest.raises(CaptureError, match="not a pcap"):
        list(CaptureReader(write(tmp_path, "tiny.pcap", b"\xd4")))
    with pytest.raises(CaptureError, match="truncated"):
        list(CaptureReader(write(tmp_path, "hdr.pcap", b"\xd4\xc3\xb2\xa1\x02\x00")))


def test_missing_directory_and_fifo(tmp_path):
    with pytest.raises(CaptureError, match="cannot open"):
        CaptureReader(str(tmp_path / "nope.pcap"))
    with pytest.raises(CaptureError, match="not a regular file"):
        CaptureReader(str(tmp_path))
    if hasattr(os, "mkfifo"):
        fifo = tmp_path / "fifo"
        os.mkfifo(str(fifo))
        assert stat.S_ISFIFO(os.stat(fifo).st_mode)
        with pytest.raises(CaptureError, match="not a regular file"):
            CaptureReader(str(fifo))  # must not block on open()
    if os.path.exists("/dev/zero"):
        with pytest.raises(CaptureError, match="not a regular file"):
            CaptureReader("/dev/zero")


def test_file_size_limit(tmp_path):
    p = write(tmp_path, "big.pcap", pcap_bytes([FRAME] * 10))
    with pytest.raises(CaptureError, match="limit"):
        CaptureReader(p, Limits(max_file_bytes=100))


def test_display_name_and_info_dict(tmp_path):
    p = write(tmp_path, "secret-location.pcap", pcap_bytes([FRAME]))
    r = CaptureReader(p, display_name="upload")
    list(r)
    d = r.info.to_dict()
    assert d["name"] == "upload" and "secret-location" not in str(d)
    assert set(d) >= {"format", "packets", "linktypes", "duration", "truncated", "limited", "warnings"}


def test_warnings_are_capped(tmp_path):
    data = shb() + idb() + epb(9, 1, FRAME) * 200
    _, info = read_all(write(tmp_path, "w.pcapng", data))
    assert len(info.warnings) == 50


# --------------------------------------------------------------------------- #
# limits & helpers
# --------------------------------------------------------------------------- #

def test_packet_limit(tmp_path):
    p = write(tmp_path, "many.pcap", pcap_bytes([FRAME] * 50))
    frames, info = read_all(p, Limits(max_packets=7))
    assert len(frames) == 7 and info.limited and any("packet limit" in w for w in info.warnings)
    frames, info = read_all(write(tmp_path, "many.pcapng", simple_pcapng(50)), Limits(max_packets=7))
    assert len(frames) == 7 and info.limited


def test_read_frames_filter(tmp_path):
    p = write(tmp_path, "f.pcap", pcap_bytes([bytes([i]) * 10 for i in range(20)]))
    got = [f.no for f in read_frames(p, {3, 5, 9})]
    assert got == [3, 5, 9]
    assert [f.no for f in read_frames(p, set())] == []
    assert len(list(read_frames(p))) == 20


def test_reader_is_reiterable(tmp_path):
    r = CaptureReader(write(tmp_path, "r.pcap", pcap_bytes([FRAME] * 3)))
    assert len(list(r)) == 3
    assert len(list(r)) == 3  # second pass works; counters continue (callers create a new reader per pass)


# --------------------------------------------------------------------------- #
# timing
# --------------------------------------------------------------------------- #

def _timed(path, limits=None):
    t0 = time.perf_counter()
    frames, info = read_all(path, limits)
    return time.perf_counter() - t0, frames, info


@pytest.mark.parametrize("kind", ["pcap_zero_len", "pcap_tiny", "pcapng_unknown_blocks", "pcapng_tiny_epb", "gzip_bomb", "random"])
def test_hostile_megabyte_under_two_seconds(tmp_path, kind):
    mb = 1024 * 1024
    if kind == "pcap_zero_len":
        hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        data = hdr + struct.pack("<IIII", 1, 0, 0, 0) * (mb // 16)
    elif kind == "pcap_tiny":
        hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        data = hdr + (struct.pack("<IIII", 1, 0, 1, 1) + b"x") * (mb // 17)
    elif kind == "pcapng_unknown_blocks":
        data = shb() + idb() + ng_block(0x0BAD, b"") * (mb // 12)
    elif kind == "pcapng_tiny_epb":
        data = shb() + idb() + epb(0, 1, b"") * (mb // 32)
    elif kind == "gzip_bomb":
        data = gzip.compress(pcap_bytes([b"\x00" * 60000] * 1000))  # 60 MB inside
    else:
        import random
        data = pcap_bytes([FRAME]) + random.Random(7).randbytes(mb)
    lim = Limits(max_decompressed_bytes=8 * mb)
    secs, frames, info = _timed(write(tmp_path, f"{kind}.bin", data), lim)
    assert secs < 2.0, (kind, secs)
    if kind == "gzip_bomb":
        assert info.limited
