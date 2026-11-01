"""Hardened, streaming reader for pcap, pcapng and gzip-compressed captures.

Design goals (see tech.md, "Security of the solution"):

* Never trust a length field. Every length is checked against hard caps and
  against the bytes actually available before anything is allocated.
* Never crash on bad input. Corruption ends iteration gracefully and is
  reported as a warning (with the byte offset) so the analysis of everything
  read so far still completes.
* Bounded resources: file size, packet count, record size, block size and the
  decompressed size of gzip input are all capped (decompression-bomb guard).
* Stream: frames are yielded one by one; the whole file is never loaded.
"""

from __future__ import annotations

import gzip
import io
import os
import stat
import struct
import zlib
from dataclasses import dataclass, field
from typing import BinaryIO, Iterator

# Link-layer types we decode (others are counted but not dissected)
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LOOP = 108
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}
PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"
GZIP_MAGIC = b"\x1f\x8b"


class CaptureError(Exception):
    """The file cannot be analysed at all (bad format, unreadable, too big)."""


@dataclass
class Limits:
    max_file_bytes: int = 4 * 1024**3  # 4 GiB on disk
    max_decompressed_bytes: int = 2 * 1024**3  # gzip bomb guard
    max_packets: int = 10_000_000
    max_record_bytes: int = 256 * 1024  # larger than any real snaplen
    max_block_bytes: int = 16 * 1024 * 1024  # pcapng block
    max_interfaces: int = 1024
    max_skipped_blocks: int = 100_000
    max_empty_records: int = 10_000  # all-zero record headers (padding / garbage)


@dataclass
class CaptureInfo:
    name: str
    format: str = "unknown"
    compressed: bool = False
    file_bytes: int = 0
    packets: int = 0
    bytes_captured: int = 0
    linktypes: set[int] = field(default_factory=set)
    first_ts: float | None = None
    last_ts: float | None = None
    truncated: bool = False
    limited: bool = False
    warnings: list[str] = field(default_factory=list)

    def warn(self, msg: str) -> None:
        if len(self.warnings) < 50:
            self.warnings.append(msg)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "format": self.format,
            "compressed": self.compressed,
            "file_bytes": self.file_bytes,
            "packets": self.packets,
            "bytes_captured": self.bytes_captured,
            "linktypes": sorted(self.linktypes),
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "duration": (self.last_ts - self.first_ts) if self.first_ts is not None and self.last_ts is not None else 0.0,
            "truncated": self.truncated,
            "limited": self.limited,
            "warnings": list(self.warnings),
        }


class Frame:
    __slots__ = ("no", "ts", "caplen", "wirelen", "linktype", "data")

    def __init__(self, no: int, ts: float, wirelen: int, linktype: int, data: bytes):
        self.no = no
        self.ts = ts
        self.caplen = len(data)
        self.wirelen = wirelen
        self.linktype = linktype
        self.data = data


class _BombGuard(io.RawIOBase):
    """Wraps a decompressing stream and stops after ``limit`` bytes."""

    def __init__(self, inner: BinaryIO, limit: int):
        self._inner = inner
        self._left = limit
        self.tripped = False

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:
        if self._left <= 0:
            self.tripped = True
            return 0
        want = min(len(b), self._left)
        try:
            data = self._inner.read(want)
        except (OSError, EOFError, gzip.BadGzipFile, zlib.error) as exc:  # corrupt gzip/deflate stream
            raise _StreamCorrupt(str(exc)) from None
        n = len(data)
        b[:n] = data
        self._left -= n
        return n


class _StreamCorrupt(Exception):
    pass


def _read_exact(fh: BinaryIO, n: int) -> bytes:
    """Read exactly n bytes or fewer at EOF (never raises on short read)."""
    if n <= 0:
        return b""
    chunks = []
    left = n
    while left:
        chunk = fh.read(left)
        if not chunk:
            break
        chunks.append(chunk)
        left -= len(chunk)
    return b"".join(chunks)


class CaptureReader:
    """Iterate over frames of a capture file.

    >>> reader = CaptureReader("capture.pcap")
    >>> for frame in reader: ...
    >>> reader.info.warnings
    """

    def __init__(self, path: str, limits: Limits | None = None, display_name: str | None = None):
        self.path = path
        self.limits = limits or Limits()
        self.info = CaptureInfo(name=display_name or os.path.basename(path))
        self._validate_path()

    # ------------------------------------------------------------------ #
    def _validate_path(self) -> None:
        try:
            st = os.stat(self.path)
        except OSError as exc:
            raise CaptureError(f"cannot open capture: {exc.strerror or exc}") from None
        if not stat.S_ISREG(st.st_mode):
            raise CaptureError("capture path is not a regular file")
        if st.st_size == 0:
            raise CaptureError("capture file is empty (0 bytes)")
        if st.st_size > self.limits.max_file_bytes:
            raise CaptureError(
                f"capture is {st.st_size / 1024**3:.1f} GiB, above the {self.limits.max_file_bytes / 1024**3:.0f} GiB limit; "
                "split it first (e.g. editcap -c 1000000)"
            )
        self.info.file_bytes = st.st_size

    def __iter__(self) -> Iterator[Frame]:
        try:
            raw = open(self.path, "rb")
        except OSError as exc:
            raise CaptureError(f"cannot open capture: {exc.strerror or exc}") from None
        with raw:
            head = raw.read(4)
            raw.seek(0)
            fh: BinaryIO = raw
            guard = None
            if head[:2] == GZIP_MAGIC:
                self.info.compressed = True
                guard = _BombGuard(gzip.GzipFile(fileobj=raw, mode="rb"), self.limits.max_decompressed_bytes)
                fh = io.BufferedReader(guard, buffer_size=1 << 16)
                try:
                    head = fh.peek(4)[:4]
                except _StreamCorrupt as exc:
                    raise CaptureError(f"corrupt gzip stream: {exc}") from None
            try:
                if head in PCAP_MAGICS:
                    yield from self._read_pcap(fh)
                elif head == PCAPNG_SHB:
                    yield from self._read_pcapng(fh)
                else:
                    raise CaptureError(
                        f"not a pcap/pcapng capture (magic bytes {head.hex() or 'none'}); "
                        "convert other formats with: editcap -F pcap in.file out.pcap"
                    )
            except _StreamCorrupt as exc:
                self.info.truncated = True
                self.info.warn(f"compressed stream is corrupt after {self.info.packets} packets ({exc})")
            if guard is not None and guard.tripped:
                self.info.limited = True
                self.info.warn(
                    f"decompressed data exceeded {self.limits.max_decompressed_bytes // 1024**2} MiB; "
                    "stopped reading (possible decompression bomb)"
                )

    # ------------------------------------------------------------------ #
    def _emit(self, ts: float, wirelen: int, linktype: int, data: bytes) -> Frame | None:
        info = self.info
        if info.packets >= self.limits.max_packets:
            info.limited = True
            info.warn(f"stopped after the first {self.limits.max_packets:,} packets (packet limit)")
            return None
        info.packets += 1
        info.bytes_captured += len(data)
        info.linktypes.add(linktype)
        if info.first_ts is None or ts < info.first_ts:
            info.first_ts = ts
        if info.last_ts is None or ts > info.last_ts:
            info.last_ts = ts
        return Frame(info.packets, ts, max(wirelen, len(data)), linktype, data)

    def _read_pcap(self, fh: BinaryIO) -> Iterator[Frame]:
        hdr = _read_exact(fh, 24)
        if len(hdr) < 24:
            raise CaptureError("pcap global header is truncated")
        endian, resolution = PCAP_MAGICS[hdr[:4]]
        vmaj, vmin, _zone, _sig, snaplen, network = struct.unpack(endian + "HHiIII", hdr[4:])
        if vmaj != 2:
            self.info.warn(f"unusual pcap version {vmaj}.{vmin}")
        linktype = network & 0x0FFFFFFF
        self.info.format = "pcap" + (" (ns)" if resolution == 1e-9 else "")
        rec = struct.Struct(endian + "IIII")
        offset = 24
        empty_run = 0
        while True:
            rh = _read_exact(fh, 16)
            if not rh:
                return
            if len(rh) < 16:
                self.info.truncated = True
                self.info.warn(f"file ends inside a record header at byte {offset} (capture was cut short)")
                return
            ts_s, ts_f, incl, orig = rec.unpack(rh)
            if incl > self.limits.max_record_bytes:
                self.info.truncated = True
                self.info.warn(
                    f"record at byte {offset} claims {incl:,} bytes (limit {self.limits.max_record_bytes:,}); "
                    "file is corrupt or hostile, stopped reading here"
                )
                return
            if resolution == 1e-6 and ts_f >= 1_000_000 or resolution == 1e-9 and ts_f >= 1_000_000_000:
                self.info.warn(f"invalid sub-second timestamp at byte {offset}; value clamped")
                ts_f = 0
            data = _read_exact(fh, incl)
            if len(data) < incl:
                self.info.truncated = True
                self.info.warn(f"file ends inside packet data at byte {offset} (capture was cut short)")
                return
            offset += 16 + incl
            if incl == 0 and orig == 0:
                empty_run += 1
                if empty_run > self.limits.max_empty_records:
                    self.info.truncated = True
                    self.info.warn(
                        f"more than {self.limits.max_empty_records:,} consecutive empty records at byte {offset}; "
                        "the rest of the file looks like padding or garbage, stopped reading here"
                    )
                    return
            else:
                empty_run = 0
            frame = self._emit(ts_s + ts_f * resolution, orig, linktype, data)
            if frame is None:
                return
            yield frame

    def _read_pcapng(self, fh: BinaryIO) -> Iterator[Frame]:
        self.info.format = "pcapng"
        lim = self.limits
        endian = "<"
        interfaces: list[tuple[int, float, int]] = []  # (linktype, ts_unit, ts_offset)
        offset = 0
        skipped = 0
        while True:
            bh = _read_exact(fh, 8)
            if not bh:
                return
            if len(bh) < 8:
                if not offset:
                    raise CaptureError("pcapng section header is truncated")
                self.info.truncated = True
                self.info.warn(f"file ends inside a block header at byte {offset}")
                return
            btype_raw = bh[:4]
            if btype_raw == PCAPNG_SHB:
                # need the byte-order magic to know how to read the length
                bom = _read_exact(fh, 4)
                if len(bom) < 4:
                    if not offset:
                        raise CaptureError("pcapng section header is truncated")
                    self.info.truncated = True
                    self.info.warn("truncated section header block")
                    return
                if bom == b"\x4d\x3c\x2b\x1a":
                    endian = "<"
                elif bom == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                else:
                    if offset:  # a later section is corrupt: keep what we have
                        self.info.truncated = True
                        self.info.warn(f"section header at byte {offset} has an invalid byte-order magic; stopped reading here")
                        return
                    raise CaptureError("pcapng section header has an invalid byte-order magic")
                (blen,) = struct.unpack(endian + "I", bh[4:8])
                if blen < 28 or blen % 4 or blen > lim.max_block_bytes:
                    if offset:
                        self.info.truncated = True
                        self.info.warn(f"section header at byte {offset} has an invalid length ({blen}); stopped reading here")
                        return
                    raise CaptureError(f"pcapng section header has an invalid length ({blen})")
                rest = _read_exact(fh, blen - 12)
                if len(rest) < blen - 12:
                    if not offset:
                        raise CaptureError("pcapng section header is truncated")
                    self.info.truncated = True
                    self.info.warn("truncated section header block")
                    return
                interfaces = []  # new section resets interface ids
                offset += blen
                continue
            btype, blen = struct.unpack(endian + "II", bh)
            if blen < 12 or blen % 4 or blen > lim.max_block_bytes:
                self.info.truncated = True
                self.info.warn(f"pcapng block at byte {offset} has an invalid length ({blen}); stopped reading here")
                return
            body = _read_exact(fh, blen - 8)
            if len(body) < blen - 8:
                self.info.truncated = True
                self.info.warn(f"file ends inside a pcapng block at byte {offset}")
                return
            (trailer,) = struct.unpack(endian + "I", body[-4:])
            if trailer != blen:
                self.info.truncated = True
                self.info.warn(f"pcapng block at byte {offset} has mismatched length fields; stopped reading here")
                return
            body = body[:-4]
            offset += blen

            if btype == 1:  # Interface Description Block
                if len(body) < 8:
                    self.info.warn(f"short interface block at byte {offset - blen}; ignored")
                    continue
                if len(interfaces) >= lim.max_interfaces:
                    self.info.warn("too many interfaces declared; extra ones ignored")
                    continue
                linktype, _res, _snap = struct.unpack(endian + "HHI", body[:8])
                unit, ts_off = self._idb_options(body[8:], endian)
                interfaces.append((linktype, unit, ts_off))
            elif btype == 6:  # Enhanced Packet Block
                if len(body) < 20:
                    self.info.warn(f"short packet block at byte {offset - blen}; skipped")
                    continue
                ifid, ts_hi, ts_lo, caplen, origlen = struct.unpack(endian + "IIIII", body[:20])
                if ifid >= len(interfaces):
                    self.info.warn(f"packet references unknown interface {ifid}; skipped")
                    continue
                if caplen > len(body) - 20 or caplen > lim.max_record_bytes:
                    self.info.warn(f"packet block at byte {offset - blen} has an invalid captured length; skipped")
                    continue
                linktype, unit, ts_off = interfaces[ifid]
                ts = ((ts_hi << 32) | ts_lo) * unit + ts_off
                frame = self._emit(ts, origlen, linktype, bytes(body[20 : 20 + caplen]))
                if frame is None:
                    return
                yield frame
            elif btype == 3:  # Simple Packet Block
                if not interfaces or len(body) < 4:
                    continue
                (origlen,) = struct.unpack(endian + "I", body[:4])
                data = bytes(body[4 : 4 + min(origlen, lim.max_record_bytes)])
                linktype, _unit, _off = interfaces[0]
                ts = self.info.last_ts or 0.0  # SPBs carry no timestamp
                frame = self._emit(ts, origlen, linktype, data)
                if frame is None:
                    return
                yield frame
            elif btype == 2:  # obsolete Packet Block
                if len(body) < 20:
                    continue
                ifid, _drops, ts_hi, ts_lo, caplen, origlen = struct.unpack(endian + "HHIIII", body[:20])
                if ifid >= len(interfaces) or caplen > len(body) - 20 or caplen > lim.max_record_bytes:
                    continue
                linktype, unit, ts_off = interfaces[ifid]
                frame = self._emit(((ts_hi << 32) | ts_lo) * unit + ts_off, origlen, linktype, bytes(body[20 : 20 + caplen]))
                if frame is None:
                    return
                yield frame
            else:
                skipped += 1  # name resolution, statistics, custom blocks ...
                if skipped > lim.max_skipped_blocks:
                    self.info.warn("too many non-packet blocks; stopped reading (file looks hostile)")
                    return

    @staticmethod
    def _idb_options(opts: bytes, endian: str) -> tuple[float, float]:
        unit, ts_off = 1e-6, 0.0
        pos, n = 0, 0
        while pos + 4 <= len(opts) and n < 256:
            n += 1
            code, olen = struct.unpack(endian + "HH", opts[pos : pos + 4])
            pos += 4
            if code == 0:
                break
            val = opts[pos : pos + olen]
            if len(val) < olen:
                break
            if code == 9 and olen >= 1:  # if_tsresol
                v = val[0]
                exp = v & 0x7F
                if exp <= 30:  # sanity: no absurd resolutions
                    unit = 2.0 ** -exp if v & 0x80 else 10.0 ** -exp
            elif code == 14 and olen == 8:  # if_tsoffset (seconds)
                (ts_off,) = struct.unpack(endian + "q", val)
            pos += (olen + 3) & ~3
        return unit, float(ts_off)


def read_frames(path: str, wanted: set[int] | None = None, limits: Limits | None = None) -> Iterator[Frame]:
    """Re-read a capture and yield only frames whose number is in ``wanted``."""
    reader = CaptureReader(path, limits)
    for frame in reader:
        if wanted is None or frame.no in wanted:
            yield frame
            if wanted is not None and frame.no >= max(wanted):
                return
