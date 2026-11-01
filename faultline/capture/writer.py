"""Capture writers: classic pcap and pcapng (standard library only).

Both writers share one interface::

    with PcapWriter("out.pcap") as w:          # or PcapNgWriter("out.pcapng")
        w.write(ts, frame_bytes)                # ts = float epoch seconds
        w.write(ts, frame_bytes[:96], wirelen=len(frame_bytes))

``path_or_fileobj`` may be a filesystem path or a binary file object (for
example ``io.BytesIO``); a file object passed in is not closed by ``close()``.
Frames longer than ``snaplen`` are truncated (``wirelen`` keeps the original
length).
"""

from __future__ import annotations

import struct
from typing import BinaryIO

__all__ = ["PcapWriter", "PcapNgWriter", "LINKTYPE_ETHERNET", "LINKTYPE_RAW"]

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113


class _BaseWriter:
    def __init__(self, path_or_fileobj, linktype: int = LINKTYPE_ETHERNET,
                 snaplen: int = 262144, nanos: bool = False):
        if isinstance(path_or_fileobj, (str, bytes)) or hasattr(path_or_fileobj, "__fspath__"):
            self._fh: BinaryIO = open(path_or_fileobj, "wb")
            self._owns = True
        else:
            self._fh = path_or_fileobj
            self._owns = False
        self.linktype = int(linktype)
        self.snaplen = int(snaplen)
        self.nanos = bool(nanos)
        self.count = 0
        self._closed = False
        self._write_header()

    # -- helpers ---------------------------------------------------------
    def _split_ts(self, ts: float) -> tuple[int, int]:
        """Return (seconds, fraction) in micro- or nanoseconds, rounding safely."""
        scale = 1_000_000_000 if self.nanos else 1_000_000
        total = int(round(ts * scale))
        return total // scale, total % scale

    def _clip(self, frame: bytes, wirelen: int | None) -> tuple[bytes, int]:
        frame = bytes(frame)
        if wirelen is None:
            wirelen = len(frame)
        wirelen = max(int(wirelen), len(frame))
        if len(frame) > self.snaplen:
            frame = frame[: self.snaplen]
        return frame, wirelen

    def _write_header(self) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    def write(self, ts: float, frame: bytes, wirelen: int | None = None) -> None:  # pragma: no cover
        raise NotImplementedError

    def write_all(self, packets) -> None:
        """Write an iterable of ``(ts, frame)`` or ``(ts, frame, wirelen)`` tuples."""
        for p in packets:
            self.write(*p)

    def flush(self) -> None:
        self._fh.flush()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._fh.flush()
        finally:
            if self._owns:
                self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


class PcapWriter(_BaseWriter):
    """Classic little-endian libpcap file (v2.4).

    Magic ``0xa1b2c3d4`` (microseconds) or ``0xa1b23c4d`` when ``nanos=True``.
    """

    def _write_header(self) -> None:
        magic = 0xA1B23C4D if self.nanos else 0xA1B2C3D4
        self._fh.write(struct.pack("<IHHiIII", magic, 2, 4, 0, 0, self.snaplen, self.linktype))

    def write(self, ts: float, frame: bytes, wirelen: int | None = None) -> None:
        frame, wirelen = self._clip(frame, wirelen)
        sec, frac = self._split_ts(ts)
        self._fh.write(struct.pack("<IIII", sec, frac, len(frame), wirelen))
        self._fh.write(frame)
        self.count += 1


def _pad4(n: int) -> int:
    return (4 - n % 4) % 4


def _ng_option(code: int, value: bytes) -> bytes:
    return struct.pack("<HH", code, len(value)) + value + b"\x00" * _pad4(len(value))


def _ng_block(btype: int, body: bytes) -> bytes:
    total = 12 + len(body)
    return struct.pack("<II", btype, total) + body + struct.pack("<I", total)


class PcapNgWriter(_BaseWriter):
    """pcapng file: one Section Header Block, one Interface Description Block,
    then one Enhanced Packet Block per ``write()``.

    ``nanos=True`` sets ``if_tsresol`` to 9 (nanoseconds); default is 6 (µs).
    """

    def __init__(self, path_or_fileobj, linktype: int = LINKTYPE_ETHERNET,
                 snaplen: int = 262144, nanos: bool = False,
                 if_name: str = "eth0", application: str = "faultline-lab"):
        self._if_name = if_name
        self._app = application
        super().__init__(path_or_fileobj, linktype, snaplen, nanos)

    def _write_header(self) -> None:
        shb_opts = _ng_option(4, self._app.encode()) + _ng_option(0, b"")  # shb_userappl, end
        shb = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + shb_opts
        self._fh.write(_ng_block(0x0A0D0D0A, shb))
        tsresol = 9 if self.nanos else 6
        idb_opts = (_ng_option(2, self._if_name.encode())          # if_name
                    + _ng_option(9, bytes([tsresol]))              # if_tsresol
                    + _ng_option(0, b""))
        idb = struct.pack("<HHI", self.linktype, 0, self.snaplen) + idb_opts
        self._fh.write(_ng_block(0x00000001, idb))

    def write(self, ts: float, frame: bytes, wirelen: int | None = None) -> None:
        frame, wirelen = self._clip(frame, wirelen)
        scale = 1_000_000_000 if self.nanos else 1_000_000
        units = int(round(ts * scale))
        body = (struct.pack("<IIIII", 0, (units >> 32) & 0xFFFFFFFF, units & 0xFFFFFFFF,
                            len(frame), wirelen)
                + frame + b"\x00" * _pad4(len(frame)))
        self._fh.write(_ng_block(0x00000006, body))
        self.count += 1
