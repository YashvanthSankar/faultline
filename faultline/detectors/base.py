"""Detector interface.

A detector sees every decoded packet once (streaming, in capture order) and
returns findings at the end. Detectors must:

* keep memory bounded: cap per-key tables (see ``BoundedDict``) and evidence
  lists (``Evidence`` keeps at most ``Evidence.CAP`` frame numbers);
* never raise on odd input: fields may be None, timestamps may go backwards;
* state evidence *for each hypothesis* via ``Indicator``s and provide a
  ``Variant`` per plausible category, so the verdict engine can decide
  fault / misconfig / attack and explain "why not" the others.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Iterable

from ..context import AnalysisContext
from ..model import Category, Finding, Indicator, Packet, Severity, Variant

__all__ = [
    "Detector", "register", "REGISTRY", "Evidence", "BoundedDict",
    "Category", "Finding", "Indicator", "Packet", "Severity", "Variant",
    "AnalysisContext", "fmt_ms", "fmt_pct", "plural",
]

REGISTRY: list[type["Detector"]] = []


def register(cls: type["Detector"]) -> type["Detector"]:
    REGISTRY.append(cls)
    return cls


class Detector:
    name: str = "base"

    def on_packet(self, pkt: Packet, ctx: AnalysisContext) -> None:  # pragma: no cover - interface
        pass

    def finalize(self, ctx: AnalysisContext) -> list[Finding]:  # pragma: no cover - interface
        return []


class Evidence:
    """Collects evidence frames: keeps the first ``CAP`` frame numbers, counts all."""

    CAP = 200

    __slots__ = ("packets", "total", "first_ts", "last_ts")

    def __init__(self) -> None:
        self.packets: list[int] = []
        self.total = 0
        self.first_ts: float | None = None
        self.last_ts: float | None = None

    def add(self, pkt: Packet) -> None:
        self.total += 1
        if len(self.packets) < self.CAP:
            self.packets.append(pkt.no)
        if self.first_ts is None or pkt.ts < self.first_ts:
            self.first_ts = pkt.ts
        if self.last_ts is None or pkt.ts > self.last_ts:
            self.last_ts = pkt.ts

    def merge(self, other: "Evidence") -> None:
        for no in other.packets:
            if len(self.packets) >= self.CAP:
                break
            self.packets.append(no)
        self.total += other.total
        for ts in (other.first_ts, other.last_ts):
            if ts is None:
                continue
            if self.first_ts is None or ts < self.first_ts:
                self.first_ts = ts
            if self.last_ts is None or ts > self.last_ts:
                self.last_ts = ts

    def apply(self, finding: Finding) -> Finding:
        """Copy evidence into a finding (sorted, de-duplicated)."""
        finding.packets = sorted(set(self.packets))[: self.CAP]
        finding.packet_total = max(self.total, len(finding.packets))
        finding.first_ts = self.first_ts
        finding.last_ts = self.last_ts
        return finding


class BoundedDict(OrderedDict):
    """Dict that evicts the oldest key once ``maxlen`` is reached (LRU-ish).

    Use it for per-flow / per-host state so hostile captures with millions of
    random addresses cannot exhaust memory.
    """

    def __init__(self, maxlen: int = 100_000):
        super().__init__()
        self.maxlen = maxlen
        self.evicted = 0

    def __setitem__(self, key, value):
        if key not in self and len(self) >= self.maxlen:
            self.popitem(last=False)
            self.evicted += 1
        super().__setitem__(key, value)


def fmt_ms(seconds: float | None) -> str:
    if seconds is None:
        return "n/a"
    if seconds >= 1:
        return f"{seconds:.2f} s"
    return f"{seconds * 1000:.1f} ms"


def fmt_pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def plural(n: int, word: str, suffix: str = "s") -> str:
    return f"{n:,} {word}{'' if n == 1 else suffix}"


def top(items: Iterable, n: int = 5) -> list:
    return list(items)[:n]
