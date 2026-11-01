"""Analysis pipeline: capture → packets → detectors → verdicts → report.

Two passes over the file:
1. Stream every frame through the decoder, the host table and all detectors.
2. Re-read only the evidence frames to attach human-readable evidence lines
   and small per-finding evidence pcaps (skipped in redact mode).

A misbehaving detector never takes the analysis down: its exception is
recorded as a warning and the detector is disabled.
"""

from __future__ import annotations

import base64
import hashlib
import io
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from . import __version__
from .capture.decode import decode
from .capture.reader import CaptureReader, Limits, read_frames
from .capture.writer import PcapWriter
from .context import AnalysisContext, Config, is_private, protocol_label
from .correlate import assign_ids, correlate, health_score, overall_verdict
from .detectors import all_detectors
from .detectors.base import Evidence
from .model import Category, Finding, Incident, Indicator, Severity
from .verdict import assess

MAX_EVIDENCE_LINES = 40
MAX_EVIDENCE_PCAP_PACKETS = 150
MAX_EVIDENCE_TOTAL_BYTES = 8 * 1024 * 1024
MAX_TIMELINE_POINTS = 240
MAX_CONVERSATIONS = 50_000
DETECTOR_ERROR_LIMIT = 25


@dataclass
class AnalyzeOptions:
    redact: bool = False
    sensitivity: str = "normal"  # low | normal | high
    evidence: bool = True  # attach evidence lines + evidence pcaps
    max_packets: int | None = None
    limits: Limits | None = None


@dataclass
class Report:
    capture: dict
    verdict: dict
    findings: list[Finding]
    incidents: list[Incident]
    hosts: list[dict]
    stats: dict
    warnings: list[str]
    evidence_lines: dict[str, list[dict]] = field(default_factory=dict)
    evidence_pcaps: dict[str, str] = field(default_factory=dict)
    redacted: bool = False
    elapsed: float = 0.0

    def to_dict(self) -> dict:
        findings = []
        for f in self.findings:
            d = f.to_dict()
            d["evidence_lines"] = self.evidence_lines.get(f.id, [])
            findings.append(d)
        out = {
            "tool": {"name": "Faultline", "version": __version__},
            "generated_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
            "capture": self.capture,
            "verdict": self.verdict,
            "findings": findings,
            "incidents": [i.to_dict() for i in self.incidents],
            "hosts": self.hosts,
            "stats": self.stats,
            "redacted": self.redacted,
            "warnings": list(self.warnings),
            "analysis_seconds": round(self.elapsed, 3),
        }
        if self.evidence_pcaps and not self.redacted:
            out["evidence"] = dict(self.evidence_pcaps)
        if self.redacted:
            try:
                from .report.redact import redact_report
            except ImportError:  # pragma: no cover - module ships with the package
                raise RuntimeError("redaction module unavailable") from None
            out = redact_report(out)
        return out


def _sha256(path: str, limit: int) -> str:
    h = hashlib.sha256()
    read = 0
    with open(path, "rb") as fh:
        while read < limit:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
            read += len(chunk)
    return h.hexdigest()


class _Stats:
    """Traffic statistics gathered in the main pass (bounded memory)."""

    def __init__(self) -> None:
        self.per_second: dict[int, list[int]] = {}
        self.conversations: Counter = Counter()
        self.conv_bytes: Counter = Counter()
        self.malformed = Evidence()
        self.malformed_reasons: Counter = Counter()

    def observe(self, p) -> None:
        sec = int(p.ts)
        slot = self.per_second.get(sec)
        if slot is None:
            if len(self.per_second) < 500_000:
                slot = self.per_second[sec] = [0, 0]
            else:
                return
        slot[0] += 1
        slot[1] += p.wirelen
        if p.src and p.dst:
            a, b = (p.src, p.dst) if p.src <= p.dst else (p.dst, p.src)
            key = (a, b, protocol_label(p))
            if key in self.conversations or len(self.conversations) < MAX_CONVERSATIONS:
                self.conversations[key] += 1
                self.conv_bytes[key] += p.wirelen
        if p.malformed:
            self.malformed.add(p)
            self.malformed_reasons[p.malformed.split(":")[0][:40]] += 1

    def timeline(self, start: float | None, end: float | None) -> dict:
        if not self.per_second or start is None or end is None:
            return {"start": start, "bucket_seconds": 1, "series": []}
        span = max(1.0, end - start)
        bucket = 1
        while span / bucket > MAX_TIMELINE_POINTS:
            bucket *= 2
        base = int(start)
        series: dict[int, list[int]] = {}
        for sec, (pk, by) in self.per_second.items():
            idx = (sec - base) // bucket
            s = series.setdefault(idx, [0, 0])
            s[0] += pk
            s[1] += by
        n = int(span // bucket) + 1
        out = []
        for i in range(min(n, MAX_TIMELINE_POINTS + 1)):
            pk, by = series.get(i, (0, 0))
            out.append({"t": base + i * bucket, "packets": pk, "bytes": by})
        return {"start": start, "bucket_seconds": bucket, "series": out}


def _malformed_finding(stats: _Stats, ctx: AnalysisContext) -> Finding | None:
    ev = stats.malformed
    if ev.total == 0:
        return None
    ratio = ev.total / max(1, ctx.packet_count)
    reasons = ", ".join(f"{r} ({n})" for r, n in stats.malformed_reasons.most_common(4))
    many = ratio >= 0.05 and ev.total >= 20
    f = Finding(
        kind="capture.malformed",
        category=Category.FAULT if many else Category.INFO,
        severity=Severity.MEDIUM if many else Severity.INFO,
        title="Damaged or unusual packets in the capture" if many else "A few packets could not be fully decoded",
        summary=f"{ev.total:,} of {ctx.packet_count:,} packets ({ratio:.1%}) were damaged or non-standard.",
        explanation=(
            "Some packets in this capture don't follow the protocol rules, so parts of them could not be read. "
            "Faultline skipped those parts safely and analysed everything else."
        ),
        analogy="Like a few pages of a letter being smudged: you can still read the rest.",
        cause=(
            "Usually the capture was cut short or taken with a small snap length, or a network card / driver is damaging frames. "
            "Rarely, deliberately malformed packets are used to crash or evade security tools."
        ),
        fix=[
            "Re-capture with a full snap length (e.g. `tcpdump -s 0 -w capture.pcap`).",
            "If the damaged packets come from one device, check its cable, network card and driver.",
            "If the damaged packets target one server from an unknown device, treat it as suspicious and investigate that device.",
        ],
        technical=f"Malformed frames: {ev.total} ({ratio:.2%}). Reasons: {reasons}.",
        metrics={"malformed": ev.total, "ratio": round(ratio, 4), "reasons": dict(stats.malformed_reasons.most_common(6))},
    )
    if many:
        f.indicators.append(Indicator(f"{ratio:.0%} of packets are damaged, typical of a capture or hardware problem", Category.FAULT, 1.0))
    ev.apply(f)
    return f


def analyze(path: str, options: AnalyzeOptions | None = None, display_name: str | None = None,
            progress: Callable[[int], None] | None = None) -> Report:
    """Analyse a capture file. Raises ``CaptureError`` if the file is unusable."""
    opts = options or AnalyzeOptions()
    started = time.perf_counter()
    limits = opts.limits or Limits()
    if opts.max_packets:
        limits.max_packets = max(1, int(opts.max_packets))
    reader = CaptureReader(path, limits, display_name)
    ctx = AnalysisContext(reader.info, Config(sensitivity=opts.sensitivity))
    detectors = all_detectors()
    errors: Counter = Counter()
    disabled: set[str] = set()
    warnings: list[str] = []
    stats = _Stats()

    for frame in reader:
        p = decode(frame)
        ctx.observe(p)
        stats.observe(p)
        for d in detectors:
            if d.name in disabled:
                continue
            try:
                d.on_packet(p, ctx)
            except Exception as exc:  # a detector bug must not kill the analysis
                errors[d.name] += 1
                if errors[d.name] >= DETECTOR_ERROR_LIMIT:
                    disabled.add(d.name)
                    warnings.append(f"detector '{d.name}' disabled after repeated internal errors ({type(exc).__name__})")
        if progress is not None and ctx.packet_count % 5000 == 0:
            progress(ctx.packet_count)

    findings: list[Finding] = []
    for d in detectors:
        try:
            findings.extend(d.finalize(ctx) or [])
        except Exception as exc:
            warnings.append(f"detector '{d.name}' failed while summarising ({type(exc).__name__}); its results are omitted")
    for name, n in errors.items():
        if name not in disabled:
            warnings.append(f"detector '{name}' skipped {n} packet(s) after internal errors")
    mf = _malformed_finding(stats, ctx)
    if mf is not None:
        findings.append(mf)

    for f in findings:
        assess(f)
    assign_ids(findings)
    incidents = correlate(findings)
    # re-rank so root causes come before their symptoms, keep ids stable
    findings.sort(key=lambda f: (f.symptom_of is not None, -int(f.severity), f.id and int(f.id[1:])))

    info = reader.info
    capture = info.to_dict()
    capture["sha256"] = _sha256(path, limits.max_file_bytes)
    capture["malformed_packets"] = ctx.malformed
    verdict = overall_verdict(findings, ctx.packet_count, ctx.duration)

    timeline = stats.timeline(ctx.start_ts, ctx.end_ts)
    timeline["markers"] = [
        {"t": f.first_ts, "end": f.last_ts, "finding": f.id, "category": f.category.value, "title": f.title}
        for f in findings if f.first_ts is not None and f.severity >= Severity.LOW
    ]
    talkers = sorted(ctx.hosts.hosts.values(), key=lambda h: -h.bytes_sent)[:10]
    convs = []
    for (a, b, proto), n in stats.conversations.most_common(15):
        convs.append({"a": a, "b": b, "proto": proto, "packets": n, "bytes": stats.conv_bytes[(a, b, proto)]})
    stats_out = {
        "protocols": dict(ctx.protocols.most_common()),
        "top_talkers": [{"ip": h.ip, "packets": h.packets_sent, "bytes": h.bytes_sent, "local": is_private(h.ip)} for h in talkers],
        "conversations": convs,
        "timeline": timeline,
    }

    report = Report(
        capture=capture,
        verdict=verdict,
        findings=findings,
        incidents=incidents,
        hosts=ctx.hosts.to_list(),
        stats=stats_out,
        warnings=list(info.warnings) + warnings,
        redacted=opts.redact,
    )
    if opts.evidence and findings:
        _attach_evidence(path, limits, report, with_pcaps=not opts.redact)
    report.elapsed = time.perf_counter() - started
    return report


def _attach_evidence(path: str, limits: Limits, report: Report, with_pcaps: bool) -> None:
    """Second pass: evidence lines (summaries) and per-finding evidence pcaps."""
    line_wanted: dict[int, list[str]] = {}
    pcap_wanted: dict[int, list[str]] = {}
    for f in report.findings:
        for no in f.packets[:MAX_EVIDENCE_LINES]:
            line_wanted.setdefault(no, []).append(f.id)
        if with_pcaps:
            for no in f.packets[:MAX_EVIDENCE_PCAP_PACKETS]:
                pcap_wanted.setdefault(no, []).append(f.id)
    wanted = set(line_wanted) | set(pcap_wanted)
    if not wanted:
        return
    lines: dict[str, list[dict]] = {}
    buffers: dict[str, tuple[io.BytesIO, PcapWriter, int]] = {}
    total_bytes = 0
    start = report.capture.get("first_ts") or 0.0
    try:
        for frame in read_frames(path, wanted, limits):
            if frame.no in line_wanted:
                p = decode(frame)
                entry = {"no": frame.no, "ts": frame.ts, "rel": round(frame.ts - start, 6), "summary": p.summary()[:240]}
                for fid in line_wanted[frame.no]:
                    lines.setdefault(fid, []).append(entry)
            if frame.no in pcap_wanted and total_bytes < MAX_EVIDENCE_TOTAL_BYTES:
                for fid in pcap_wanted[frame.no]:
                    slot = buffers.get(fid)
                    if slot is None:
                        buf = io.BytesIO()
                        slot = buffers[fid] = (buf, PcapWriter(buf, linktype=frame.linktype), frame.linktype)
                    buf, writer, lt = slot
                    if lt != frame.linktype:
                        continue
                    writer.write(frame.ts, frame.data, frame.wirelen)
                    total_bytes += len(frame.data) + 16
    except Exception as exc:  # evidence is best-effort; never fail the analysis
        report.warnings.append(f"evidence extraction stopped early ({type(exc).__name__})")
    report.evidence_lines = lines
    for fid, (buf, writer, _lt) in buffers.items():
        try:
            writer.flush()
        except Exception:
            pass
        report.evidence_pcaps[fid] = base64.b64encode(buf.getvalue()).decode("ascii")
    if total_bytes >= MAX_EVIDENCE_TOTAL_BYTES:
        report.warnings.append("evidence pcaps were capped at 8 MiB in total")


def evidence_pcap_bytes(report_dict: dict, finding_id: str) -> bytes | None:
    data = (report_dict.get("evidence") or {}).get(finding_id)
    if not data:
        return None
    return base64.b64decode(data)


def health(findings: list[Finding]) -> int:  # convenience re-export
    return health_score(findings)
