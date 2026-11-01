"""Stealth scans that the port-scan counter in ``scan.py`` cannot see.

``scan.idle``       An *idle* ("zombie") scan. The scanner never talks to the target
                    under its own address. It sends forged connection requests that
                    claim to come from an innocent third host (the zombie) and learns
                    the result by reading the zombie's IPv4 ID counter, which goes up
                    by one for every packet the zombie sends. What the capture shows:

                    * unsolicited SYN/ACKs sent to the zombie (nobody asked for them),
                      each answered with a RST whose IP ID has grown by a small, steady
                      step: the scanner is sampling the counter;
                    * SYNs that claim to come from the zombie, sent to the real target
                      while the zombie is being sampled.

                    The target only ever sees the zombie's address; the finding names
                    the host that was really doing the sampling.

``scan.ack_probe``  An ACK scan (``nmap -sA``), used to map firewall rules rather than
                    find open ports. Each probe is a bare TCP acknowledgement for a
                    connection that never existed: no handshake before it, no data after
                    it, only (at most) a RST back. A real connection that merely started
                    before the capture looks different: it keeps carrying traffic.

Both detectors only use header fields, never payload.
"""

from __future__ import annotations

from ..model import Tcp
from .base import (
    AnalysisContext, BoundedDict, Category, Detector, Evidence, Finding, Indicator, Packet, Severity, Variant,
    plural, register,
)
from .scan import scanner_sources

SYN, ACK, RST, FIN, PSH, URG = Tcp.SYN, Tcp.ACK, Tcp.RST, Tcp.FIN, Tcp.PSH, Tcp.URG
NMAP_WINDOWS = {1024, 2048, 3072, 4096}  # window sizes nmap uses for raw probes


def _ipid_step(a: int, b: int) -> int:
    return (b - a) & 0xFFFF


def _ev_add(ev: Evidence, no: int, ts: float) -> None:
    """Evidence.add from a stored (frame number, timestamp) instead of a kept Packet object."""
    ev.total += 1
    if len(ev.packets) < ev.CAP:
        ev.packets.append(no)
    if ev.first_ts is None or ts < ev.first_ts:
        ev.first_ts = ts
    if ev.last_ts is None or ts > ev.last_ts:
        ev.last_ts = ts


# --------------------------------------------------------------------------- #
# Idle / zombie scan
# --------------------------------------------------------------------------- #


class _Zombie:
    __slots__ = ("ip", "mac", "probers", "prober_macs", "sports", "low_sports", "dports", "sent", "ids", "ev", "first", "last")

    def __init__(self, ip: str) -> None:
        self.ip = ip
        self.mac: str | None = None  # the zombie's own network card, from its RST replies
        self.probers: dict[str, int] = {}  # host that sent the SYN/ACK -> count
        self.prober_macs: dict[str, str] = {}  # MAC that put each prober's SYN/ACKs on the wire -> prober
        self.sports: set[int] = set()
        self.low_sports = 0  # SYN/ACKs from a well-known port (looks like DoS backscatter instead)
        self.dports: set[int] = set()
        self.sent = 0  # unsolicited SYN/ACKs
        self.ids: list[tuple[float, int, str]] = []  # (ts, IP ID of the zombie's RST, prober)
        self.ev = Evidence()
        self.first = self.last = 0.0


@register
class IdleScanDetector(Detector):
    name = "idle_scan"
    MIN_SAMPLES = 4  # RST answers needed to call the counter "sampled"
    MAX_STEP = 10  # IP ID growth between samples that still counts as "steady"

    def __init__(self) -> None:
        self.syns: BoundedDict = BoundedDict(100_000)  # (src, sport, dst, dport) of every SYN
        self.pending: BoundedDict = BoundedDict(20_000)  # (zombie, zport, prober, pport) -> _Zombie
        self.zombies: BoundedDict = BoundedDict(2_000)
        self.syns_from: BoundedDict = BoundedDict(5_000)  # src -> list[(ts, dst, dport, sport, no)]

    def on_packet(self, pkt: Packet, ctx: AnalysisContext) -> None:
        tcp = pkt.tcp
        if tcp is None or pkt.src is None or pkt.dst is None or pkt.ip_ver != 4:
            return
        fl = tcp.flags or 0
        src, dst, sp, dp = pkt.src, pkt.dst, tcp.sport, tcp.dport
        if fl & SYN and not fl & (ACK | RST | FIN):
            self.syns[(src, sp, dst, dp)] = None
            lst = self.syns_from.get(src)
            if lst is None:
                lst = self.syns_from[src] = []
            if len(lst) < 64:
                lst.append((pkt.ts or 0.0, dst, dp, sp, pkt.no, pkt.eth_src))
            return
        if fl & SYN and fl & ACK and not fl & RST:
            if (dst, dp, src, sp) in self.syns:
                return  # an answer to a SYN we saw: a normal handshake
            z = self.zombies.get(dst)
            if z is None:
                z = self.zombies[dst] = _Zombie(dst)
                z.first = pkt.ts or 0.0
            z.sent += 1
            z.last = max(z.last, pkt.ts or 0.0)
            z.probers[src] = z.probers.get(src, 0) + 1
            if pkt.eth_src and len(z.prober_macs) < 16:
                z.prober_macs.setdefault(pkt.eth_src, src)
            if len(z.sports) < 1024:
                z.sports.add(sp)
            if sp is not None and sp < 1024:
                z.low_sports += 1
            if len(z.dports) < 64:
                z.dports.add(dp)
            z.ev.add(pkt)
            self.pending[(dst, dp, src, sp)] = z
            return
        if fl & RST and not fl & SYN:
            z = self.pending.pop((src, sp, dst, dp), None)
            if z is not None and pkt.ip_id is not None and len(z.ids) < 4096:
                z.mac = z.mac or pkt.eth_src
                z.ids.append((pkt.ts or 0.0, pkt.ip_id, dst))
                z.ev.add(pkt)
                z.last = max(z.last, pkt.ts or 0.0)

    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        out: list[Finding] = []
        for z in list(self.zombies.values()):
            f = self._finding(z, ctx)
            if f is not None:
                out.append(f)
        return out

    def _finding(self, z: _Zombie, ctx: AnalysisContext) -> Finding | None:
        n = len(z.ids)
        if n < self.MIN_SAMPLES or len(z.dports) > 2:
            return None
        if z.low_sports * 2 >= z.sent:
            return None  # SYN/ACKs from a server port to many clients: backscatter of a spoofed SYN flood
        ids = sorted(z.ids)
        steps = [_ipid_step(a[1], b[1]) for a, b in zip(ids, ids[1:])]
        steady = sum(1 for s in steps if 1 <= s <= self.MAX_STEP) / max(1, len(steps))
        # SYNs that claim to come from the zombie while it is being sampled
        lo, hi = ids[0][0] - 1.0, ids[-1][0] + 5.0
        forged = [s for s in (self.syns_from.get(z.ip) or []) if lo <= s[0] <= hi]
        forged_ev = Evidence()
        for s in forged:
            _ev_add(forged_ev, s[4], s[0])
        if steady < 0.6 and not forged:
            return None
        targets: dict[str, set[int]] = {}
        for _ts, d, dp, _sp, _no, _mac in forged:
            targets.setdefault(d, set()).add(dp)
        reused = sum(1 for s in forged if s[3] in z.dports)
        # the real scanner: the prober that is not itself one of the targets, with the most probes
        # the network card that actually transmitted the forged requests (same LAN segment only)
        fmacs = [s[5] for s in forged if s[5] and s[5] != z.mac]
        sent_by = max(set(fmacs), key=fmacs.count) if fmacs else None
        mac_owner = z.prober_macs.get(sent_by) if sent_by else None
        if mac_owner in targets:
            mac_owner = None
        probers = sorted(z.probers.items(), key=lambda kv: (kv[0] != mac_owner, kv[0] in targets, -kv[1]))
        scanner = probers[0][0]
        decoys = [p for p, _ in probers[1:]]
        zport = sorted(z.dports)[0]
        A, F = Category.ATTACK, Category.FAULT
        ind = [Indicator(
            f"{scanner} sent {plural(z.probers[scanner], 'SYN/ACK')} to {z.ip}:{zport} that answer no connection request; "
            f"{z.ip} rejected each with a RST", A, 2.0)]
        if steady >= 0.6:
            first_ids = ", ".join(str(i[1]) for i in ids[:5])
            ind.append(Indicator(
                f"The IP ID in {z.ip}'s replies rose in small, steady steps ({first_ids}, ...): someone was reading its "
                "packet counter, which is how an idle scan learns results without showing its own address", A, 2.5))
        if forged:
            tg = ", ".join(f"{d}:{'/'.join(str(p) for p in sorted(ps)[:3])}" for d, ps in list(targets.items())[:3])
            ind.append(Indicator(
                f"During the same seconds, {plural(len(forged), 'connection request')} claiming to come from {z.ip} "
                f"went to {tg}: the scanner forged {z.ip}'s address to probe the real target", A, 3.0))
        if mac_owner and z.mac:
            ind.append(Indicator(
                f"The requests carrying {z.ip}'s address were transmitted by network card {sent_by}, which is "
                f"{scanner}'s, not {z.ip}'s own ({z.mac}): proof of a forged sender", A, 2.0))
        if reused:
            ind.append(Indicator(
                f"Those requests use source port {zport}, the same port the scanner was sampling on {z.ip}", A, 1.0))
        if decoys:
            ind.append(Indicator(
                f"SYN/ACKs to {z.ip} also arrived claiming to come from {', '.join(decoys[:3])} (the scanner checking "
                "that the zombie's counter reacts to other hosts)", A, 0.5))
        if not forged:
            ind.append(Indicator(
                "No forged connection requests were seen; the SYNs that would explain these SYN/ACKs may just be "
                "missing from the capture (asymmetric routing, capture started late)", F, 1.5))
        sev = Severity.HIGH if forged else Severity.MEDIUM
        tgt_txt = ", ".join(list(targets)[:3]) or "another host"
        ev = Evidence()
        ev.merge(z.ev)
        ev.merge(forged_ev)
        attack = Variant(
            title=f"Idle (zombie) scan: {scanner} is scanning {tgt_txt} while hiding behind {z.ip}",
            summary=(f"{scanner} sampled {z.ip}'s IP ID counter {n} times"
                     + (f" while forged requests from {z.ip} probed {tgt_txt}." if forged else ".")),
            explanation=(
                f"This is one of the stealthiest ways to scan a network. The scanner never contacts the target with its own "
                f"address. It sends connection requests that pretend to come from {z.ip} (the 'zombie'), and works out "
                f"which ports are open by watching a counter inside {z.ip}'s packets go up. The target's logs show only "
                f"{z.ip}; the real scanner is {scanner}."),
            analogy=("Like someone posting letters with a neighbour's return address and then checking how full the "
                     "neighbour's letterbox gets, to learn who wrote back."),
            cause=f"A scanning tool (such as `nmap -sI`) on {scanner}, using {z.ip} as an unwitting relay.",
            fix=[
                f"Investigate {scanner}, not {z.ip}: find the device (`arp -a`, DHCP leases, switch MAC table) and who owns it.",
                f"Block {scanner} at the firewall and check it for malware or unauthorised tools.",
                f"Update or replace {z.ip}: modern systems use random IP IDs, which makes them useless as a zombie.",
                "Enable anti-spoofing (ingress filtering / unicast RPF) on the router so hosts cannot send packets with "
                "another host's address.",
                f"On {tgt_txt}, review what is listening; the scanner may now know which ports are open.",
            ],
            mitre="T1046 Network Service Discovery", severity=sev)
        fault = Variant(
            title=f"{z.ip} receives SYN/ACKs it never asked for",
            summary=f"{z.ip} answered {plural(n, 'unexpected SYN/ACK')} with a RST.",
            explanation=("A SYN/ACK is the second step of opening a connection. If the first step was sent on a path "
                         "the capture did not see, the replies look unsolicited. This can happen with asymmetric routing."),
            cause="The capture point sees only one direction of some connections.",
            fix=["Capture on a port that sees both directions (a mirror port on the router uplink).",
                 "If the pattern repeats with a steady IP ID, treat it as a scan."],
            severity=Severity.LOW)
        f = Finding(
            kind="scan.idle", category=A, severity=sev, title=attack.title, summary=attack.summary,
            explanation=attack.explanation, cause=attack.cause, fix=attack.fix, analogy=attack.analogy,
            mitre=attack.mitre,
            technical=(f"Zombie {z.ip}: {z.sent} unsolicited SYN/ACKs to port(s) {sorted(z.dports)} from "
                       f"{dict(list(z.probers.items())[:5])}; {n} RST replies, IP ID steps {steps[:12]} "
                       f"({steady:.0%} within 1..{self.MAX_STEP}); {len(forged)} SYNs claiming src {z.ip} in the "
                       f"sampling window, {reused} reusing the sampled port; targets {sorted(targets)[:5]}."),
            hosts=[scanner, z.ip] + [t for t in targets if t not in (scanner, z.ip)][:6],
            metrics={"scanner": scanner, "zombie": z.ip, "zombie_port": zport, "samples": n,
                     "ipid_steps": steps[:20], "steady_ratio": round(steady, 3), "forged_syns": len(forged),
                     "targets": sorted(targets)[:10], "decoy_sources": decoys[:5],
                     "forged_sender_mac": sent_by if mac_owner else None},
            indicators=ind, variants={A: attack, F: fault})
        scanner_sources(ctx).add(scanner)
        return ev.apply(f)


# --------------------------------------------------------------------------- #
# ACK scan
# --------------------------------------------------------------------------- #


@register
class AckScanDetector(Detector):
    name = "ack_scan"
    MANY_PORTS = 10

    def __init__(self) -> None:
        self.seen: BoundedDict = BoundedDict(200_000)  # normalised 4-tuples with any traffic
        self.cand: BoundedDict = BoundedDict(50_000)  # (src, sport, dst, dport) -> [(no, ts, win), seq0, nmap_win, rst?, alive]

    @staticmethod
    def _norm(src: str, sp: int, dst: str, dp: int) -> tuple:
        a, b = (src, sp), (dst, dp)
        return (a, b) if a <= b else (b, a)

    def on_packet(self, pkt: Packet, ctx: AnalysisContext) -> None:
        tcp = pkt.tcp
        if tcp is None or pkt.src is None or pkt.dst is None or tcp.sport is None or tcp.dport is None:
            return
        src, dst, sp, dp = pkt.src, pkt.dst, tcp.sport, tcp.dport
        fl = tcp.flags or 0
        c = self.cand.get((src, sp, dst, dp))
        if c is not None:  # the probing side keeps talking: a real connection
            c[4] = True
        else:
            c = self.cand.get((dst, dp, src, sp))
            if c is not None:
                if fl & RST and not tcp.plen:
                    c[3] = True
                else:
                    c[4] = True
        k = self._norm(src, sp, dst, dp)
        if k in self.seen:
            return
        self.seen[k] = None
        if fl == ACK and not tcp.plen and (tcp.hlen or 20) <= 20 and not pkt.malformed:
            self.cand[(src, sp, dst, dp)] = [(pkt.no, pkt.ts or 0.0, tcp.win), (tcp.seq or 0) == 0, tcp.win in NMAP_WINDOWS, False, False]

    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        groups: dict[tuple[str, str], list] = {}
        for (src, sp, dst, dp), c in self.cand.items():
            if c[4]:
                continue
            groups.setdefault((src, dst), []).append((sp, dp, c))
        already = scanner_sources(ctx)
        out = []
        for (src, dst), probes in groups.items():
            if src in already:
                continue
            f = self._finding(src, dst, probes, ctx)
            if f is not None:
                out.append(f)
        return out

    def _finding(self, src: str, dst: str, probes: list, ctx: AnalysisContext) -> Finding | None:
        n = len(probes)
        sports = {p[0] for p in probes}
        dports = sorted({p[1] for p in probes})
        seq0 = sum(1 for p in probes if p[2][1])
        nmapw = sum(1 for p in probes if p[2][2])
        rst = sum(1 for p in probes if p[2][3])
        signature = seq0 == n or nmapw == n
        if n < 2 or len(sports) < 2:
            return None
        if len(dports) < self.MANY_PORTS and not signature:
            return None  # a couple of stray ACKs with ordinary headers: not enough to call it a scan
        A, F = Category.ATTACK, Category.FAULT
        ports_txt = ", ".join(str(p) for p in dports[:8]) + ("..." if len(dports) > 8 else "")
        ind = [Indicator(
            f"{src} sent {plural(n, 'bare TCP acknowledgement')} to {dst} (port {ports_txt}) for connections that never "
            "existed: no handshake before, no data after", A, 2.0)]
        if len(sports) == n:
            ind.append(Indicator(f"Each one came from a new source port ({len(sports)} ports), as a probing tool does", A, 1.0))
        if seq0 == n:
            ind.append(Indicator("Every probe has sequence number 0, which a real connection practically never uses", A, 1.5))
        if nmapw == n:
            ind.append(Indicator(f"Every probe uses window size {probes[0][2][0][2]} and no TCP options, the "
                                 "fingerprint of a raw-packet scanner such as nmap", A, 1.0))
        if len(dports) >= self.MANY_PORTS:
            ind.append(Indicator(f"{plural(len(dports), 'different port')} were probed this way", A, 2.0))
        if rst:
            ind.append(Indicator(f"{dst} answered {rst} with a RST, which tells the scanner the port is not filtered", A, 0.5))
        else:
            ind.append(Indicator(f"{dst} never answered, which tells the scanner a firewall is filtering the port", A, 0.5))
        if n <= 3:
            ind.append(Indicator(f"Only {plural(n, 'packet')}; a capture that starts in the middle of old connections "
                                 "can also contain stray acknowledgements", F, 1.0))
        sev = Severity.MEDIUM if len(dports) < self.MANY_PORTS else Severity.HIGH
        ev = Evidence()
        for p in probes:
            _ev_add(ev, p[2][0][0], p[2][0][1])
        what = f"port {dports[0]}" if len(dports) == 1 else plural(len(dports), "port")
        attack = Variant(
            title=f"ACK scan: {src} is mapping the firewall in front of {dst} ({what})",
            summary=f"{src} sent {plural(n, 'connection-less ACK probe')} to {dst} on {what}; {rst} drew a RST.",
            explanation=(
                "Instead of asking to open a connection, the scanner sends acknowledgements for connections that never "
                "existed. A host with no firewall in front answers with a reset; a firewall silently drops them. The "
                "scanner learns which ports the firewall lets through, often as preparation for a later attack."),
            analogy="Like rattling a door and listening for whether a guard or an empty room answers.",
            cause=f"A scanning tool (such as `nmap -sA`) on {src}, checking firewall rules.",
            fix=[
                f"Identify the device behind {src} (`arp -a`, DHCP leases, switch MAC table) and who owns it.",
                f"If it is not an authorised security test, block {src} at the firewall and check it for malware.",
                "Use a stateful firewall that drops TCP packets that do not belong to a known connection.",
                f"Review firewall logs for further activity from {src}.",
            ],
            mitre="T1046 Network Service Discovery", severity=sev)
        fault = Variant(
            title=f"Stray TCP acknowledgements from {src} to {dst}",
            summary=f"{plural(n, 'acknowledgement')} for connections not present in the capture.",
            explanation=("If the capture started after a connection was opened, or one side restarted and forgot the "
                         "connection, a few acknowledgements can arrive with no connection around them."),
            cause="A capture started mid-connection, or a device that restarted and lost its connection state.",
            fix=["Capture for longer from before the problem starts.", "If the packets repeat, treat them as a scan."],
            severity=Severity.LOW)
        f = Finding(
            kind="scan.ack_probe", category=A, severity=sev, title=attack.title, summary=attack.summary,
            explanation=attack.explanation, cause=attack.cause, fix=attack.fix, analogy=attack.analogy,
            mitre=attack.mitre,
            technical=(f"{n} orphan ACK probes {src} -> {dst}, {len(sports)} source ports, destination ports {dports[:20]}; "
                       f"seq=0 on {seq0}, nmap window on {nmapw}, no TCP options, no payload; {rst} answered by RST, "
                       "none followed by further traffic in the flow."),
            hosts=[src, dst],
            metrics={"source": src, "target": dst, "probes": n, "ports": dports[:50], "source_ports": len(sports),
                     "seq_zero": seq0, "nmap_window": nmapw, "rst_replies": rst},
            indicators=ind, variants={A: attack, F: fault})
        scanner_sources(ctx).add(src)
        return ev.apply(f)
