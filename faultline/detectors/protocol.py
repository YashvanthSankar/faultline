"""Protocol-level anomalies found while testing on public real-world captures.

``dns.non_dns_traffic``   Something that is not DNS uses port 53: typically a backdoor
                          shell or tunnel hiding on the one port firewalls always allow
                          (seen in the public Wireshark sample ``dns-remoteshell.pcap``).
``ip.fragment_attack``    Overlapping IP fragments (Teardrop-style) and tiny first
                          fragments that split the TCP header (firewall/IDS evasion,
                          e.g. ``nmap -f``), seen in ``teardrop.cap`` and the Nmap samples.
"""

from __future__ import annotations

from .base import (
    AnalysisContext, BoundedDict, Category, Detector, Evidence, Finding, Indicator, Packet, Severity, Variant,
    plural, register,
)


def _clip(s, n: int = 100) -> str:
    return "".join(ch for ch in str(s) if ch.isprintable())[:n]


@register
class NonDnsOnDnsPort(Detector):
    """Readable text (and especially shell output) on TCP/UDP port 53, where only binary DNS belongs."""

    name = "dns_port_abuse"

    def __init__(self) -> None:
        self.flows: BoundedDict = BoundedDict(20_000)  # (a, ap, b, bp) -> [Evidence, shell?, dirs:set]
        self.dns_answers: dict[str, int] = {}  # server ip -> real DNS answers it sent

    def on_packet(self, pkt: Packet, ctx: AnalysisContext) -> None:
        if pkt.dns is not None and pkt.dns.qr and pkt.src and len(self.dns_answers) < 50_000:
            self.dns_answers[pkt.src] = self.dns_answers.get(pkt.src, 0) + 1
        kind = pkt.app_anomaly
        if not kind or pkt.src is None or pkt.dst is None:
            return
        sp, dp = pkt.sport, pkt.dport
        if dp == 53:
            key, side = (pkt.src, sp, pkt.dst, dp), "client"
        else:
            key, side = (pkt.dst, dp, pkt.src, sp), "server"
        st = self.flows.get(key)
        if st is None:
            st = self.flows[key] = [Evidence(), False, set(), "tcp" if pkt.tcp is not None else "udp"]
        st[0].add(pkt)
        st[1] = st[1] or kind.startswith("shell")
        st[2].add(side)

    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        if not self.flows:
            return []
        ev = Evidence()
        shell = False
        both = False
        servers: dict[str, int] = {}
        clients: set[str] = set()
        transports: set[str] = set()
        for (cli, _cp, srv, _sp), (e, sh, dirs, tr) in self.flows.items():
            ev.merge(e)
            shell = shell or sh
            both = both or len(dirs) == 2
            servers[srv] = servers.get(srv, 0) + e.total
            clients.add(cli)
            transports.add(tr)
        if ev.total < 3 and not shell:
            return []
        top_srv = max(servers, key=servers.get)
        real_dns = self.dns_answers.get(top_srv, 0)
        A, M = Category.ATTACK, Category.MISCONFIG
        ind = [Indicator(f"{plural(ev.total, 'packet')} on port 53 carry readable text; real DNS messages are binary", A, 1.5)]
        if shell:
            ind.append(Indicator("The text looks like a command shell (a Windows/Unix prompt or command output)", A, 3.0))
        if both:
            ind.append(Indicator("Text flows in both directions, like an interactive session", A, 1.0))
        if real_dns == 0:
            ind.append(Indicator(f"{top_srv} never answered a single real DNS query, so it is not a DNS server", A, 1.0))
        else:
            ind.append(Indicator(f"{top_srv} also answers real DNS queries ({real_dns}), so it might be a quirky DNS service", M, 1.0))
        if not shell and not both:
            ind.append(Indicator("Only one direction carries text: could be an application misusing port 53", M, 0.5))
        sev = Severity.CRITICAL if shell else Severity.HIGH
        port = "/".join(sorted(transports)).upper()
        attack = Variant(
            title=(f"A remote shell is hiding on the DNS port ({top_srv}:53)" if shell
                   else f"Something other than DNS is using the DNS port ({top_srv}:53)"),
            summary=(f"{ev.total} packets between {', '.join(sorted(clients)[:3])} and {top_srv} on {port} port 53 contain "
                     + ("command-shell text, not DNS." if shell else "readable text instead of DNS messages.")),
            explanation=(
                "Port 53 is reserved for DNS, and almost every firewall lets it through, so attackers love to hide "
                "remote-control sessions and data tunnels there. Real DNS messages are compact binary data; here the "
                "traffic is plain text" + (", and it looks like someone typing commands into a remote computer." if shell else ".")),
            analogy="Like a smuggler wearing a postal uniform: the guard waves it through because of the uniform, not the contents.",
            cause=(f"A backdoor or reverse shell on {top_srv} (or a tunnelling tool) deliberately using port 53 to "
                   "get past the firewall."),
            fix=[
                f"Isolate {top_srv} and {', '.join(sorted(clients)[:2])} from the network and check them for malware.",
                "On the firewall, allow port 53 only to your real DNS servers, and block it everywhere else.",
                "Enable protocol inspection on the firewall so non-DNS traffic on port 53 is dropped.",
                "Treat any account used on these machines as compromised and change its passwords.",
            ],
            mitre="T1571 Non-Standard Port",
            severity=sev,
        )
        misconf = Variant(
            title=f"An application is using the DNS port for something else ({top_srv}:53)",
            summary=f"{ev.total} packets on port 53 are not DNS.",
            explanation=("Some VPNs and games use port 53 to get through restrictive networks. It is not DNS, "
                         "and it confuses firewalls and troubleshooting tools."),
            cause="Software configured to use port 53 for its own protocol.",
            fix=["Identify the application on the two hosts.", "Move it to its own port, or block it if it isn't approved."],
            severity=Severity.MEDIUM,
        )
        f = Finding(
            kind="dns.non_dns_traffic", category=A, severity=sev, title=attack.title, summary=attack.summary,
            explanation=attack.explanation, cause=attack.cause, fix=attack.fix,
            technical=(f"{len(self.flows)} flow(s) on port 53 with non-DNS text; {ev.total} packets; transport {port}; "
                       f"shell markers: {'yes' if shell else 'no'}; bidirectional: {'yes' if both else 'no'}; "
                       f"{top_srv} sent {real_dns} genuine DNS answers."),
            hosts=[top_srv] + sorted(clients)[:4],
            metrics={"packets": ev.total, "flows": len(self.flows), "shell": shell, "bidirectional": both,
                     "server": top_srv, "server_real_dns_answers": real_dns},
            indicators=ind, variants={A: attack, M: misconf},
        )
        return [ev.apply(f)]


@register
class FragmentAttack(Detector):
    """Overlapping IPv4 fragments (Teardrop) and tiny first fragments that split the TCP header (evasion)."""

    name = "ip_fragments"
    TINY = 16  # a first TCP fragment shorter than this cannot even hold the flag byte + window

    def __init__(self) -> None:
        self.frags: BoundedDict = BoundedDict(50_000)  # (src, dst, proto, id) -> list[(start, end)]
        self.overlap = Evidence()
        self.tiny = Evidence()
        self.sources: dict[str, int] = {}
        self.targets: dict[str, int] = {}
        self.fragmented = 0

    def on_packet(self, pkt: Packet, ctx: AnalysisContext) -> None:
        if pkt.ip_ver != 4 or not (pkt.mf or pkt.frag_off):
            return
        self.fragmented += 1
        start = int(pkt.frag_off or 0)
        end = start + max(0, int(pkt.ip_len or 0))
        key = (pkt.src, pkt.dst, pkt.proto, pkt.ip_id)
        ranges = self.frags.get(key)
        if ranges is None:
            ranges = self.frags[key] = []
        bad = False
        for s, e in ranges:
            if (s, e) == (start, end):
                break  # an exact duplicate fragment (network duplication) is harmless
            if start < e and s < end:
                bad = True
                break
        if len(ranges) < 64:
            ranges.append((start, end))
        if bad:
            self.overlap.add(pkt)
            self._who(pkt)
        if start == 0 and pkt.mf and pkt.proto == 6 and end < self.TINY:
            self.tiny.add(pkt)
            self._who(pkt)

    def _who(self, pkt: Packet) -> None:
        if len(self.sources) < 1000:
            self.sources[pkt.src] = self.sources.get(pkt.src, 0) + 1
            self.targets[pkt.dst] = self.targets.get(pkt.dst, 0) + 1

    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        if not self.overlap.total and not self.tiny.total:
            return []
        A, F = Category.ATTACK, Category.FAULT
        src = max(self.sources, key=self.sources.get)
        dst = max(self.targets, key=self.targets.get)
        ind: list[Indicator] = []
        if self.overlap.total:
            ind.append(Indicator(f"{plural(self.overlap.total, 'fragment')} overlap data from an earlier fragment of the "
                                 "same packet; normal senders never do this", A, 3.0))
        if self.tiny.total:
            ind.append(Indicator(f"{plural(self.tiny.total, 'first fragment')} are too small to hold a complete TCP header, "
                                 "a classic trick to slip past firewalls", A, 2.0))
        if self.overlap.total == 1 and not self.tiny.total:
            ind.append(Indicator("Only a single overlapping fragment: could also be a buggy network stack", F, 1.0))
        overlap_main = self.overlap.total >= self.tiny.total
        attack = Variant(
            title=(f"Overlapping IP fragments aimed at {dst} (Teardrop-style attack)" if overlap_main
                   else f"Tiny IP fragments from {src}, used to sneak past firewalls"),
            summary=(f"{src} sent {self.overlap.total} overlapping and {self.tiny.total} tiny fragment(s) to {dst}."),
            explanation=(
                "Large packets can be split into fragments that the receiver puts back together. Attackers send pieces "
                "that overlap or are deliberately tiny: overlapping pieces crash or confuse old systems (the 'Teardrop' "
                "attack), and tiny pieces hide the real packet header from firewalls that only inspect the first piece."),
            analogy="Like mailing a letter as torn strips that only make sense, or cause harm, once taped back together.",
            cause=f"A fragmentation attack or evasion tool (e.g. a Teardrop exploit or `nmap -f`) on {src}.",
            fix=[
                f"Identify and isolate {src}; check it for attack tools or malware.",
                "Make sure the target systems are patched (modern OSes reject overlapping fragments).",
                "Configure the firewall/IDS to reassemble fragments before inspecting, and to drop overlapping or tiny fragments.",
            ],
            mitre="T1499 Endpoint Denial of Service" if overlap_main else None,
            severity=Severity.HIGH if overlap_main else Severity.MEDIUM,
        )
        fault = Variant(
            title=f"Malformed IP fragments between {src} and {dst}",
            summary=f"{self.overlap.total} fragment(s) overlap.",
            explanation="A device produced inconsistent fragments. This can happen with buggy network drivers.",
            cause="A faulty network stack or driver on the sender.",
            fix=["Update the sender's network driver/firmware.", "Re-capture to see whether it keeps happening."],
            severity=Severity.LOW,
        )
        ev = Evidence()
        ev.merge(self.overlap)
        ev.merge(self.tiny)
        f = Finding(
            kind="ip.fragment_attack", category=A, severity=attack.severity or Severity.HIGH, title=attack.title,
            summary=attack.summary, explanation=attack.explanation, cause=attack.cause, fix=attack.fix,
            technical=(f"{self.fragmented} fragmented IPv4 packets; {self.overlap.total} with a partial overlap of an earlier "
                       f"fragment (same src/dst/proto/id); {self.tiny.total} first TCP fragments shorter than {self.TINY} bytes. "
                       f"Top source {src}, top target {dst}."),
            hosts=[src, dst], metrics={"overlapping": self.overlap.total, "tiny_first_fragments": self.tiny.total,
                                       "fragmented_packets": self.fragmented, "source": src, "target": dst},
            indicators=ind, variants={A: attack, F: fault},
        )
        return [ev.apply(f)]
