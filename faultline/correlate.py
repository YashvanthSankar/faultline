"""Correlation: root cause vs. symptoms, incidents, health score and verdict.

A beginner faced with ten red alerts doesn't know where to start. Many of
those alerts are *consequences* of one problem: a rogue DHCP server causes
DNS hijacking; a dead DHCP server causes DNS timeouts and failed connections;
a port scan causes a wave of resets and ICMP errors. This module links such
findings into incidents and tells the user what to fix first.
"""

from __future__ import annotations

from dataclasses import dataclass

from .model import Category, Finding, Incident, Severity

SEVERITY_PENALTY = {Severity.INFO: 0, Severity.LOW: 3, Severity.MEDIUM: 9, Severity.HIGH: 18, Severity.CRITICAL: 30}
CATEGORY_RANK = {Category.ATTACK: 0, Category.FAULT: 1, Category.MISCONFIG: 2, Category.INFO: 3}


@dataclass(frozen=True)
class ChainRule:
    """``root`` findings explain ``consequences``.

    ``root_category``: only applies when the root was judged this category (None = any).
    ``need_overlap``: consequences must share at least one host with the root.
    """

    name: str
    root_kinds: tuple[str, ...]
    consequence_kinds: tuple[str, ...]
    title: str
    story: str
    root_category: Category | None = None
    need_overlap: bool = True


RULES: tuple[ChainRule, ...] = (
    ChainRule(
        "mitm",
        ("dhcp.multiple_servers", "arp.duplicate_ip", "icmp.redirect"),
        ("dns.hijack", "cred.cleartext", "tls.failure", "dns.timeout", "tcp.resets", "arp.duplicate_ip"),
        "Man-in-the-middle attack",
        "A device on your network put itself between your users and the internet ({root}). "
        "Because their traffic now flows through it, it can read or change what they see ({effects}).",
        root_category=Category.ATTACK,
        need_overlap=False,
    ),
    ChainRule(
        "dns-spoofing",
        ("dns.hijack",),
        ("arp.duplicate_ip", "tls.failure", "cred.cleartext"),
        "DNS spoofing attack",
        "A device on your network is forging DNS answers ({root}); the other oddities come from the same device "
        "impersonating the router or intercepting the redirected connections ({effects}).",
        root_category=Category.ATTACK,
    ),
    ChainRule(
        "rogue-router",
        ("dhcp.multiple_servers",),
        ("dns.timeout", "dns.errors", "tcp.syn_timeout", "arp.unanswered", "icmp.unreachable", "dhcp.nak"),
        "A second router is breaking connectivity",
        "A second DHCP server handed out wrong network settings ({root}), so the devices that took them "
        "could not reach anything ({effects}).",
        root_category=Category.MISCONFIG,
        need_overlap=False,
    ),
    ChainRule(
        "no-dhcp",
        ("dhcp.no_server",),
        ("dns.timeout", "tcp.syn_timeout", "arp.unanswered", "icmp.unreachable"),
        "Devices can't get a network address",
        "No DHCP server answered ({root}), so devices never received an address, router or DNS server, "
        "and everything after that failed ({effects}).",
        need_overlap=False,
    ),
    ChainRule(
        "gateway-down",
        ("arp.unanswered",),
        ("dns.timeout", "tcp.syn_timeout", "icmp.unreachable", "latency.high_rtt"),
        "The router stopped responding",
        "Devices could not reach the router at all ({root}), so nothing beyond it worked ({effects}).",
    ),
    ChainRule(
        "scan-noise",
        ("scan.port", "scan.host_sweep", "arp.scan"),
        ("tcp.refused", "tcp.resets", "icmp.unreachable", "arp.unanswered", "tcp.syn_timeout"),
        "Reconnaissance scan",
        "One device is mapping your network ({root}). The errors it triggers are side effects of the scan, "
        "not separate problems ({effects}).",
        root_category=Category.ATTACK,
    ),
    ChainRule(
        "flood",
        ("flood.syn", "flood.icmp"),
        ("tcp.syn_timeout", "latency.slow_server", "latency.high_rtt", "tcp.retransmissions", "tcp.resets", "http.errors"),
        "Denial-of-service attack",
        "A server is being flooded ({root}), which explains why legitimate users see slow or failing connections ({effects}).",
    ),
    ChainRule(
        "mtu",
        ("mtu.blackhole", "mtu.frag_needed"),
        ("tcp.retransmissions", "tcp.resets", "tls.failure", "latency.slow_server"),
        "Packet-size (MTU) problem",
        "Large packets can't pass a link on the path ({root}); the repeated resends and stalls are a direct result ({effects}).",
    ),
    ChainRule(
        "routing-loop",
        ("icmp.routing_loop",),
        ("icmp.unreachable", "tcp.syn_timeout", "dns.timeout", "latency.high_rtt"),
        "Routing loop",
        "Packets are circling between routers instead of reaching their destination ({root}), so connections to it fail ({effects}).",
    ),
    ChainRule(
        "dns-down",
        ("dns.timeout",),
        ("dns.slow", "dns.errors"),
        "DNS outage",
        "The DNS server is failing ({root}); slow or failed lookups are part of the same outage ({effects}).",
        need_overlap=False,
    ),
    ChainRule(
        "broadcast-storm",
        ("flood.broadcast",),
        ("tcp.retransmissions", "dns.timeout", "latency.high_rtt", "arp.unanswered", "dhcp.no_server"),
        "Network loop / broadcast storm",
        "The network is flooded with broadcast traffic ({root}), which crowds out normal traffic ({effects}).",
        need_overlap=False,
    ),
)


def rank_key(f: Finding):
    return (-int(f.severity), CATEGORY_RANK.get(f.category, 9), -f.confidence, f.first_ts or 0.0)


def assign_ids(findings: list[Finding]) -> list[Finding]:
    findings.sort(key=rank_key)
    for i, f in enumerate(findings, 1):
        f.id = f"F{i}"
    return findings


def _overlap(a: Finding, b: Finding) -> bool:
    return bool(set(a.hosts) & set(b.hosts))


def correlate(findings: list[Finding]) -> list[Incident]:
    """Link findings into incidents (mutates ``symptom_of`` / ``incident``)."""
    incidents: list[Incident] = []
    used_roots: set[str] = set()
    for rule in RULES:
        roots = [
            f for f in findings
            if f.kind in rule.root_kinds and f.id not in used_roots and f.symptom_of is None
            and (rule.root_category is None or f.category == rule.root_category)
            and f.severity >= Severity.LOW
        ]
        for root in roots:
            effects = [
                f for f in findings
                if f is not root and f.kind in rule.consequence_kinds and f.symptom_of is None and f.incident is None
                and f.id not in used_roots
                and (not rule.need_overlap or _overlap(root, f))
                and not (rule.name == "mitm" and f.kind == root.kind)
            ]
            # a consequence of an attack chain must itself not be a stronger root
            if rule.name == "rogue-router":
                effects = [e for e in effects if e.category != Category.ATTACK]
            if not effects:
                continue
            inc_id = f"I{len(incidents) + 1}"
            root.incident = inc_id
            used_roots.add(root.id)
            for e in effects:
                e.symptom_of = root.id
                e.incident = inc_id
            members = [root] + effects
            cat = Category.ATTACK if any(m.category == Category.ATTACK for m in members) else root.category
            sev = max(m.severity for m in members)
            first = min((m.first_ts for m in members if m.first_ts is not None), default=None)
            last = max((m.last_ts for m in members if m.last_ts is not None), default=None)
            hosts: list[str] = []
            for m in members:
                for h in m.hosts:
                    if h not in hosts and len(hosts) < 12:
                        hosts.append(h)
            story = rule.story.format(
                root=root.title.rstrip("."),
                effects="; ".join(e.title.rstrip(".") for e in effects[:4]),
            )
            incidents.append(Incident(
                id=inc_id,
                title=rule.title,
                category=cat,
                severity=sev,
                story=story,
                root_cause=root.id,
                findings=[m.id for m in members],
                hosts=hosts,
                first_ts=first,
                last_ts=last,
                first_fix=list(root.fix[:3]),
            ))
    incidents.sort(key=lambda i: (-int(i.severity), CATEGORY_RANK.get(i.category, 9)))
    return incidents


def health_score(findings: list[Finding]) -> int:
    penalty = 0.0
    for f in findings:
        w = SEVERITY_PENALTY.get(f.severity, 0) * max(0.5, f.confidence)
        penalty += w * (0.4 if f.symptom_of else 1.0)
    return int(max(0, min(100, round(100 - penalty))))


def overall_verdict(findings: list[Finding], packets: int, duration: float) -> dict:
    counts = {c.value: 0 for c in (Category.ATTACK, Category.FAULT, Category.MISCONFIG, Category.INFO)}
    for f in findings:
        if f.severity >= Severity.LOW:
            counts[f.category.value] += 1
        else:
            counts[Category.INFO.value] += 1
    attacks = [f for f in findings if f.category == Category.ATTACK and f.severity >= Severity.MEDIUM and f.confidence >= 0.6]
    problems = [f for f in findings if f.category in (Category.FAULT, Category.MISCONFIG) and f.severity >= Severity.MEDIUM]
    minor = [f for f in findings if f.severity >= Severity.LOW]
    score = health_score(findings)
    span = _human_duration(duration)

    if attacks:
        top = attacks[0]
        status = "under_attack"
        headline = f"{top.title.rstrip('.')}."
        extra = len(problems)
        summary = (
            f"We found {len(attacks)} sign{'s' if len(attacks) != 1 else ''} of malicious activity. "
            "This is not an ordinary outage: restarting the router will not fix it."
        )
        if extra:
            summary += (f" Separately, {extra} genuine fault{'s' if extra != 1 else ''} or misconfiguration{'s' if extra != 1 else ''} "
                        f"also need{'s' if extra == 1 else ''} attention.")
    elif problems:
        top = problems[0]
        status = "faulty"
        headline = f"{top.title.rstrip('.')}."
        summary = (
            f"We found {len(problems)} problem{'s' if len(problems) != 1 else ''} affecting your network, "
            "and no sign of an attack. This looks like an ordinary fault or misconfiguration."
        )
    elif minor:
        status = "minor_issues"
        headline = "Mostly healthy, with a few minor issues."
        summary = f"Nothing serious in {packets:,} packets over {span}; see the minor notes below."
    else:
        status = "healthy"
        headline = "No faults or attacks found."
        summary = f"We checked {packets:,} packets over {span} and found nothing wrong."
    return {"status": status, "headline": headline, "summary": summary, "score": score, "counts": counts}


def _human_duration(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 120:
        return f"{seconds:.1f} seconds"
    if seconds < 7200:
        return f"{seconds / 60:.1f} minutes"
    return f"{seconds / 3600:.1f} hours"
