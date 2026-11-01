from faultline.correlate import assign_ids, correlate, health_score, overall_verdict
from faultline.model import Category, Finding, Indicator, Severity, Variant
from faultline.verdict import assess


def mk(kind="arp.duplicate_ip", cat=Category.MISCONFIG, sev=Severity.MEDIUM, indicators=(), variants=None, hosts=(), ts=0.0):
    return Finding(kind=kind, category=cat, severity=sev, title=f"{kind} default", summary="s", explanation="e",
                   cause="c", fix=["step"], indicators=list(indicators), variants=variants or {}, hosts=list(hosts),
                   first_ts=ts, last_ts=ts + 1)


VARIANTS = {
    Category.MISCONFIG: Variant("Two devices share one IP", "s", "e", "c", ["unplug one"]),
    Category.ATTACK: Variant("ARP spoofing of the router", "s", "e", "c", ["find the attacker"], mitre="T1557.002",
                             severity=Severity.HIGH),
}


def test_attack_variant_wins_with_strong_attack_evidence():
    f = mk(indicators=[
        Indicator("claims the gateway IP", Category.ATTACK, 3),
        Indicator("unsolicited replies every second", Category.ATTACK, 2),
        Indicator("both MACs send normal traffic", Category.MISCONFIG, 1),
    ], variants=VARIANTS)
    assess(f)
    assert f.category == Category.ATTACK
    assert f.title == "ARP spoofing of the router"
    assert f.mitre == "T1557.002"
    assert f.severity == Severity.HIGH
    assert 0.9 <= f.confidence <= 0.99
    assert f.alternatives and f.alternatives[0]["category"] == "misconfig"
    assert "claims the gateway IP" in f.alternatives[0]["why_not"]


def test_misconfig_wins_when_attack_evidence_is_weak():
    f = mk(indicators=[
        Indicator("both MACs stable for minutes", Category.MISCONFIG, 2),
        Indicator("ARP probe at boot", Category.MISCONFIG, 1.5),
        Indicator("one extra ARP reply", Category.ATTACK, 0.5),
    ], variants=VARIANTS)
    assess(f)
    assert f.category == Category.MISCONFIG
    assert f.mitre is None
    assert f.title == "Two devices share one IP"


def test_tie_goes_to_detector_default_and_weights_are_clamped():
    f = mk(cat=Category.FAULT, indicators=[Indicator("x", Category.ATTACK, 99)],
           variants={Category.ATTACK: Variant("a", "s", "e", "c", ["f"])})
    assess(f)
    # weight 99 clamps to 3 > prior 0.5
    assert f.category == Category.ATTACK
    g = mk(cat=Category.FAULT, indicators=[], variants={Category.ATTACK: Variant("a", "s", "e", "c", ["f"])})
    assess(g)
    assert g.category == Category.FAULT


def test_single_hypothesis_confidence_grows_with_evidence():
    weak = assess(mk(cat=Category.FAULT, indicators=[Indicator("a", Category.FAULT, 0.5)]))
    strong = assess(mk(cat=Category.FAULT, indicators=[Indicator("a", Category.FAULT, 3), Indicator("b", Category.FAULT, 3)]))
    assert weak.confidence < strong.confidence


def test_correlation_links_rogue_dhcp_and_dns_hijack():
    rogue = assess(mk("dhcp.multiple_servers", Category.ATTACK, Severity.HIGH,
                      [Indicator("offers itself as router", Category.ATTACK, 3)], hosts=["192.168.1.66"]))
    hijack = assess(mk("dns.hijack", Category.ATTACK, Severity.HIGH,
                       [Indicator("forged answer", Category.ATTACK, 3)], hosts=["192.168.1.66", "192.168.1.15"]))
    unrelated = assess(mk("tcp.retransmissions", Category.FAULT, Severity.MEDIUM, hosts=["203.0.113.10"]))
    fs = assign_ids([rogue, hijack, unrelated])
    incidents = correlate(fs)
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.title == "Man-in-the-middle attack"
    assert hijack.symptom_of == rogue.id
    assert unrelated.symptom_of is None
    v = overall_verdict(fs, 1000, 60)
    assert v["status"] == "under_attack"
    assert "1 genuine fault" in v["summary"]


def test_scan_noise_requires_shared_host():
    scan = assess(mk("scan.port", Category.ATTACK, Severity.HIGH, [Indicator("1000 ports", Category.ATTACK, 3)],
                     hosts=["192.168.1.66", "192.168.1.20"]))
    refused_same = assess(mk("tcp.refused", Category.MISCONFIG, Severity.MEDIUM, hosts=["192.168.1.20"]))
    refused_other = assess(mk("tcp.refused", Category.MISCONFIG, Severity.MEDIUM, hosts=["10.9.9.9"]))
    fs = assign_ids([scan, refused_same, refused_other])
    correlate(fs)
    assert refused_same.symptom_of == scan.id
    assert refused_other.symptom_of is None


def test_health_and_verdict_states():
    assert health_score([]) == 100
    assert overall_verdict([], 10, 1.0)["status"] == "healthy"
    fault = assess(mk("dns.timeout", Category.FAULT, Severity.HIGH))
    v = overall_verdict(assign_ids([fault]), 10, 1.0)
    assert v["status"] == "faulty" and "no sign of an attack" in v["summary"]
    low = assess(mk("tls.deprecated", Category.MISCONFIG, Severity.LOW))
    assert overall_verdict(assign_ids([low]), 10, 1.0)["status"] == "minor_issues"


def test_tiny_clean_capture_says_it_is_too_short_to_judge():
    v = overall_verdict([], 1, 0.0)
    assert v["status"] == "healthy" and "too little traffic" in v["headline"]
    assert "only 1 packet," in v["summary"]
    big = overall_verdict([], 500, 60.0)
    assert big["headline"] == "No faults or attacks found." and "500 packets" in big["summary"]
