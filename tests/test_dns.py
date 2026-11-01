"""DNS detector tests: timeouts, errors, slow, NXDOMAIN (typo vs DGA), hijack vs CDN, tunneling, robustness."""

from __future__ import annotations

import base64
import random

from faultline.detectors.arp import scores_of
from faultline.detectors.dns import DnsDetector, randomish, registered_domain
from faultline.model import Category, Severity
from tests.factory import Seq, dns_query, dns_response, run_detector

C = "192.168.1.20"
C_MAC = "02:00:00:00:00:20"
R_MAC = "aa:bb:cc:00:00:01"
LOCAL_DNS = "192.168.1.1"
X_MAC = "de:ad:be:ef:00:66"


def winner(f):
    sc = scores_of(f.indicators)
    return max(sc, key=sc.get)


def run(pk):
    pk.sort(key=lambda p: p.ts)
    return run_detector(DnsDetector(), pk)


def lookup(s, t, qid, name, server=LOCAL_DNS, rtt=0.015, answers=(("A", "93.184.216.34", 300),), rcode=0,
           sport=None, qtype=1, client=C, resp_eth=R_MAC):
    sport = sport or (40000 + qid % 20000)
    return [dns_query(s, t, client, server, qid, name, qtype=qtype, sport=sport, eth_src=C_MAC, eth_dst=R_MAC),
            dns_response(s, t + rtt, server, client, qid, name, answers=answers, rcode=rcode, qtype=qtype,
                         dport=sport, eth_src=resp_eth, eth_dst=C_MAC)]


def browsing(s, t0=0.0, n=40, server=LOCAL_DNS, rtt=0.015):
    pk = []
    sites = ["example.com", "www.wikipedia.org", "news.bbc.co.uk", "github.com", "cdn.jsdelivr.net", "mail.google.com",
             "www.youtube.com", "api.spotify.com", "login.microsoftonline.com", "static.xx.fbcdn.net"]
    for i in range(n):
        pk += lookup(s, t0 + i * 0.5, 1000 + i, sites[i % len(sites)], server=server, rtt=rtt,
                     answers=(("A", f"151.101.{i % 200}.{(i * 7) % 250}", 60),))
    return pk


# --------------------------------------------------------------------------- #
def test_helpers():
    assert registered_domain("a.b.example.com") == "example.com"
    assert registered_domain("news.bbc.co.uk") == "bbc.co.uk"
    assert registered_domain("") == ""
    assert randomish("xkqjdhwpzvbt") and randomish("a8f3k2m9q1z7x4")
    assert not randomish("documentation") and not randomish("google") and not randomish("wikipedia")


def test_healthy_browsing_quiet():
    s = Seq()
    pk = browsing(s, n=200)
    pk += lookup(s, 50.0, 7777, "gooogle.com", rcode=3, answers=())  # one typo
    # CDN: same name looked up repeatedly, different IP each time (separate transactions)
    for i in range(10):
        pk += lookup(s, 60.0 + i, 8000 + i, "www.netflix.com", answers=(("A", f"52.{i}.1.{i + 3}", 20),))
    # mDNS chatter is ignored
    q = dns_query(s, 70.0, C, "224.0.0.251", 0, "_googlecast._tcp.local", sport=5353)
    q.udp.dport = 5353
    pk.append(q)
    # a query in the very last second without answer is not a timeout
    pk.append(dns_query(s, 120.5, C, LOCAL_DNS, 9999, "late.example.com"))
    assert [f for f in run(pk) if f.severity >= Severity.MEDIUM] == []
    assert not [f for f in run(pk) if f.kind in ("dns.hijack", "dns.timeout", "dns.nxdomain")]


def test_timeout_primary_down_backup_works():
    s = Seq()
    pk = browsing(s, n=20)  # primary answers until ~t=10
    for i in range(12):
        t = 20.0 + i * 2
        pk.append(dns_query(s, t, C, LOCAL_DNS, 2000 + i, f"site{i}.example.com", sport=41000 + i))
        pk += lookup(s, t + 1.0, 3000 + i, f"site{i}.example.com", server="1.1.1.1", rtt=0.02)
    pk += lookup(s, 60.0, 4000, "final.example.com", server="1.1.1.1")
    out = [f for f in run(pk) if f.kind == "dns.timeout"]
    assert len(out) == 1
    f = out[0]
    assert f.category == Category.FAULT and f.severity >= Severity.MEDIUM
    assert LOCAL_DNS in f.summary and "1.1.1.1" in f.summary
    assert f.metrics["servers"][LOCAL_DNS]["unanswered"] == 12
    assert any("stopped" in i.text for i in f.indicators)


def test_single_lost_query_is_quiet():
    s = Seq()
    pk = browsing(s, n=100)
    pk.append(dns_query(s, 10.2, C, LOCAL_DNS, 5555, "lost.example.com"))
    assert not [f for f in run(pk) if f.kind == "dns.timeout"]


def test_servfail_and_refused():
    s = Seq()
    pk = browsing(s, n=20)
    for i in range(10):
        pk += lookup(s, 20 + i, 6000 + i, f"www.site{i}.org", rcode=2, answers=())
    f = [x for x in run(pk) if x.kind == "dns.errors"]
    assert len(f) == 1 and f[0].category == Category.FAULT and f[0].severity >= Severity.MEDIUM
    # all failures under one domain: that domain's DNS is broken, not the network -> LOW
    s = Seq()
    pk = browsing(s, n=20)
    for i in range(10):
        pk += lookup(s, 20 + i, 6000 + i, f"x{i}.broken-dnssec.org", rcode=2, answers=())
    f = [x for x in run(pk) if x.kind == "dns.errors"]
    assert len(f) == 1 and f[0].severity == Severity.LOW
    s = Seq()
    pk = browsing(s, n=10)
    for i in range(10):
        pk += lookup(s, 20 + i, 6000 + i, f"y{i}.example.net", server="10.9.9.9", rcode=5, answers=())
    f = [x for x in run(pk) if x.kind == "dns.errors"]
    assert len(f) == 1 and winner(f[0]) == Category.MISCONFIG and f[0].category == Category.MISCONFIG


def test_slow_dns():
    s = Seq()
    pk = browsing(s, n=20, rtt=0.8)
    for i in range(4):
        pk += lookup(s, 30 + i, 7000 + i, "slow.example.com", rtt=1.5)
    out = [f for f in run(pk) if f.kind == "dns.slow"]
    assert len(out) == 1 and out[0].metrics["servers"][LOCAL_DNS]["over_1s"] == 4
    assert not [f for f in run(browsing(Seq(), n=50)) if f.kind == "dns.slow"]


# --------------------------------------------------------------------------- #
def test_nxdomain_dga_is_attack():
    s = Seq()
    rnd = random.Random(5)
    pk = browsing(s, n=20)
    for i in range(60):
        label = "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(rnd.randrange(12, 20)))
        pk += lookup(s, 30 + i * 0.3, 9000 + i, f"{label}.{rnd.choice(['com', 'net', 'info', 'biz'])}", rcode=3, answers=())
    out = [f for f in run(pk) if f.kind == "dns.nxdomain"]
    assert len(out) == 1
    f = out[0]
    assert winner(f) == Category.ATTACK and f.mitre.startswith("T1568.002")


def test_nxdomain_search_domain_is_misconfig():
    s = Seq()
    pk = browsing(s, n=20)
    names = ["www.google.com", "github.com", "outlook.office.com", "example.com"]
    for i in range(40):
        pk += lookup(s, 30 + i * 0.3, 9500 + i, f"{names[i % 4]}.corp.lan", rcode=3, answers=())
    out = [f for f in run(pk) if f.kind == "dns.nxdomain"]
    assert len(out) == 1 and winner(out[0]) == Category.MISCONFIG and out[0].category == Category.MISCONFIG


# --------------------------------------------------------------------------- #
def test_dns_race_with_different_answers_is_attack():
    s = Seq()
    pk = browsing(s, n=30, server="8.8.8.8", rtt=0.025)
    for i in range(5):
        t = 30.0 + i
        qid, port = 100 + i, 45000 + i
        pk.append(dns_query(s, t, C, "8.8.8.8", qid, "www.mybank.com", sport=port, eth_src=C_MAC, eth_dst=R_MAC))
        # forged answer from a LAN device, 0.3 ms later, pointing to itself
        pk.append(dns_response(s, t + 0.0003, "8.8.8.8", C, qid, "www.mybank.com", answers=(("A", "192.168.1.66", 60),),
                               dport=port, eth_src=X_MAC, eth_dst=C_MAC))
        # the real answer arrives later via the router
        pk.append(dns_response(s, t + 0.026, "8.8.8.8", C, qid, "www.mybank.com", answers=(("A", "203.0.113.10", 300),),
                               dport=port, eth_src=R_MAC, eth_dst=C_MAC))
    out = [f for f in run(pk) if f.kind == "dns.hijack"]
    assert len(out) == 1
    f = out[0]
    sc = scores_of(f.indicators)
    assert winner(f) == Category.ATTACK and sc[Category.ATTACK] >= 5
    assert f.category == Category.ATTACK and f.mitre.startswith("T1557")
    assert "192.168.1.66" in f.metrics["forged_ips"] and "203.0.113.10" in f.metrics["legit_ips"]
    assert f.metrics["forger_mac"] == X_MAC and f.metrics["fast_forgeries"] == 5
    assert "www.mybank.com" in f.metrics["domains"]
    assert f.severity >= Severity.HIGH and f.packets


def test_retry_with_same_txid_and_cdn_rotation_is_not_a_race():
    s = Seq()
    pk = browsing(s, n=10)
    # client re-sends the same txid/port; each copy gets its own (rotated) CDN answer
    pk.append(dns_query(s, 20.0, C, LOCAL_DNS, 77, "www.netflix.com", sport=46000))
    pk.append(dns_query(s, 21.0, C, LOCAL_DNS, 77, "www.netflix.com", sport=46000))
    pk.append(dns_response(s, 21.02, LOCAL_DNS, C, 77, "www.netflix.com", answers=(("A", "52.1.1.1", 20),), dport=46000,
                           eth_src=R_MAC))
    pk.append(dns_response(s, 21.03, LOCAL_DNS, C, 77, "www.netflix.com", answers=(("A", "52.2.2.2", 20),), dport=46000,
                           eth_src=R_MAC))
    # duplicate identical response (capture duplicate) is harmless too
    pk += lookup(s, 25.0, 78, "example.com")
    pk.append(dns_response(s, 25.016, LOCAL_DNS, C, 78, "example.com", dport=40078, eth_src=R_MAC))
    assert not [f for f in run(pk) if f.kind == "dns.hijack"]


def test_response_from_unqueried_server_and_mitm_self_pointing():
    s = Seq()
    pk = browsing(s, n=10)
    for i in range(4):
        pk.append(dns_query(s, 20 + i, C, LOCAL_DNS, 300 + i, "login.example.com", sport=47000 + i))
        pk.append(dns_response(s, 20 + i + 0.001, "192.168.1.66", C, 300 + i, "login.example.com",
                               answers=(("A", "192.168.1.66", 5),), dport=47000 + i, eth_src=X_MAC))
    out = [f for f in run(pk) if f.kind == "dns.hijack"]
    assert len(out) == 1 and out[0].category == Category.ATTACK
    assert any("never asked" in i.text for i in out[0].indicators)


def test_captive_portal_is_misconfig_low():
    s = Seq()
    pk = []
    sites = ["example.com", "wikipedia.org", "bbc.co.uk", "github.com", "google.com", "apple.com", "netflix.com"]
    for i, name in enumerate(sites * 2):
        pk += lookup(s, i * 0.5, 500 + i, name, server="10.0.0.1", answers=(("A", "10.0.0.1", 0),))
    out = [f for f in run(pk) if f.kind == "dns.hijack"]
    assert len(out) == 1
    f = out[0]
    assert winner(f) == Category.MISCONFIG and f.severity == Severity.LOW and f.metrics["portal_ip"] == "10.0.0.1"


def test_split_horizon_internal_names_quiet():
    s = Seq()
    pk = browsing(s, n=10)
    for i, name in enumerate(["nas.local", "printer.lan", "intranet.corp", "git.mycompany.com", "wiki.mycompany.com"]):
        pk += lookup(s, 20 + i, 600 + i, name, answers=(("A", f"10.1.0.{i + 5}", 300),))
    assert not [f for f in run(pk) if f.kind == "dns.hijack"]


# --------------------------------------------------------------------------- #
def test_tunneling_detected():
    s = Seq()
    rnd = random.Random(9)
    pk = browsing(s, n=10)
    for i in range(150):
        chunk = base64.b32encode(rnd.randbytes(24)).decode().rstrip("=").lower()
        name = f"{chunk[:30]}.{chunk[30:]}.t.evil-tunnel.com"
        pk += lookup(s, 10 + i * 0.5, 10000 + i, name, qtype=16, answers=(("TXT", "ok", 0),))
    out = [f for f in run(pk) if f.kind == "dns.tunneling"]
    assert len(out) == 1
    f = out[0]
    assert f.category == Category.ATTACK and f.mitre.startswith("T1071.004")
    assert f.metrics["domain"] == "evil-tunnel.com" and f.metrics["unique_subdomains"] == 150
    assert any("steady rhythm" in i.text for i in f.indicators)


def test_many_cdn_hostnames_not_tunneling():
    s = Seq()
    pk = []
    for i in range(120):
        pk += lookup(s, i * 0.2, 20000 + i, f"e{1000 + i}.dscx.akamaiedge.net")
        pk += lookup(s, i * 0.2 + 0.1, 30000 + i, f"r{i % 9}---sn-ab5l6nzr.googlevideo.com")
    assert not [f for f in run(pk) if f.kind == "dns.tunneling"]


# --------------------------------------------------------------------------- #
def test_robust_odd_packets_and_bounded_state():
    s = Seq()
    pk = []
    q = dns_query(s, 0.0, C, LOCAL_DNS, 1, "")
    q.dns.qname = None
    pk.append(q)
    r = dns_response(s, 0.01, LOCAL_DNS, C, 1, "", answers=())
    r.dns.qname = None
    pk.append(r)
    r2 = dns_response(s, 0.02, LOCAL_DNS, C, 2, "x" * 300 + "<b>", answers=(("A", None, None), ("CNAME", "a.b", 5)))
    pk.append(r2)
    odd = dns_query(s, 0.03, None, None, 3, "a.com")
    pk.append(odd)
    rnd = random.Random(2)
    for i in range(30_000):
        pk.append(dns_query(s, 1 + i * 0.001, f"10.0.{rnd.randrange(256)}.{rnd.randrange(256)}", LOCAL_DNS,
                            rnd.getrandbits(16), f"h{i}.example.com", sport=rnd.randrange(1024, 65535)))
    det = DnsDetector()
    det.MAX_PENDING = 5000
    out = run_detector(det, pk)
    assert len(det.pending) == 0 and len(det.loose) <= 5000
    t = [f for f in out if f.kind == "dns.timeout"]
    assert t and t[0].category == Category.FAULT


def test_unqueried_server_pointing_to_itself_is_linked():
    s = Seq()
    pk = browsing(s, n=5)
    pk.append(dns_query(s, 20, C, LOCAL_DNS, 900, "www.paypal.com", sport=48000))
    pk.append(dns_response(s, 20.0005, "192.168.1.66", C, 900, "www.paypal.com", answers=(("A", "192.168.1.66", 5),),
                           dport=48000, eth_src=X_MAC))
    out = [f for f in run(pk) if f.kind == "dns.hijack"]
    assert len(out) == 1 and out[0].category == Category.ATTACK
    assert any("very device" in i.text for i in out[0].indicators)
