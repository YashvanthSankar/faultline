"""ARP detector tests: IP conflict vs. spoofing, scans, unanswered ARP, storms, robustness."""

from __future__ import annotations

import random

from faultline.detectors.arp import ArpDetector, scores_of
from faultline.model import Category, Severity
from tests.factory import Seq, arp, dhcp, tcp

R_MAC = "aa:bb:cc:00:00:01"   # router
V_MAC = "aa:bb:cc:00:00:15"   # victim
X_MAC = "de:ad:be:ef:00:66"   # attacker
GW, VIC, ATK = "192.168.1.1", "192.168.1.15", "192.168.1.66"


def kinds(findings):
    return [f.kind for f in findings]


def winner(f):
    sc = scores_of(f.indicators)
    return max(sc, key=sc.get)


def internet(s, t, host, host_mac, n=3):
    """Normal internet traffic through the router (public IPs carry the router MAC)."""
    pk = []
    for i in range(n):
        pk.append(tcp(s, t + i * 0.01, host, 50000 + i, f"93.184.216.{30 + i}", 443, "A", eth_src=host_mac, eth_dst=R_MAC))
        pk.append(tcp(s, t + i * 0.01 + 0.02, f"93.184.216.{30 + i}", 443, host, 50000 + i, "A", eth_src=R_MAC, eth_dst=host_mac))
    return pk


def healthy_lan(s, until=60.0):
    """Router and two hosts doing normal ARP refresh plus traffic."""
    pk = [dhcp(s, 0.0, 5, 0x1, V_MAC, src=GW, dst=VIC, server_id=GW, yiaddr=VIC, routers=[GW], dns_servers=[GW],
               eth_src=R_MAC)]
    t = 0.5
    while t < until:
        pk.append(arp(s, t, 1, V_MAC, VIC, tpa=GW))
        pk.append(arp(s, t + 0.001, 2, R_MAC, GW, tha=V_MAC, tpa=VIC))
        pk += internet(s, t + 0.1, VIC, V_MAC)
        t += 20.0
    return pk


# --------------------------------------------------------------------------- #
# duplicate IP: misconfig vs attack
# --------------------------------------------------------------------------- #


def test_ip_conflict_is_misconfig():
    s = Seq()
    A_MAC, B_MAC = "10:20:30:00:00:0a", "50:60:70:00:00:0b"
    ip = "192.168.1.50"
    pk = healthy_lan(s)
    # A uses .50 normally
    pk.append(arp(s, 1.0, 1, A_MAC, ip, tpa=GW))
    pk += internet(s, 1.1, ip, A_MAC)
    # B boots with a static .50: probes, then announces once, then both answer requests
    pk.append(arp(s, 10.0, 1, B_MAC, "0.0.0.0", tpa=ip))
    pk.append(arp(s, 10.5, 1, B_MAC, ip, tpa=ip))  # gratuitous announcement
    for k in range(4):
        t = 15.0 + k * 10
        pk.append(arp(s, t, 1, V_MAC, VIC, tpa=ip))
        pk.append(arp(s, t + 0.001, 2, A_MAC, ip, tha=V_MAC, tpa=VIC))
        pk.append(arp(s, t + 0.002, 2, B_MAC, ip, tha=V_MAC, tpa=VIC))
        pk += internet(s, t + 0.1, ip, A_MAC, n=2)
        pk += internet(s, t + 0.2, ip, B_MAC, n=2)
    f = [x for x in ArpDetector_run(pk) if x.kind == "arp.duplicate_ip"]
    assert len(f) == 1, kinds(f)
    f = f[0]
    assert winner(f) == Category.MISCONFIG
    assert f.category == Category.MISCONFIG
    assert f.severity == Severity.MEDIUM
    assert set(f.variants) == {Category.ATTACK, Category.MISCONFIG}
    assert f.metrics["suspect_mac"] == B_MAC and f.metrics["legit_macs"][ip] == A_MAC
    assert f.packets and f.mitre is None
    assert "same IP" in f.title


def ArpDetector_run(pk):
    from tests.factory import run_detector
    return run_detector(ArpDetector(), pk)


def gateway_spoof_capture():
    s = Seq()
    pk = healthy_lan(s, until=30)
    # attacker has its own address
    pk.append(arp(s, 2.0, 1, X_MAC, ATK, tpa=GW))
    pk.append(arp(s, 2.001, 2, R_MAC, GW, tha=X_MAC, tpa=ATK))
    t = 5.0
    while t < 45.0:
        # bidirectional poisoning, unsolicited, every 2 s
        pk.append(arp(s, t, 2, X_MAC, GW, tha=V_MAC, tpa=VIC))
        pk.append(arp(s, t + 0.001, 2, X_MAC, VIC, tha=R_MAC, tpa=GW))
        # victim's internet traffic now goes to the attacker MAC; attacker relays
        pk.append(tcp(s, t + 0.5, VIC, 51000, "93.184.216.34", 443, "PA", plen=100, eth_src=V_MAC, eth_dst=X_MAC))
        pk.append(tcp(s, t + 0.501, VIC, 51000, "93.184.216.34", 443, "PA", plen=100, eth_src=X_MAC, eth_dst=R_MAC))
        pk.append(tcp(s, t + 0.52, "93.184.216.34", 443, VIC, 51000, "A", eth_src=R_MAC, eth_dst=X_MAC))
        pk.append(tcp(s, t + 0.521, "93.184.216.34", 443, VIC, 51000, "A", eth_src=X_MAC, eth_dst=V_MAC))
        t += 2.0
    # real router still alive and answering
    pk.append(arp(s, 40.0, 1, V_MAC, VIC, tpa=GW))
    pk.append(arp(s, 40.001, 2, R_MAC, GW, tha=V_MAC, tpa=VIC))
    pk.sort(key=lambda p: p.ts)
    return pk


def test_gateway_arp_spoofing_is_attack():
    pk = gateway_spoof_capture()
    f = [x for x in ArpDetector_run(pk) if x.kind == "arp.duplicate_ip"]
    assert len(f) == 1, kinds(f)  # both spoofed IPs grouped under one suspect MAC
    f = f[0]
    sc = scores_of(f.indicators)
    assert winner(f) == Category.ATTACK and sc[Category.ATTACK] > sc.get(Category.MISCONFIG, 0) + 3
    assert f.category == Category.ATTACK
    assert f.mitre.startswith("T1557.002")
    assert f.severity >= Severity.HIGH
    assert f.metrics["suspect_mac"] == X_MAC
    assert f.metrics["legit_macs"][GW] == R_MAC
    assert f.metrics["unsolicited_replies"] >= 30
    assert GW in f.title and GW in f.hosts
    texts = " ".join(i.text for i in f.indicators)
    assert "router" in texts and "2 different IPs" in texts and "clockwork" in texts
    # evidence references the poisoning replies
    poison = {p.no for p in pk if p.arp and p.arp.sha == X_MAC and p.arp.op == 2}
    assert poison & set(f.packets)


def test_healthy_lan_no_findings():
    s = Seq()
    pk = healthy_lan(s, until=120)
    # a new device boots: probe + one gratuitous ARP; an existing device re-announces after reconnect
    pk.append(arp(s, 30.0, 1, "10:20:30:40:50:60", "0.0.0.0", tpa="192.168.1.77"))
    pk.append(arp(s, 30.5, 1, "10:20:30:40:50:60", "192.168.1.77", tpa="192.168.1.77"))
    pk.append(arp(s, 31.0, 2, R_MAC, GW, tha=R_MAC, tpa=GW))
    pk.sort(key=lambda p: p.ts)
    assert [f for f in ArpDetector_run(pk) if f.severity >= Severity.MEDIUM] == []


def test_mac_handover_is_not_a_conflict():
    """NIC replaced / MAC randomisation: the old MAC is gone before the new one appears."""
    s = Seq()
    ip = "192.168.1.40"
    pk = [arp(s, t, 1, "10:00:00:00:00:01", ip, tpa=GW) for t in (0, 10, 20)]
    pk += [arp(s, t, 1, "20:00:00:00:00:02", ip, tpa=GW) for t in (100, 110, 120)]
    assert not [f for f in ArpDetector_run(pk) if f.kind == "arp.duplicate_ip"]


def test_vrrp_virtual_mac_is_lenient():
    s = Seq()
    vmac = "00:00:5e:00:01:01"
    pk = []
    for t in range(0, 60, 5):  # master and backup both use the same virtual MAC for the VIP
        pk.append(arp(s, t, 2, vmac, GW, tha=BCAST(), tpa=GW))
        pk.append(arp(s, t + 0.1, 1, "aa:aa:aa:00:00:02", "192.168.1.2", tpa=VIC))
        pk.append(arp(s, t + 0.2, 1, "aa:aa:aa:00:00:03", "192.168.1.3", tpa=VIC))
    # during a failover the backup's real MAC briefly answers for the VIP
    pk.append(arp(s, 30.0, 2, "aa:aa:aa:00:00:03", GW, tha=V_MAC, tpa=VIC))
    pk.append(arp(s, 31.0, 2, "aa:aa:aa:00:00:03", GW, tha=V_MAC, tpa=VIC))
    pk.sort(key=lambda p: p.ts)
    out = [f for f in ArpDetector_run(pk) if f.kind == "arp.duplicate_ip"]
    for f in out:
        assert f.severity <= Severity.MEDIUM


def BCAST():
    return "ff:ff:ff:ff:ff:ff"


def test_two_nic_host_arp_flux_is_low():
    s = Seq()
    m1, m2 = "3c:22:fb:00:00:10", "3c:22:fb:00:00:11"  # consecutive MACs, same vendor
    ip = "192.168.1.20"
    pk = []
    for k in range(5):
        t = k * 10.0
        pk.append(arp(s, t, 1, V_MAC, VIC, tpa=ip))
        pk.append(arp(s, t + 0.001, 2, m1, ip, tha=V_MAC, tpa=VIC))
        pk.append(arp(s, t + 0.002, 2, m2, ip, tha=V_MAC, tpa=VIC))
    out = [f for f in ArpDetector_run(pk) if f.kind == "arp.duplicate_ip"]
    assert len(out) == 1
    assert out[0].category == Category.MISCONFIG and out[0].severity == Severity.LOW


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #


def test_arp_scan_detected():
    s = Seq()
    pk = healthy_lan(s, until=30)
    for i in range(2, 120):
        pk.append(arp(s, 5.0 + i * 0.05, 1, X_MAC, ATK, tpa=f"192.168.1.{i}"))
    pk.sort(key=lambda p: p.ts)
    out = ArpDetector_run(pk)
    sc = [f for f in out if f.kind == "arp.scan"]
    assert len(sc) == 1
    f = sc[0]
    assert f.category == Category.ATTACK and f.mitre
    assert f.metrics["distinct_targets"] >= 100 and f.metrics["sequential_fraction"] > 0.9
    assert f.severity >= Severity.MEDIUM
    # targets of the scan must not be reported as "offline"
    assert not [x for x in out if x.kind == "arp.unanswered"]


def test_router_refresh_is_not_a_scan():
    s = Seq()
    pk = []
    hosts = [f"192.168.1.{i}" for i in random.Random(3).sample(range(2, 250), 40)]
    for k, h in enumerate(hosts):
        t = k * 1.2
        pk.append(arp(s, t, 1, R_MAC, GW, tpa=h))
        pk.append(arp(s, t + 0.002, 2, "02:00:00:00:%02x:%02x" % (k, 7), h, tha=R_MAC, tpa=GW))
        pk += internet(s, t + 0.01, h, "02:00:00:00:%02x:%02x" % (k, 7), n=1)
    assert not [f for f in ArpDetector_run(pk) if f.kind == "arp.scan"]


# --------------------------------------------------------------------------- #
# unanswered
# --------------------------------------------------------------------------- #


def test_unanswered_gateway_is_high():
    s = Seq()
    pk = [dhcp(s, 0.0, 5, 0x1, V_MAC, src=GW, dst=VIC, server_id=GW, yiaddr=VIC, routers=[GW], eth_src=R_MAC),
          arp(s, 0.5, 1, V_MAC, VIC, tpa=GW), arp(s, 0.501, 2, R_MAC, GW, tha=V_MAC, tpa=VIC)]
    for k in range(8):
        pk.append(arp(s, 10.0 + k * 1.0, 1, V_MAC, VIC, tpa=GW))
        pk.append(arp(s, 10.3 + k * 1.0, 1, "aa:bb:cc:00:00:22", "192.168.1.22", tpa=GW))
    out = [f for f in ArpDetector_run(pk) if f.kind == "arp.unanswered"]
    assert len(out) == 1
    f = out[0]
    assert f.severity == Severity.HIGH and f.category == Category.FAULT
    assert "router" in f.title and f.metrics["target"] == GW
    assert any("went silent" in i.text for i in f.indicators)


def test_unanswered_device_low_and_answered_is_quiet():
    s = Seq()
    pk = [arp(s, t, 1, V_MAC, VIC, tpa="192.168.1.99") for t in (0.0, 1.0, 2.5)]
    out = [f for f in ArpDetector_run(pk) if f.kind == "arp.unanswered"]
    assert len(out) == 1 and out[0].severity == Severity.LOW
    s = Seq()
    pk = [arp(s, 0.0, 1, V_MAC, VIC, tpa="192.168.1.99"), arp(s, 1.0, 1, V_MAC, VIC, tpa="192.168.1.99"),
          arp(s, 1.01, 2, "aa:00:00:00:00:99", "192.168.1.99", tha=V_MAC, tpa=VIC),
          arp(s, 2.0, 1, V_MAC, VIC, tpa="192.168.1.99"), arp(s, 2.01, 2, "aa:00:00:00:00:99", "192.168.1.99",
                                                              tha=V_MAC, tpa=VIC)]
    assert not ArpDetector_run(pk)


# --------------------------------------------------------------------------- #
# storm + robustness
# --------------------------------------------------------------------------- #


def test_arp_storm_switching_loop():
    s = Seq()
    pk = []
    senders = [("aa:00:00:00:00:%02x" % i, f"10.0.0.{i}") for i in range(1, 9)]
    for sec in range(6):
        for k in range(400):
            mac, ip = senders[k % len(senders)]
            pk.append(arp(s, sec + k / 400, 1, mac, ip, tpa="10.0.0.254"))
    out = [f for f in ArpDetector_run(pk) if f.kind == "arp.storm"]
    assert len(out) == 1 and out[0].category == Category.FAULT


def test_robust_to_none_fields_and_random_mac_flood():
    s = Seq()
    rnd = random.Random(7)
    pk = []
    for i in range(30_000):
        mac = "%02x:%02x:%02x:%02x:%02x:%02x" % tuple(rnd.randrange(256) & (0xFE if j == 0 else 0xFF) for j in range(6))
        ip = f"10.{rnd.randrange(256)}.{rnd.randrange(256)}.{rnd.randrange(1, 255)}"
        pk.append(arp(s, i * 0.0005, rnd.choice((1, 2)), mac, ip, tpa=f"10.0.{rnd.randrange(256)}.{rnd.randrange(256)}"))
    odd = arp(s, 20.0, 2, "aa:bb:cc:dd:ee:ff", "1.2.3.4")
    odd.arp.sha = None
    odd.arp.spa = None
    odd.arp.tpa = None
    pk.append(odd)
    odd2 = arp(s, 20.1, 7, "", "")
    pk.append(odd2)
    det = ArpDetector()
    from tests.factory import run_detector
    out = run_detector(det, pk)
    assert len(det.ips) <= det.ips.maxlen and len(det.targets) <= det.targets.maxlen
    assert all(f.severity < Severity.CRITICAL for f in out)


def test_dhcp_server_conflict_detection_is_not_a_scan():
    """A DHCP server ARP-probes each address before offering it (sequential, unanswered)."""
    s = Seq()
    pk = []
    for k in range(40):
        ip = f"192.168.1.{100 + k}"
        t = k * 1.0
        pk.append(arp(s, t, 1, R_MAC, GW, tpa=ip))
        pk.append(dhcp(s, t + 0.5, 2, 0x100 + k, "02:00:00:00:0b:%02x" % k, src=GW, server_id=GW, yiaddr=ip,
                       routers=[GW], eth_src=R_MAC))
    out = ArpDetector_run(pk)
    assert not [f for f in out if f.kind in ("arp.scan", "arp.unanswered")]
