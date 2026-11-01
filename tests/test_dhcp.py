"""DHCP detector tests: rogue vs. second router, no server, NAK, starvation, robustness."""

from __future__ import annotations

import random

from faultline.detectors.arp import scores_of
from faultline.detectors.dhcp import DhcpDetector
from faultline.model import Category, Severity
from tests.factory import Seq, arp, dhcp, run_detector, tcp

R_MAC = "aa:bb:cc:00:00:01"
X_MAC = "de:ad:be:ef:00:66"
GW = "192.168.1.1"


def winner(f):
    sc = scores_of(f.indicators)
    return max(sc, key=sc.get)


def run(pk):
    pk.sort(key=lambda p: p.ts)
    return run_detector(DhcpDetector(), pk)


def router_traffic(s, t, host="192.168.1.20", host_mac="02:00:00:00:00:20"):
    return [tcp(s, t + i * 0.01, f"93.184.216.{i}", 443, host, 50000, "A", eth_src=R_MAC, eth_dst=host_mac)
            for i in range(1, 5)]


def dora(s, t, mac, xid, server, smac, yiaddr, routers, dns, delay=0.010, mask="255.255.255.0", hostname=None):
    pk = [dhcp(s, t, 1, xid, mac, hostname=hostname),
          dhcp(s, t + delay, 2, xid, mac, src=server, server_id=server, yiaddr=yiaddr, routers=routers,
               dns_servers=dns, eth_src=smac),
          dhcp(s, t + delay + 0.01, 3, xid, mac, server_id=server, requested_ip=yiaddr, hostname=hostname),
          dhcp(s, t + delay + 0.02, 5, xid, mac, src=server, server_id=server, yiaddr=yiaddr, routers=routers,
               dns_servers=dns, eth_src=smac)]
    for p in pk:
        if p.dhcp.msg_type in (2, 5):
            p.dhcp.subnet_mask = mask
    return pk


def test_rogue_dhcp_same_subnet_is_attack():
    s = Seq()
    pk = router_traffic(s, 0.0)
    for k in range(6):
        mac = "02:00:00:00:01:%02x" % k
        xid = 0x1000 + k
        t = 5.0 + k * 3
        # the real router answers in 30 ms; the rogue races it in 1 ms with itself as gateway + DNS
        pk += dora(s, t, mac, xid, GW, R_MAC, f"192.168.1.{100 + k}", [GW], [GW], delay=0.030)
        o = dhcp(s, t + 0.001, 2, xid, mac, src="192.168.1.66", server_id="192.168.1.66",
                 yiaddr=f"192.168.1.{200 + k}", routers=["192.168.1.66"], dns_servers=["192.168.1.66"], eth_src=X_MAC)
        o.dhcp.subnet_mask = "255.255.255.0"
        pk.append(o)
        if k % 2:
            a = dhcp(s, t + 0.05, 5, xid, mac, src="192.168.1.66", server_id="192.168.1.66",
                     yiaddr=f"192.168.1.{200 + k}", routers=["192.168.1.66"], dns_servers=["192.168.1.66"], eth_src=X_MAC)
            pk.append(a)
            # client then uses the rogue as its gateway
            pk += [tcp(s, t + 1 + i * 0.1, f"192.168.1.{200 + k}", 50000, "8.8.4.4", 443, "S",
                       eth_src=mac, eth_dst=X_MAC) for i in range(3)]
    out = [f for f in run(pk) if f.kind == "dhcp.multiple_servers"]
    assert len(out) == 1
    f = out[0]
    assert winner(f) == Category.ATTACK and f.category == Category.ATTACK
    assert f.mitre.startswith("T1557.003")
    assert f.metrics["legit_server"] == GW and f.metrics["other_server"] == "192.168.1.66"
    assert f.metrics["same_subnet"] is True and f.metrics["other_wins"] >= 5
    assert f.severity >= Severity.HIGH
    assert "192.168.1.66" in f.hosts
    texts = " ".join(i.text for i in f.indicators)
    assert "names itself" in texts and "races" in texts


def test_second_home_router_is_misconfig():
    s = Seq()
    pk = router_traffic(s, 0.0)
    for k in range(4):
        mac = "02:00:00:00:02:%02x" % k
        t = 2.0 + k * 5
        pk += dora(s, t, mac, 0x2000 + k, GW, R_MAC, f"192.168.1.{100 + k}", [GW], ["192.168.1.1"])
    # a consumer router plugged in LAN-side hands out its own 192.168.0.0/24
    for k in range(2):
        mac = "02:00:00:00:03:%02x" % k
        pk += dora(s, 30.0 + k * 5, mac, 0x3000 + k, "192.168.0.1", "c8:3a:35:00:00:01", f"192.168.0.{100 + k}",
                   ["192.168.0.1"], ["8.8.8.8"], delay=0.005)
    out = [f for f in run(pk) if f.kind == "dhcp.multiple_servers"]
    assert len(out) == 1
    f = out[0]
    assert winner(f) == Category.MISCONFIG and f.category == Category.MISCONFIG
    assert f.metrics["same_subnet"] is False and f.metrics["other_subnet"] == "192.168.0.0/24"
    assert f.severity in (Severity.MEDIUM, Severity.HIGH)
    assert "second router" in f.title


def test_failover_pair_and_relay_are_quiet():
    s = Seq()
    pk = router_traffic(s, 0.0)
    for k in range(4):
        mac = "02:00:00:00:04:%02x" % k
        srv, smac = (("192.168.1.2", "aa:00:00:00:00:02") if k % 2 else ("192.168.1.3", "aa:00:00:00:00:03"))
        pk += dora(s, 1.0 + k * 3, mac, 0x4000 + k, srv, smac, f"192.168.1.{50 + k}", [GW], ["192.168.1.2", "192.168.1.3"])
    # relayed replies: src = relay address, server_id = real server
    for k in range(3):
        mac = "02:00:00:00:05:%02x" % k
        pk += dora(s, 20.0 + k * 3, mac, 0x5000 + k, "192.168.1.2", "aa:00:00:00:00:02", f"192.168.1.{60 + k}",
                   [GW], ["192.168.1.2", "192.168.1.3"])
        for p in pk[-4:]:
            if p.dhcp.msg_type in (2, 5):
                p.src, p.eth_src = GW, R_MAC
    # renewals
    pk += [dhcp(s, 40.0, 3, 0x6000, "02:00:00:00:04:00", server_id="192.168.1.3"),
           dhcp(s, 40.01, 5, 0x6000, "02:00:00:00:04:00", src="192.168.1.3", server_id="192.168.1.3",
                yiaddr="192.168.1.50", routers=[GW], dns_servers=["192.168.1.2", "192.168.1.3"], eth_src="aa:00:00:00:00:03")]
    out = run(pk)
    assert [f for f in out if f.severity >= Severity.MEDIUM] == []


def test_no_server_with_apipa():
    s = Seq()
    mac = "02:00:00:00:07:01"
    pk = [dhcp(s, t, 1, 0x7000 + i, mac, hostname="laptop") for i, t in enumerate((0.0, 4.0, 12.0, 28.0))]
    pk.append(arp(s, 30.0, 1, mac, "0.0.0.0", tpa="169.254.12.7"))
    out = [f for f in run(pk) if f.kind == "dhcp.no_server"]
    assert len(out) == 1
    f = out[0]
    assert f.category == Category.FAULT and f.severity >= Severity.MEDIUM
    assert f.metrics["apipa_macs"] == [mac]
    assert any("169.254" in i.text for i in f.indicators)


def test_quick_offer_is_not_no_server():
    s = Seq()
    pk = [dhcp(s, 0.0, 1, 0x8000, "02:00:00:00:08:01"), dhcp(s, 2.0, 1, 0x8001, "02:00:00:00:08:01")]
    pk += dora(s, 3.0, "02:00:00:00:08:01", 0x8002, GW, R_MAC, "192.168.1.80", [GW], [GW])
    assert not [f for f in run(pk) if f.kind == "dhcp.no_server"]


def test_nak_detection_and_single_nak_quiet():
    s = Seq()
    pk = []
    for k in range(3):
        mac = "02:00:00:00:09:%02x" % k
        pk.append(dhcp(s, k * 2.0, 3, 0x9000 + k, mac, requested_ip="10.0.0.%d" % (5 + k)))
        pk.append(dhcp(s, k * 2.0 + 0.01, 6, 0x9000 + k, mac, src=GW, server_id=GW, eth_src=R_MAC))
    pk += dora(s, 10.0, "02:00:00:00:09:00", 0x9100, GW, R_MAC, "192.168.1.90", [GW], [GW])
    out = [f for f in run(pk) if f.kind == "dhcp.nak"]
    assert len(out) == 1 and out[0].category == Category.MISCONFIG
    assert out[0].metrics["naks"] == 3
    # one NAK after moving networks, followed by a normal lease: nothing
    s = Seq()
    pk = [dhcp(s, 0.0, 3, 0x1, "02:00:00:00:0a:01", requested_ip="10.0.0.5"),
          dhcp(s, 0.01, 6, 0x1, "02:00:00:00:0a:01", src=GW, server_id=GW, eth_src=R_MAC)]
    pk += dora(s, 1.0, "02:00:00:00:0a:01", 0x2, GW, R_MAC, "192.168.1.91", [GW], [GW])
    assert not run(pk)


def test_starvation_attack():
    s = Seq()
    rnd = random.Random(1)
    pk = []
    for i in range(300):
        chaddr = "%02x:%02x:%02x:%02x:%02x:%02x" % tuple(rnd.randrange(256) for _ in range(6))
        pk.append(dhcp(s, i * 0.02, 1, rnd.getrandbits(32), chaddr, eth_src=X_MAC))
    out = [f for f in run(pk) if f.kind == "dhcp.starvation"]
    assert len(out) == 1
    f = out[0]
    assert f.category == Category.ATTACK and f.mitre and f.severity == Severity.HIGH
    assert f.metrics["top_sender"] == X_MAC and f.metrics["peak_new_macs"] >= 250


def test_lab_boot_is_not_starvation():
    s = Seq()
    pk = []
    for k in range(40):
        mac = "3c:22:fb:00:10:%02x" % k
        pk += dora(s, k * 1.2, mac, 0xA000 + k, GW, R_MAC, f"192.168.1.{100 + k}", [GW], [GW], hostname=f"lab-pc-{k}")
    assert not [f for f in run(pk) if f.kind == "dhcp.starvation"]


def test_robust_none_fields():
    s = Seq()
    p = dhcp(s, 0.0, 2, 0x1, "02:00:00:00:00:01", src=GW, server_id=None)
    p.dhcp.chaddr = None
    p.dhcp.xid = None
    p.dhcp.routers = []  # the shared HostTable expects lists here (decoder contract)
    p.dhcp.dns_servers = []
    p.dhcp.yiaddr = None
    q = dhcp(s, 0.1, 1, 0x2, "")
    q.dhcp.hostname = "<script>alert(1)</script>" * 20
    r = dhcp(s, 0.2, 99, 0x3, "zz:zz")
    t = dhcp(s, 0.3, 6, 0x4, "02:00:00:00:00:01", src=None)
    run([p, q, r, t])
