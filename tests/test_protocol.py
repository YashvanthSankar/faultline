from faultline.detectors.protocol import FragmentAttack, NonDnsOnDnsPort
from faultline.model import Category
from faultline.verdict import assess
from tests.factory import Seq, base, dns_query, dns_response, run_detector, tcp


def _text(p, kind="text on DNS port"):
    p.app_anomaly = kind
    return p


def test_shell_on_dns_port_is_an_attack():
    s = Seq()
    pk = [tcp(s, 0, "192.168.1.3", 1396, "192.168.1.2", 53, "S"), tcp(s, 0.001, "192.168.1.2", 53, "192.168.1.3", 1396, "SA")]
    pk.append(_text(tcp(s, 0.01, "192.168.1.2", 53, "192.168.1.3", 1396, "PA", plen=120), "shell on DNS port"))
    pk.append(_text(tcp(s, 0.5, "192.168.1.3", 1396, "192.168.1.2", 53, "PA", plen=5)))
    pk.append(_text(tcp(s, 0.6, "192.168.1.2", 53, "192.168.1.3", 1396, "PA", plen=900)))
    [f] = run_detector(NonDnsOnDnsPort(), pk)
    assess(f)
    assert f.kind == "dns.non_dns_traffic" and f.category == Category.ATTACK
    assert "shell" in f.title and f.mitre.startswith("T1571")
    assert f.packet_total == 3


def test_real_dns_never_triggers():
    s = Seq()
    pk = [dns_query(s, 0, "10.0.0.5", "10.0.0.1", 7, "example.com"), dns_response(s, 0.01, "10.0.0.1", "10.0.0.5", 7, "example.com")]
    assert run_detector(NonDnsOnDnsPort(), pk) == []


def _frag(s, t, off, length, mf, ip_id=242, proto=17, src="10.1.1.1", dst="129.111.30.27"):
    p = base(s, t, src, dst, proto=proto, ip_id=ip_id, df=False)
    p.frag_off, p.ip_len, p.mf = off, length, mf
    return p


def test_teardrop_overlap_is_an_attack():
    s = Seq()
    [f] = run_detector(FragmentAttack(), [_frag(s, 0, 0, 36, True), _frag(s, 0.001, 24, 4, False)])
    assess(f)
    assert f.kind == "ip.fragment_attack" and f.category == Category.ATTACK and "Teardrop" in f.title


def test_normal_and_duplicate_fragments_are_quiet():
    s = Seq()
    pk = [_frag(s, 0, 0, 1480, True), _frag(s, 0.001, 1480, 1480, True), _frag(s, 0.002, 2960, 100, False),
          _frag(s, 0.003, 1480, 1480, True)]  # exact duplicate of fragment 2 (network duplication)
    assert run_detector(FragmentAttack(), pk) == []


def test_tiny_first_tcp_fragment_is_evasion():
    s = Seq()
    [f] = run_detector(FragmentAttack(), [_frag(s, 0, 0, 8, True, proto=6), _frag(s, 0.001, 8, 12, False, proto=6)])
    assess(f)
    assert f.category == Category.ATTACK and "Tiny" in f.title
