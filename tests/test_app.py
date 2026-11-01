"""Tests for cred.cleartext / tls.failure / tls.deprecated / http.errors."""

from __future__ import annotations

from faultline.detectors.app import AppDetector, clean
from faultline.model import Category, Severity, Tls
from tests.factory import Seq, http_request, http_response, run_detector, tcp, tls_hello

C, SRV = "10.0.0.2", "10.0.0.9"


def score(f, cat):
    return sum(i.weight for i in f.indicators if i.supports is cat)


def winner(f):
    return max((Category.FAULT, Category.MISCONFIG, Category.ATTACK), key=lambda c: score(f, c))


def cred(s, t, proto, client=C, cport=50000, server=SRV, port=21):
    p = tcp(s, t, client, cport, server, port, "PA", plen=20)
    p.cred = proto
    return p


def alert(s, t, src, sport, dst, dport, desc, level=2):
    p = tcp(s, t, src, sport, dst, dport, "PA", plen=7)
    tl = Tls()
    tl.record_version = 0x0303
    tl.alerts = [(level, desc)]
    p.tls = tl
    return p


def server_hello(s, t, src, sport, dst, dport, version):
    p = tcp(s, t, src, sport, dst, dport, "PA", plen=90)
    tl = Tls()
    tl.record_version, tl.handshake_types, tl.client_version = version, [2], version
    p.tls = tl
    return p


def kinds(fs):
    return sorted(f.kind for f in fs)


# --------------------------------------------------------------------------- #
# credentials
# --------------------------------------------------------------------------- #


def test_ftp_cleartext_login():
    s = Seq()
    fs = run_detector(AppDetector(), [cred(s, 0, "FTP"), cred(s, 0.1, "FTP")])
    assert kinds(fs) == ["cred.cleartext"]
    f = fs[0]
    assert f.category is Category.MISCONFIG and f.severity == Severity.HIGH
    assert "unencrypted" in f.title.lower() and f.metrics["server"] == f"{SRV}:21"
    assert any("SFTP" in x for x in f.fix)
    assert any("anyone" in i.text.lower() for i in f.indicators)
    assert f.mitre is None and Category.ATTACK not in f.variants


def test_ftp_brute_force_variant():
    s = Seq()
    pk = [cred(s, i * 1.5, "FTP", cport=50000 + i) for i in range(20)]
    f = run_detector(AppDetector(), pk)[0]
    assert Category.ATTACK in f.variants and f.variants[Category.ATTACK].mitre.startswith("T1110")
    assert score(f, Category.ATTACK) >= 2.5


def test_http_basic_on_many_requests_is_not_brute_force():
    s = Seq()
    pk = [cred(s, i * 0.02, "HTTP Basic", cport=50000 + i % 6, port=80) for i in range(80)]
    f = run_detector(AppDetector(), pk)[0]
    assert Category.ATTACK not in f.variants


def test_telnet_server_side_detection():
    s = Seq()
    p = tcp(s, 0, SRV, 23, C, 50000, "PA", plen=10)  # credential seen on a server->client packet
    p.cred = "Telnet"
    f = run_detector(AppDetector(), [p])[0]
    assert f.metrics["server"] == f"{SRV}:23" and f.metrics["clients"] == [C]


# --------------------------------------------------------------------------- #
# TLS
# --------------------------------------------------------------------------- #


def test_expired_certificate_single_alert_low():
    s = Seq()
    pk = [tls_hello(s, 0, C, 50000, SRV, sni="shop.example.com"), alert(s, 0.05, C, 50000, SRV, 443, 45)]
    fs = run_detector(AppDetector(), pk)
    assert kinds(fs) == ["tls.failure"]
    f = fs[0]
    assert "expired" in f.summary and f.severity == Severity.LOW
    assert f.metrics["sni"] == ["shop.example.com"]
    assert any("certbot" in x for x in f.fix)


def test_handshake_failures_from_server_misconfig():
    s = Seq()
    pk = []
    for i in range(3):
        pk += [tls_hello(s, i, f"10.0.0.{i + 2}", 50000, SRV, sni="api.example.com"),
               alert(s, i + 0.01, SRV, 443, f"10.0.0.{i + 2}", 50000, 40)]
    f = run_detector(AppDetector(), pk)[0]
    assert f.category is Category.MISCONFIG and winner(f) is Category.MISCONFIG
    assert f.severity == Severity.MEDIUM


def test_single_non_certificate_alert_and_close_notify_ignored():
    s = Seq()
    pk = [tls_hello(s, 0, C, 50000, SRV), alert(s, 0.1, SRV, 443, C, 50000, 80),
          alert(s, 0.2, C, 50001, SRV, 443, 0, level=1), alert(s, 0.3, C, 50002, SRV, 443, 90, level=1)]
    assert run_detector(AppDetector(), pk) == []


def test_unknown_ca_on_many_servers_suggests_interception():
    s = Seq()
    pk = []
    for i in range(4):
        srv = f"93.184.{i}.10"
        pk += [tls_hello(s, i, C, 50000 + i, srv, sni=f"site{i}.example"), alert(s, i + 0.01, C, 50000 + i, srv, 443, 48)]
    fs = run_detector(AppDetector(), pk)
    assert len(fs) == 4
    for f in fs:
        assert Category.ATTACK in f.variants
        assert any(i.supports is Category.ATTACK and i.weight >= 1.5 for i in f.indicators)


def test_deprecated_tls_server_and_client():
    s = Seq()
    pk = [tls_hello(s, 0, C, 50000, SRV, sni="old.example.com", version=0x0301),
          server_hello(s, 0.01, SRV, 443, C, 50000, 0x0301),
          tls_hello(s, 1, C, 50001, "10.0.0.10", sni="legacy.example.com", version=0x0302),
          tls_hello(s, 2, C, 50002, "10.0.0.11", sni="modern.example.com", version=0x0303)]
    fs = run_detector(AppDetector(), pk)
    assert kinds(fs) == ["tls.deprecated", "tls.deprecated"]
    by = {f.metrics["server"]: f for f in fs}
    assert by[f"{SRV}:443"].severity == Severity.MEDIUM and "TLS 1.0" in by[f"{SRV}:443"].title
    assert by["10.0.0.10:443"].severity == Severity.LOW
    assert by[f"{SRV}:443"].metrics["sni"] == ["old.example.com"]


def test_tls13_with_grease_not_deprecated():
    s = Seq()
    p = tls_hello(s, 0, C, 50000, SRV)
    p.tls.supported_versions = [0x1A1A, 0x0304, 0x0303]
    p.tls.client_version = 0x0303
    assert run_detector(AppDetector(), [p]) == []


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #


def http_pair(s, t, cport, status, path="/", client=C, server=SRV, method="GET", host="shop.example.com"):
    return [http_request(s, t, client, cport, server, 80, method=method, host=host, path=path),
            http_response(s, t + 0.05, server, 80, client, cport, status=status)]


def test_http_5xx_server_fault():
    s = Seq()
    pk = []
    for i in range(10):
        pk += http_pair(s, i, 50000 + i, 502 if i % 2 else 200, path="/checkout" if i % 2 else "/")
    fs = run_detector(AppDetector(), pk)
    assert kinds(fs) == ["http.errors"]
    f = fs[0]
    assert f.category is Category.FAULT and "shop.example.com" in f.title
    assert f.metrics["failing_requests"] == ["GET /checkout"]
    assert Category.MISCONFIG in f.variants  # 502 -> proxy/backend config reading


def test_one_404_and_few_5xx_nothing():
    s = Seq()
    pk = http_pair(s, 0, 50000, 404, "/favicon.ico")
    for i in range(40):
        pk += http_pair(s, 1 + i, 50001 + i, 500 if i < 2 else 200)
    assert run_detector(AppDetector(), pk) == []


def test_http_401_brute_force():
    s = Seq()
    pk = []
    for i in range(30):
        pk += http_pair(s, i * 0.3, 50000 + i, 401, "/login", method="POST")
    fs = run_detector(AppDetector(), pk)
    att = [f for f in fs if f.category is Category.ATTACK]
    assert len(att) == 1 and att[0].mitre.startswith("T1110") and winner(att[0]) is Category.ATTACK
    assert all(f.severity < Severity.MEDIUM for f in fs if f is not att[0])


def test_ntlm_challenge_401_then_200_not_brute_force():
    s = Seq()
    pk = []
    for i in range(40):
        pk += http_pair(s, i * 0.5, 50000 + i, 401, "/api/status")
        pk += http_pair(s, i * 0.5 + 0.1, 50000 + i, 200, "/api/status")
    fs = run_detector(AppDetector(), pk)
    assert not [f for f in fs if f.severity >= Severity.MEDIUM]


def test_stale_password_app_is_misconfig_not_attack():
    s = Seq()
    pk = []
    for i in range(60):  # every 2 s for 2 minutes
        pk += http_pair(s, i * 2.0, 50000 + i, 401, "/api/sync")
    fs = [f for f in run_detector(AppDetector(), pk) if f.kind == "http.errors" and "c401" in f.metrics]
    assert len(fs) == 1 and fs[0].category is Category.MISCONFIG and fs[0].severity == Severity.LOW


def test_wordlist_content_scan():
    s = Seq()
    words = ["admin", "backup", "wp-admin", ".git", "phpmyadmin", "old", "test", "config", "db", "uploads", "cgi-bin",
             "private", "secret", "api", "dev", "tmp", "logs", "server-status", "install", "setup", "shell", "panel"]
    pk = []
    for i in range(80):
        pk += http_pair(s, i * 0.2, 50000 + i, 404, f"/{words[i % len(words)]}{i // len(words) or ''}/")
    fs = run_detector(AppDetector(), pk)
    att = [f for f in fs if f.category is Category.ATTACK]
    assert len(att) == 1 and att[0].mitre.startswith("T1595.003")
    assert len(fs) == 1  # the generic 4xx finding is explained by the scan


def test_broken_page_many_missing_images_not_scan():
    s = Seq()
    pk = []
    for i in range(70):
        pk += http_pair(s, i * 0.05, 50000 + i, 404, f"/static/thumbs/{i}.jpg")
    fs = run_detector(AppDetector(), pk)
    assert not [f for f in fs if f.category is Category.ATTACK]
    assert all(f.severity <= Severity.LOW for f in fs)


def test_untrusted_strings_are_cleaned():
    s = Seq()
    evil = "<script>alert(1)</script>\x00\x1b[31m" + "A" * 300
    pk = [tls_hello(s, 0, C, 50000, SRV, sni=evil), alert(s, 0.01, C, 50000, SRV, 443, 45)]
    f = run_detector(AppDetector(), pk)[0]
    sni = f.metrics["sni"][0]
    assert len(sni) <= 100 and "\x00" not in sni and "\x1b" not in sni
    assert clean(None) == "" and len(clean("x" * 500)) == 100


def test_none_fields_robust():
    s = Seq()
    p1 = http_response(s, 0, SRV, 80, C, 50000, status=None)
    p2 = tls_hello(s, 0, C, 50000, SRV, sni=None)
    p2.tls.supported_versions = []
    p2.tls.client_version = None
    p3 = alert(s, 0, C, 50000, SRV, 443, 45)
    p3.tcp.sport = None
    p4 = http_request(s, 0, C, 50000, SRV, host=None, path=None, method=None)
    run_detector(AppDetector(), [p1, p2, p3, p4])
