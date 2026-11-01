"""Web dashboard: CSRF, upload validation, sample allowlist, limits and headers."""

from __future__ import annotations

import gzip
import io
import json
import os
import re
import struct
import threading
from pathlib import Path

import pytest

from faultline.web.app import create_app, sanitize_display_name, sniff_capture

FIXTURE = Path(__file__).parent / "fixtures" / "sample_report.json"


def tiny_pcap() -> bytes:
    """pcap global header + one Ethernet/ARP request frame."""
    gh = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    eth = b"\xff" * 6 + bytes.fromhex("021122334415") + b"\x08\x06"
    arp = struct.pack(">HHBBH", 1, 0x0800, 6, 4, 1) + bytes.fromhex("021122334415") + bytes([192, 168, 1, 15]) \
        + b"\x00" * 6 + bytes([192, 168, 1, 1])
    frame = eth + arp + b"\x00" * 18
    rec = struct.pack("<IIII", 1793500000, 0, len(frame), len(frame))
    return gh + rec + frame


class Recorder:
    """Injected analyze_fn: records the call and returns the fixture report."""

    def __init__(self):
        self.calls = []
        self.report = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def __call__(self, path, options, display_name):
        st = os.stat(path)
        self.calls.append({"path": path, "options": options, "name": display_name, "mode": st.st_mode & 0o777,
                           "magic": Path(path).read_bytes()[:4]})
        r = json.loads(json.dumps(self.report))
        r["capture"]["name"] = display_name
        return r


@pytest.fixture()
def samples(tmp_path):
    d = tmp_path / "samples"
    d.mkdir()
    (d / "mitm_rogue_dhcp.pcap").write_bytes(tiny_pcap())
    (d / "notes.txt").write_text("not a capture")
    (d / "labels.json").write_text(json.dumps({
        "mitm_rogue_dhcp.pcap": {"title": "Rogue DHCP <b>MITM</b>", "story": "Every website is wrong.",
                                 "expected": [{"kind": "dhcp.rogue_server", "category": "attack"}], "clean": False}}))
    for extra in ("ip_conflict.pcap", "arp_spoofing.pcap", "dns_failure.pcap", "clean_office.pcap",
                  "mitm_chain.pcap", "outage_vs_attack_mixed.pcap", "xss_payload.pcap"):
        (d / extra).write_bytes(tiny_pcap())
    (tmp_path / "secret.pcap").write_bytes(tiny_pcap())
    return d


@pytest.fixture()
def rec():
    return Recorder()


@pytest.fixture()
def app(samples, rec):
    a = create_app(max_upload_mb=1, samples_dir=samples, analyze_fn=rec)
    a.config["TESTING"] = True
    return a


@pytest.fixture()
def client(app):
    return app.test_client()


def token(app):
    return app.config["FAULTLINE_CSRF_TOKEN"]


def upload(client, data: bytes, name: str, tok: str | None, **extra):
    form = {"capture": (io.BytesIO(data), name)}
    if tok is not None:
        form["csrf_token"] = tok
    form.update(extra)
    return client.post("/analyze", data=form, content_type="multipart/form-data")


SEC_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def assert_secure_headers(resp):
    for k, v in SEC_HEADERS.items():
        assert resp.headers.get(k) == v, k
    csp = resp.headers.get("Content-Security-Policy", "")
    assert "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp


# --------------------------------------------------------------------------- pages


def test_index(client, app):
    r = client.get("/")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "Analyze a capture" in body
    assert token(app) in body  # CSRF token embedded in the form
    assert "Rogue DHCP &lt;b&gt;MITM&lt;/b&gt;" in body  # labels are escaped
    assert "/sample/mitm_rogue_dhcp.pcap" in body
    assert "notes.txt" not in body
    assert_secure_headers(r)
    nonce = re.search(r"script-src 'nonce-([^']+)'", r.headers["Content-Security-Policy"]).group(1)
    assert f'<script nonce="{nonce}">' in body and f'<style nonce="{nonce}">' in body


def test_index_lists_files_without_labels(tmp_path, rec):
    d = tmp_path / "s"
    d.mkdir()
    (d / "lossy_link.pcapng").write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 28)
    c = create_app(samples_dir=d, analyze_fn=rec).test_client()
    body = c.get("/").get_data(as_text=True)
    assert "Lossy link" in body and "/sample/lossy_link.pcapng" in body


def test_index_without_samples_dir(tmp_path, rec):
    c = create_app(samples_dir=tmp_path / "missing", analyze_fn=rec).test_client()
    r = c.get("/")
    assert r.status_code == 200 and "No sample captures yet" in r.get_data(as_text=True)


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200 and r.get_json() == {"status": "ok"}
    assert_secure_headers(r)


# --------------------------------------------------------------------------- upload


def test_upload_without_token_is_403(client, rec):
    r = upload(client, tiny_pcap(), "a.pcap", None)
    assert r.status_code == 403
    assert "Request blocked" in r.get_data(as_text=True)
    assert rec.calls == []


def test_upload_with_wrong_token_is_403(client, rec):
    r = upload(client, tiny_pcap(), "a.pcap", "x" * 43)
    assert r.status_code == 403 and rec.calls == []


def test_upload_non_capture_is_400(client, app, rec):
    r = upload(client, b"MZ\x90\x00 this is an exe, not a capture" * 4, "evil.pcap", token(app))
    assert r.status_code == 400
    assert "not a packet capture" in r.get_data(as_text=True)
    assert rec.calls == []


def test_upload_bad_extension_is_400(client, app, rec):
    r = upload(client, tiny_pcap(), "notes.txt", token(app))
    assert r.status_code == 400 and "Unsupported file type" in r.get_data(as_text=True)


def test_upload_empty_is_400(client, app):
    r = upload(client, b"", "a.pcap", token(app))
    assert r.status_code == 400


def test_upload_valid_pcap(client, app, rec):
    r = upload(client, tiny_pcap(), "../../etc/<i>office\x1b[31m.pcap", token(app), redact="1", sensitivity="high")
    assert r.status_code == 200, r.get_data(as_text=True)[:500]
    body = r.get_data(as_text=True)
    assert "faultline-data" in body and "under_attack" in body
    assert 'data-embedded="1"' in body
    assert "<script>alert" not in body and "<img src=x" not in body
    assert_secure_headers(r)
    csp = r.headers["Content-Security-Policy"]
    assert "script-src 'sha256-" in csp and "default-src 'none'" in csp
    # The analysis got a private temp file, not the client's name.
    call = rec.calls[0]
    assert call["magic"] == b"\xd4\xc3\xb2\xa1"
    assert call["mode"] == 0o600
    assert "office" not in os.path.basename(call["path"]) and ".." not in call["path"]
    assert call["name"] == "<i>office[31m.pcap"
    assert "<i>office" not in body  # display name only appears escaped
    assert call["options"].redact is True and call["options"].sensitivity == "high"
    # ... and the file is gone afterwards.
    assert not os.path.exists(call["path"])


def test_upload_gzip_capture(client, app, rec):
    r = upload(client, gzip.compress(tiny_pcap()), "x.pcap.gz", token(app))
    assert r.status_code == 200
    assert rec.calls[0]["path"].endswith(".pcap.gz")


def test_upload_gzip_of_garbage_rejected(client, app, rec):
    r = upload(client, gzip.compress(b"hello world, definitely not pcap"), "x.pcap.gz", token(app))
    assert r.status_code == 400 and rec.calls == []


def test_oversize_upload_is_413(client, app, rec):
    big = tiny_pcap() + b"\x00" * (1024 * 1024 + 10)
    r = upload(client, big, "big.pcap", token(app))
    assert r.status_code == 413
    assert "File too large" in r.get_data(as_text=True)
    assert rec.calls == []


def test_cross_origin_post_blocked(client, app, rec):
    r = client.post("/analyze", data={"capture": (io.BytesIO(tiny_pcap()), "a.pcap"), "csrf_token": token(app)},
                    content_type="multipart/form-data", headers={"Origin": "http://evil.example"})
    assert r.status_code == 403 and rec.calls == []


def test_dns_rebinding_host_blocked(client):
    r = client.get("/", headers={"Host": "attacker.example:8765"})
    assert r.status_code == 400


def test_get_analyze_not_allowed(client):
    assert client.get("/analyze").status_code == 405


# --------------------------------------------------------------------------- API


def test_api_requires_token(client, rec):
    r = client.post("/api/analyze", data={"capture": (io.BytesIO(tiny_pcap()), "a.pcap")}, content_type="multipart/form-data")
    assert r.status_code == 403 and r.is_json and rec.calls == []


def test_api_returns_json(client, app):
    r = client.post("/api/analyze", data={"capture": (io.BytesIO(tiny_pcap()), "a.pcap")},
                    content_type="multipart/form-data", headers={"X-Faultline-Token": token(app)})
    assert r.status_code == 200
    data = r.get_json()
    assert data["verdict"]["status"] == "under_attack" and data["capture"]["name"] == "a.pcap"


# --------------------------------------------------------------------------- samples


def test_sample_runs(client, rec, samples):
    r = client.get("/sample/mitm_rogue_dhcp.pcap?redact=1")
    assert r.status_code == 200 and "faultline-data" in r.get_data(as_text=True)
    assert rec.calls[0]["name"] == "mitm_rogue_dhcp.pcap"
    assert rec.calls[0]["options"].redact is True
    assert Path(rec.calls[0]["path"]) == samples / "mitm_rogue_dhcp.pcap"


@pytest.mark.parametrize("name", [
    "../../etc/passwd", "..%2F..%2Fetc%2Fpasswd", "../secret.pcap", "%2e%2e/secret.pcap",
    "/etc/passwd", "notes.txt", "labels.json", "missing.pcap", "mitm_rogue_dhcp.pcap/..",
])
def test_sample_traversal_404(client, rec, name):
    r = client.get("/sample/" + name, follow_redirects=True)
    assert r.status_code == 404
    assert rec.calls == []
    assert "root:" not in r.get_data(as_text=True)


# --------------------------------------------------------------------------- errors & limits


def test_capture_error_is_friendly(samples):
    from faultline.capture.reader import CaptureError

    def boom(path, options, name):
        raise CaptureError(f"pcapng block at offset 28 in {path} is longer than the file")

    app = create_app(samples_dir=samples, analyze_fn=boom)
    c = app.test_client()
    r = upload(c, tiny_pcap(), "broken.pcap", token(app))
    assert r.status_code == 422
    body = r.get_data(as_text=True)
    assert "could not be read" in body and "broken.pcap" in body
    assert "/tmp" not in body and "faultline-" not in body and "upload-" not in body


def test_internal_error_hides_details(samples):
    def boom(path, options, name):
        raise RuntimeError(f"secret internal detail {path}")

    app = create_app(samples_dir=samples, analyze_fn=boom)
    r = upload(app.test_client(), tiny_pcap(), "a.pcap", token(app))
    assert r.status_code == 500
    body = r.get_data(as_text=True)
    assert "secret internal detail" not in body and "Traceback" not in body
    assert_secure_headers(r)


def test_concurrency_limit(samples):
    gate = threading.Event()
    started = threading.Semaphore(0)

    def slow(path, options, name):
        started.release()
        gate.wait(5)
        return json.loads(FIXTURE.read_text(encoding="utf-8"))

    app = create_app(samples_dir=samples, analyze_fn=slow)
    results = []

    def worker():
        results.append(app.test_client().get("/sample/mitm_rogue_dhcp.pcap").status_code)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    assert started.acquire(timeout=5) and started.acquire(timeout=5)
    third = app.test_client().get("/sample/mitm_rogue_dhcp.pcap")
    assert third.status_code == 503
    gate.set()
    for t in threads:
        t.join(5)
    assert results == [200, 200]


def test_unknown_route_404_has_headers(client):
    r = client.get("/nope")
    assert r.status_code == 404
    assert_secure_headers(r)


def test_secrets_are_random_per_app(samples, rec):
    a = create_app(samples_dir=samples, analyze_fn=rec)
    b = create_app(samples_dir=samples, analyze_fn=rec)
    assert a.config["FAULTLINE_CSRF_TOKEN"] != b.config["FAULTLINE_CSRF_TOKEN"]
    assert a.config["SECRET_KEY"] != b.config["SECRET_KEY"]
    assert len(a.config["FAULTLINE_CSRF_TOKEN"]) >= 40
    assert a.debug is False


# --------------------------------------------------------------------------- helpers


def test_sanitize_display_name():
    assert sanitize_display_name("C:\\Users\\me\\cap.pcap") == "cap.pcap"
    assert sanitize_display_name("/etc/../x.pcapng") == "x.pcapng"
    assert sanitize_display_name("a\u202egnp.pcap") == "agnp.pcap"  # bidi override stripped
    assert sanitize_display_name("bad\x00\x07name.pcap") == "badname.pcap"
    assert sanitize_display_name("") == "capture.pcap"
    assert sanitize_display_name("...") == "capture.pcap"
    long = sanitize_display_name("x" * 500 + ".pcap.gz")
    assert len(long) <= 80 and long.endswith(".pcap.gz")


def test_sniff_capture(tmp_path):
    cases = {
        "le.pcap": tiny_pcap(),
        "be.pcap": b"\xa1\xb2\xc3\xd4" + b"\x00" * 20,
        "ns.pcap": b"\x4d\x3c\xb2\xa1" + b"\x00" * 20,
        "x.pcapng": b"\x0a\x0d\x0d\x0a" + b"\x00" * 20,
    }
    for name, data in cases.items():
        p = tmp_path / name
        p.write_bytes(data)
        assert sniff_capture(p) is not None, name
    p = tmp_path / "x.gz"
    p.write_bytes(gzip.compress(tiny_pcap()))
    assert sniff_capture(p) == "pcap.gz"
    p.write_bytes(b"\x1f\x8b\x08\x00garbage")
    assert sniff_capture(p) is None
    p.write_bytes(b"GIF89a")
    assert sniff_capture(p) is None


def test_real_size_upload_is_accepted():
    """Regression: uploads larger than 64 KiB were rejected with 413 (werkzeug form-memory limit)."""
    import io as _io
    import os as _os

    from faultline.web.app import create_app as _create

    path = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), "samples", "lossy_link.pcap")
    if not _os.path.exists(path):
        import pytest as _pytest
        _pytest.skip("samples not generated")
    app = _create()
    c = app.test_client()
    data = open(path, "rb").read()
    assert len(data) > 1024 * 1024
    r = c.post("/analyze", data={"csrf_token": app.config["FAULTLINE_CSRF_TOKEN"], "capture": (_io.BytesIO(data), "lossy_link.pcap")},
               content_type="multipart/form-data")
    assert r.status_code == 200


# --------------------------------------------------------------------------- compare


def test_compare_get_two_samples(client, rec):
    r = client.get("/compare?a=ip_conflict.pcap&b=arp_spoofing.pcap&redact=1")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "ip_conflict.pcap" in body and "arp_spoofing.pcap" in body
    assert "What changed" in body and "Open full report" in body
    assert "/sample/ip_conflict.pcap?redact=1" in body
    assert "<script>alert" not in body and "<img src=x" not in body  # hostile fixture strings escaped
    assert [c["name"] for c in rec.calls] == ["ip_conflict.pcap", "arp_spoofing.pcap"]
    assert all(c["options"].redact is True for c in rec.calls)
    assert_secure_headers(r)
    nonce = re.search(r"style-src 'nonce-([^']+)'", r.headers["Content-Security-Policy"]).group(1)
    assert f'<style nonce="{nonce}">' in body


@pytest.mark.parametrize("qs", [
    "", "a=ip_conflict.pcap", "b=ip_conflict.pcap", "a=ip_conflict.pcap&b=missing.pcap",
    "a=../secret.pcap&b=ip_conflict.pcap", "a=ip_conflict.pcap&b=labels.json", "a=notes.txt&b=ip_conflict.pcap",
    "a=%2e%2e/secret.pcap&b=ip_conflict.pcap",
])
def test_compare_get_rejects_bad_names(client, rec, qs):
    r = client.get("/compare?" + qs)
    assert r.status_code == 404
    assert rec.calls == []
    assert_secure_headers(r)


def test_compare_post_requires_token(client, rec):
    r = client.post("/compare", data={"capture_a": (io.BytesIO(tiny_pcap()), "a.pcap"), "capture_b": (io.BytesIO(tiny_pcap()), "b.pcap")},
                    content_type="multipart/form-data")
    assert r.status_code == 403 and rec.calls == []


def test_compare_post_two_uploads(client, app, rec):
    r = client.post("/compare", data={"csrf_token": token(app), "capture_a": (io.BytesIO(tiny_pcap()), "before.pcap"),
                                      "capture_b": (io.BytesIO(gzip.compress(tiny_pcap())), "../after<b>.pcap.gz")},
                    content_type="multipart/form-data")
    assert r.status_code == 200, r.get_data(as_text=True)[:300]
    body = r.get_data(as_text=True)
    assert "before.pcap" in body and "after&lt;b&gt;.pcap.gz" in body and "<b>.pcap" not in body
    assert [c["name"] for c in rec.calls] == ["before.pcap", "after<b>.pcap.gz"]
    for c in rec.calls:
        assert c["mode"] == 0o600 and not os.path.exists(c["path"])
    assert_secure_headers(r)


def test_compare_post_one_bad_file(client, app, rec):
    r = client.post("/compare", data={"csrf_token": token(app), "capture_a": (io.BytesIO(tiny_pcap()), "a.pcap"),
                                      "capture_b": (io.BytesIO(b"MZ not a capture at all" * 3), "b.pcap")},
                    content_type="multipart/form-data")
    assert r.status_code == 400
    assert "not a packet capture" in r.get_data(as_text=True)
    assert len(rec.calls) <= 1  # the second file is refused before any analysis of it
    for c in rec.calls:
        assert not os.path.exists(c["path"])
    r = client.post("/compare", data={"csrf_token": token(app), "capture_a": (io.BytesIO(tiny_pcap()), "a.pcap")},
                    content_type="multipart/form-data")
    assert r.status_code == 400 and "Two files" in r.get_data(as_text=True)


def test_compare_cross_origin_blocked(client, app, rec):
    r = client.post("/compare", data={"csrf_token": token(app), "capture_a": (io.BytesIO(tiny_pcap()), "a.pcap"),
                                      "capture_b": (io.BytesIO(tiny_pcap()), "b.pcap")},
                    content_type="multipart/form-data", headers={"Origin": "http://evil.example"})
    assert r.status_code == 403 and rec.calls == []


def test_index_landing_features(client):
    body = client.get("/").get_data(as_text=True)
    assert 'data-filter="attack"' in body and "Hostile files" in body
    assert "Start here" in body and "The full man-in-the-middle story" in body
    assert "/compare?a=ip_conflict.pcap&amp;b=arp_spoofing.pcap" in body
    assert "/compare?a=dns_failure.pcap&amp;b=clean_office.pcap" in body
    assert 'data-badge="hostile"' in body  # xss_payload.pcap
    assert "How Faultline works" in body
    assert 'action="/compare"' in body
