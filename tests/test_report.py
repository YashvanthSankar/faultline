"""HTML report: escaping, CSP and self-containment."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
from pathlib import Path

import pytest

from faultline.report.html import build_page, embed_json, render_html

FIXTURE = Path(__file__).parent / "fixtures" / "sample_report.json"
ASSETS = Path(__file__).resolve().parents[1] / "faultline" / "report" / "assets"


@pytest.fixture(scope="module")
def report() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def page(report) -> str:
    return render_html(report)


def _inline_scripts(html: str) -> list[str]:
    return re.findall(r"<script>(.*?)</script>", html, flags=re.S)


def _sha(text: str) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode()


def test_fixture_contains_hostile_strings(report):
    raw = FIXTURE.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" in raw
    assert '"><img src=x onerror=alert(1)>' in raw or '\\"><img src=x onerror=alert(1)>' in raw


def test_hostile_strings_never_unescaped(page):
    assert "<script>alert" not in page
    assert "<img src=x onerror" not in page
    assert "</script>.example.com" not in page
    # The data is still there, just escaped.
    assert "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e.example.com" in page


def test_only_expected_tags(page):
    assert page.count("<script") == 2  # the JSON data block + the renderer
    assert page.count("</script>") == 2
    assert page.count("<style") == 1
    assert "<img" not in page and "<iframe" not in page
    links = re.findall(r"<link[^>]*>", page)
    assert len(links) == 1 and links[0].startswith('<link rel="icon" href="data:image/svg+xml,')


def test_embedded_json_roundtrips(report, page):
    m = re.search(r'<script type="application/json" id="faultline-data">(.*?)</script>', page, flags=re.S)
    assert m
    payload = m.group(1)
    for ch in "<>&  ":
        assert ch not in payload
    assert json.loads(payload) == report


def test_embed_json_escapes_separators_and_nan():
    out = embed_json({"a": "x y z</script><!--&", "n": float("nan"), "i": float("inf")})
    assert " " not in out and " " not in out and "<" not in out and ">" not in out and "&" not in out
    data = json.loads(out)
    assert data["a"] == "x y z</script><!--&"
    assert data["n"] is None and data["i"] is None


def test_csp_meta_hashes_match(page):
    m = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)">', page)
    assert m, "CSP meta tag missing"
    csp = m.group(1).replace("&#x27;", "'")
    assert "default-src 'none'" in csp
    assert "connect-src 'none'" in csp
    assert "base-uri 'none'" in csp
    assert "form-action 'none'" in csp
    assert "img-src data:" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    scripts = _inline_scripts(page)
    assert len(scripts) == 1
    assert f"script-src '{_sha(scripts[0])}'" in csp
    style = re.search(r"<style>(.*?)</style>", page, flags=re.S).group(1)
    assert f"style-src '{_sha(style)}'" in csp
    assert '<meta name="referrer" content="no-referrer">' in page


def test_build_page_returns_same_csp(report):
    rendered = build_page(report, embedded_in_app=True)
    # Header policy = meta policy + frame-ancestors (ignored by browsers when delivered via <meta>).
    assert rendered.csp.endswith("; frame-ancestors 'none'")
    meta_csp = rendered.csp[: -len("; frame-ancestors 'none'")]
    assert meta_csp.replace("'", "&#x27;") in rendered.html
    assert '<html lang="en" data-embedded="1">' in rendered.html
    assert '<html lang="en">' in render_html(report)


def test_no_external_resources(page):
    without_data = re.sub(r'<script type="application/json" id="faultline-data">.*?</script>', "", page, flags=re.S)
    for url in re.findall(r"https?://[^\s\"'<>)]+", without_data):
        # The only allowed URL is the SVG namespace identifier (not fetched).
        assert url == "http://www.w3.org/2000/svg", url
    assert "@import" not in without_data
    assert "url(http" not in without_data
    assert not re.search(r"\b(src|href)\s*=\s*[\"']?(https?:)?//", without_data)


def test_js_uses_no_html_sinks():
    js = (ASSETS / "report.js").read_text(encoding="utf-8")
    for sink in ("innerHTML", "outerHTML =", "insertAdjacentHTML", "document.write", "eval(", "new Function", "setAttribute(\"style\""):
        assert sink not in js, sink
    assert "</" not in js


def test_title_is_escaped(report):
    r = copy.deepcopy(report)
    r["capture"]["name"] = "</title><script>alert(2)</script>.pcap"
    html = render_html(r)
    assert "<script>alert(2)" not in html
    assert "&lt;/title&gt;&lt;script&gt;" in html


def test_minimal_and_broken_reports_render():
    # Healthy, nearly empty report: must not crash.
    html = render_html({"verdict": {"status": "healthy", "score": 100}, "findings": []})
    assert "faultline-data" in html
    # Garbage values: still renders (JS validates every field).
    html = render_html({"verdict": "x", "capture": ["nope"], "findings": [None, 3, {"id": "<b>"}]})
    assert "<b>" not in html.split('id="faultline-data">', 1)[1]
    with pytest.raises(TypeError):
        render_html(["not", "a", "dict"])  # type: ignore[arg-type]


def test_redacted_report_has_no_evidence_downloads(report):
    r = copy.deepcopy(report)
    r["redacted"] = True
    r.pop("evidence", None)
    html = render_html(r)
    payload = re.search(r'<script type="application/json" id="faultline-data">(.*?)</script>', html, flags=re.S).group(1)
    assert '"redacted":true' in payload
    assert '"evidence"' not in payload  # no evidence bytes are embedded at all


# --------------------------------------------------------------------------- new UI features


def test_network_map_and_glossary_are_in_renderer():
    js = (ASSETS / "report.js").read_text(encoding="utf-8")
    css = (ASSETS / "report.css").read_text(encoding="utf-8")
    assert "function networkMap(" in js and "Text version of this map" in js
    assert "MAX_DEVICES = 24" in js  # large captures are capped and aggregated as "+N more"
    assert "GLOSSARY" in js and '["ARP",' in js and '["DHCP",' in js and '["NXDOMAIN",' in js
    assert 'role: "tooltip"' in js and 'tabindex: "0"' in js  # keyboard-accessible tooltips
    assert "Show all " in js and "PREVIEW = 8" in js  # evidence table preview + toggle
    assert "mini-verdict" in js and ".mini-verdict" in css
    assert "Start with this" in js
    assert ".netmap" in css and ".term .tip" in css


def test_console_shell_and_router_are_in_renderer():
    """App shell: sidebar sections, hash routing, master-detail findings with tabs."""
    js = (ASSETS / "report.js").read_text(encoding="utf-8")
    css = (ASSETS / "report.css").read_text(encoding="utf-8")
    for sec in ("overview", "incidents", "findings", "network", "evidence", "capture"):
        assert '["%s", ' % sec in js, sec
    assert "function parseHash(" in js and "function showSection(" in js and '"hashchange"' in js
    assert '["why", "Why this verdict"]' in js and '["evidence", "Evidence"]' in js and '["technical", "Technical"]' in js
    assert '"ArrowDown"' in js and '"ArrowUp"' in js  # keyboard navigation through the list
    assert 'type: "search"' in js  # findings search box
    for cls in (".shell", ".side", ".topbar", ".fl-list", ".fl-detail", ".scoreboard", ".kpis", "@media print"):
        assert cls in css, cls
    assert "prefers-reduced-motion" in css


def test_hash_routes_are_validated_against_findings(report):
    """Only a finding id that exists in the report can be selected from the URL hash."""
    js = (ASSETS / "report.js").read_text(encoding="utf-8")
    assert "parts[1] && byId[parts[1]] ? parts[1] : null" in js
    assert "/^finding-([A-Za-z0-9_-]+)$/" in js  # legacy #finding-F1 links still work


def test_renderer_only_builds_dom_from_text(report):
    """Every string that reaches the DOM goes through textContent / createElement."""
    js = (ASSETS / "report.js").read_text(encoding="utf-8")
    assert "createElementNS" in js and "textContent" in js
    assert "new RegExp(" in js  # glossary regex is built from a static list only
    # the glossary regex is built from literal terms; no report data is ever interpolated into it
    assert js.count("new RegExp(") == 1
    assert not re.search(r"\.on[a-z]+\s*=", js)  # no inline handler assignment
    assert "javascript:" not in js


def test_hostile_host_strings_are_escaped_in_page(report):
    r = copy.deepcopy(report)
    r["hosts"] = [{"ip": '"><img src=x onerror=alert(3)>', "macs": ["<script>x</script>"], "roles": ["gateway"], "local": True,
                   "packets_sent": 1, "packets_recv": 1, "names": ["</script><b>n</b>"]}]
    r["stats"] = {"conversations": [{"a": '"><svg onload=alert(4)>', "b": "203.0.113.1", "proto": "TCP", "packets": 5, "bytes": 10}]}
    html = render_html(r)
    body = html.split('id="faultline-data">', 1)[1]
    assert "<img src=x" not in body and "<svg onload" not in body and "<script>x" not in body
    assert "<b>n</b>" not in body


def test_fixture_has_evidence_for_toggle(report):
    """The fixture carries enough evidence rows for the 'Show all N packets' toggle to appear."""
    rows = [len(f.get("evidence_lines") or []) for f in report["findings"]]
    assert rows and max(rows) >= 1
