"""Self-contained HTML report (also used as the web dashboard's report page).

Security model
--------------
Every string in a report is attacker-controlled (it came out of packets). So:

* the report is embedded as JSON inside ``<script type="application/json">``
  with ``<``, ``>``, ``&``, U+2028 and U+2029 escaped, so no byte sequence in
  the data can close the script element or be parsed as markup;
* the inline JS renders it with ``createElement``/``textContent`` only;
* a strict Content-Security-Policy pins the one inline script and the one
  inline stylesheet by SHA-256 hash; nothing else can run or load
  (``default-src 'none'``, no network, no forms, no base URI);
* the page makes no external requests and works offline from ``file://``.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import math
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import quote

ASSETS = Path(__file__).resolve().parent / "assets"

_FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">'
    '<rect x="1" y="1" width="22" height="22" rx="6" fill="#131c2a" stroke="#ece7dc" stroke-width="1.4"/>'
    '<path d="M3.5 13h4l2-6 3 10 2.4-7 1.6 3h4" fill="none" stroke="#ff6a5c" stroke-width="1.9" '
    'stroke-linecap="round" stroke-linejoin="round"/></svg>'
)
# data: URI (allowed by img-src data:) so the tab gets an icon without any request.
FAVICON_DATA_URI = "data:image/svg+xml," + quote(_FAVICON_SVG, safe="")

_JSON_ESCAPES = {
    "<": "\\u003c",
    ">": "\\u003e",
    "&": "\\u0026",
    " ": "\\u2028",
    " ": "\\u2029",
}


@dataclass(frozen=True)
class RenderedPage:
    html: str
    csp: str  # header form of the policy (the <meta> one plus frame-ancestors, which browsers ignore in <meta>)


@lru_cache(maxsize=None)
def _asset(name: str) -> str:
    return (ASSETS / name).read_text(encoding="utf-8")


def _sha256_source(text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


def _clean(value: Any, depth: int = 0) -> Any:
    """Make the report strictly JSON-safe (no NaN/Infinity, no exotic types)."""
    if depth > 40:
        return None
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, dict):
        return {str(k): _clean(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_clean(v, depth + 1) for v in value]
    if hasattr(value, "value") and isinstance(getattr(value, "value"), (str, int)):  # Enum
        return value.value
    if isinstance(value, (bytes, bytearray)):
        return None
    return str(value)


def embed_json(data: Any) -> str:
    """Serialise ``data`` for safe inclusion inside a ``<script>`` element."""
    text = json.dumps(_clean(data), ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    for ch, rep in _JSON_ESCAPES.items():
        text = text.replace(ch, rep)
    return text


def report_csp(script: str, style: str) -> str:
    return "; ".join([
        "default-src 'none'",
        f"script-src {_sha256_source(script)}",
        f"style-src {_sha256_source(style)}",
        "img-src data:",
        "font-src 'none'",
        "connect-src 'none'",
        "object-src 'none'",
        "media-src 'none'",
        "frame-src 'none'",
        "worker-src 'none'",
        "manifest-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
    ])


def build_page(report: dict, *, embedded_in_app: bool = False) -> RenderedPage:
    """Render the report and return the HTML together with its CSP."""
    if not isinstance(report, dict):
        raise TypeError("report must be a dict")
    style = _asset("report.css")
    script = _asset("report.js")
    if "</" in script or "</style" in style.lower():
        raise RuntimeError("report assets must not contain closing tags")
    csp = report_csp(script, style)
    header_csp = csp + "; frame-ancestors 'none'"
    capture = report.get("capture") if isinstance(report.get("capture"), dict) else {}
    name = str(capture.get("name") or "capture")[:120]
    status = (report.get("verdict") or {}).get("status") if isinstance(report.get("verdict"), dict) else None
    status_word = {
        "under_attack": "Under attack",
        "faulty": "Faulty",
        "minor_issues": "Minor issues",
        "healthy": "Healthy",
    }.get(status, "Report")
    title = html.escape(f"{status_word}: {name} | Faultline", quote=True)
    embedded_attr = ' data-embedded="1"' if embedded_in_app else ""
    page = (
        "<!DOCTYPE html>\n"
        f'<html lang="en"{embedded_attr}>\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        f'<meta http-equiv="Content-Security-Policy" content="{html.escape(csp, quote=True)}">\n'
        '<meta name="referrer" content="no-referrer">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta name="color-scheme" content="dark light">\n'
        '<meta name="generator" content="Faultline">\n'
        f'<link rel="icon" href="{html.escape(FAVICON_DATA_URI, quote=True)}">\n'
        f"<title>{title}</title>\n"
        f"<style>{style}</style>\n"
        "</head>\n"
        "<body>\n"
        '<div id="app"></div>\n'
        "<noscript><p>This report needs JavaScript to display. The raw data is "
        "embedded in this file as JSON.</p></noscript>\n"
        f'<script type="application/json" id="faultline-data">{embed_json(report)}</script>\n'
        f"<script>{script}</script>\n"
        "</body>\n"
        "</html>\n"
    )
    return RenderedPage(html=page, csp=header_csp)


def render_html(report: dict, *, embedded_in_app: bool = False) -> str:
    """Return one self-contained HTML document (inline CSS + JS, no external resources)."""
    return build_page(report, embedded_in_app=embedded_in_app).html


def write_html(report: dict, path: str | Path) -> Path:
    """Convenience for the CLI: write the standalone report to ``path``."""
    p = Path(path)
    p.write_text(render_html(report), encoding="utf-8")
    return p
