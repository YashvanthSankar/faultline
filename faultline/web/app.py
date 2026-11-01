"""Faultline local web dashboard.

A small Flask app that runs on the analyst's own machine: upload a capture
(or pick a bundled sample) and get the same self-contained HTML report the
CLI writes.

Security measures (the dashboard handles hostile files by design):

* binds to 127.0.0.1 by default and rejects unexpected Host headers
  (DNS-rebinding guard); a loud warning is printed for non-loopback binds;
* upload size cap (``MAX_CONTENT_LENGTH``) with a friendly 413 page;
* extension allowlist **and** magic-byte check (pcap LE/BE/ns, pcapng, gzip
  wrapping one of those) before anything is analysed;
* uploads are written with ``mkstemp`` into a private 0700 temp dir under a
  random name (never the client's filename) and deleted in ``finally``;
* the display name is sanitised (basename, no control/bidi chars, <= 80 chars);
* no report is ever written to disk;
* CSRF: a per-process random token (``secrets``), compared with
  ``hmac.compare_digest``; cross-origin ``Origin`` headers are refused;
* strict security headers on every response (CSP with nonces or hashes,
  nosniff, frame denial, no referrer, no-store, COOP/CORP);
* generic error pages: no tracebacks or paths, debug always off;
* at most two analyses run at once, so a browser tab cannot DoS the box;
* every secret is generated at runtime; nothing is hard-coded.
"""

from __future__ import annotations

import atexit
import gzip
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import shutil
import stat
import sys
import tempfile
import threading
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote, urlsplit

from flask import Flask, Response, abort, g, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

from faultline.report.html import FAVICON_DATA_URI, build_page

log = logging.getLogger("faultline.web")

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SAMPLES = REPO_ROOT / "samples"
ASSETS = Path(__file__).resolve().parents[1] / "report" / "assets"

# Longest first so ".pcap.gz" wins over ".gz"-less matches.
ALLOWED_EXTENSIONS = (".pcapng.gz", ".pcap.gz", ".cap.gz", ".pcapng", ".pcap", ".cap")
PCAP_MAGICS = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
GZIP_MAGIC = b"\x1f\x8b"
SENSITIVITIES = ("low", "normal", "high")
LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1"}
MAX_LABELS_BYTES = 1024 * 1024
MAX_DISPLAY_NAME = 80

AnalyzeFn = Callable[[str, Any, str], Any]


class UserError(Exception):
    """A problem the user can fix; ``message`` is safe to show."""

    def __init__(self, message: str, status: int = 400, title: str = "That did not work"):
        super().__init__(message)
        self.message = message
        self.status = status
        self.title = title


@dataclass
class _FallbackOptions:
    """Used only if the engine module is not importable (e.g. in isolated tests)."""

    redact: bool = False
    sensitivity: str = "normal"
    evidence: bool = True


# --------------------------------------------------------------------------- #
# Helpers (module level so they can be unit-tested)
# --------------------------------------------------------------------------- #


def sanitize_display_name(name: str | None) -> str:
    """Client filename -> safe label for display (never used as a path)."""
    raw = str(name or "")
    raw = raw.replace("\\", "/").rsplit("/", 1)[-1]
    cleaned = "".join(ch for ch in raw if unicodedata.category(ch)[0] != "C")  # Cc, Cf (bidi), Co, Cn, Cs
    cleaned = re.sub(r"\s+", " ", cleaned).strip().lstrip(".")
    if len(cleaned) > MAX_DISPLAY_NAME:
        ext = next((e for e in ALLOWED_EXTENSIONS if cleaned.lower().endswith(e)), "")
        cleaned = cleaned[: MAX_DISPLAY_NAME - len(ext) - 1] + "…" + ext
    return cleaned or "capture.pcap"


def allowed_extension(name: str) -> str | None:
    low = name.lower()
    return next((e for e in ALLOWED_EXTENSIONS if low.endswith(e)), None)


def sniff_capture(path: str | os.PathLike) -> str | None:
    """Return 'pcap', 'pcapng', 'pcap.gz' or 'pcapng.gz' if the magic bytes match, else None."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
        if head in PCAP_MAGICS:
            return "pcap"
        if head == PCAPNG_MAGIC:
            return "pcapng"
        if head[:2] == GZIP_MAGIC:
            with gzip.open(path, "rb") as gz:
                inner = gz.read(4)  # bounded read: bomb-safe
            if inner in PCAP_MAGICS:
                return "pcap.gz"
            if inner == PCAPNG_MAGIC:
                return "pcapng.gz"
    except (OSError, EOFError, ValueError, gzip.BadGzipFile):
        return None
    return None


def _is_loopback(host: str) -> bool:
    host = host.strip("[]")
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _host_only(hostport: str) -> str:
    hostport = (hostport or "").strip().lower()
    if hostport.startswith("["):
        return hostport[1: hostport.find("]")] if "]" in hostport else hostport
    if hostport.count(":") == 1:
        return hostport.split(":", 1)[0]
    return hostport


def _scrub(value: Any, needle: str, replacement: str, depth: int = 0) -> Any:
    """Replace any occurrence of the private temp path in report strings."""
    if depth > 40:
        return value
    if isinstance(value, str):
        return value.replace(needle, replacement) if needle in value else value
    if isinstance(value, dict):
        return {k: _scrub(v, needle, replacement, depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v, needle, replacement, depth + 1) for v in value]
    return value


def _default_analyze(path: str, options: Any, display_name: str) -> Any:
    from faultline.engine import analyze  # lazy: keeps the web layer importable on its own

    return analyze(path, options, display_name)


def _make_options(redact: bool, sensitivity: str, evidence: bool = True) -> Any:
    try:
        from faultline.engine import AnalyzeOptions  # type: ignore

        return AnalyzeOptions(redact=redact, sensitivity=sensitivity, evidence=evidence)
    except Exception:  # engine not available yet, or different signature
        return _FallbackOptions(redact=redact, sensitivity=sensitivity, evidence=evidence)


def _capture_error_type() -> type[BaseException] | None:
    try:
        from faultline.capture.reader import CaptureError

        return CaptureError
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Samples gallery
# --------------------------------------------------------------------------- #


def list_samples(samples_dir: Path) -> dict[str, Path]:
    """Allowlist of analysable samples: name -> path. Only regular files, no symlinks."""
    found: dict[str, Path] = {}
    for sub in ("", "malformed"):
        base = samples_dir / sub if sub else samples_dir
        try:
            entries = list(os.scandir(base))
        except OSError:
            continue
        for entry in entries:
            try:
                if not entry.is_file(follow_symlinks=False):
                    continue
            except OSError:
                continue
            if allowed_extension(entry.name) is None:
                continue
            name = f"{sub}/{entry.name}" if sub else entry.name
            found[name] = Path(entry.path)
    return found


def _badge(meta: dict, name: str) -> str:
    if name.startswith("malformed/"):
        return "corrupt"
    if meta.get("hostile_strings") is True or meta.get("hostile") is True or name == "xss_payload.pcap":
        return "hostile"
    if meta.get("clean") is True:
        return "clean"
    cats = set()
    for item in meta.get("expected") or []:
        if isinstance(item, dict) and isinstance(item.get("category"), str):
            cats.add(item["category"])
    for c in ("attack", "fault", "misconfig"):
        if c in cats:
            return c
    return "clean" if meta.get("expected") == [] else "sample"


def sample_gallery(samples_dir: Path) -> list[dict]:
    files = list_samples(samples_dir)
    labels: dict = {}
    lp = samples_dir / "labels.json"
    try:
        st = lp.lstat()
        if stat.S_ISREG(st.st_mode) and st.st_size <= MAX_LABELS_BYTES:
            data = json.loads(lp.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                labels = data
    except (OSError, ValueError):
        labels = {}
    order = {"attack": 0, "fault": 1, "misconfig": 2, "clean": 3, "sample": 4, "hostile": 5, "corrupt": 6}
    items = []
    for name in sorted(files):
        meta = labels.get(name) or labels.get(name.rsplit("/", 1)[-1]) or {}
        if not isinstance(meta, dict):
            meta = {}
        title = meta.get("title") if isinstance(meta.get("title"), str) else None
        story = meta.get("story") if isinstance(meta.get("story"), str) else ""
        if not title:
            stem = name.rsplit("/", 1)[-1]
            ext = allowed_extension(stem) or ""
            title = stem[: len(stem) - len(ext)].replace("_", " ").replace("-", " ").strip().capitalize() or stem
        try:
            size = files[name].stat().st_size
        except OSError:
            size = 0
        items.append({"name": name, "title": title[:120], "story": story[:400], "badge": _badge(meta, name), "size": size})
    items.sort(key=lambda it: (order.get(it["badge"], 9), it["title"].lower()))
    return items


# --------------------------------------------------------------------------- #
# App factory
# --------------------------------------------------------------------------- #


def create_app(*, max_upload_mb: int = 200, samples_dir: str | os.PathLike | None = None,
               analyze_fn: AnalyzeFn | None = None) -> Flask:
    app = Flask(__name__, static_folder=None)
    app.config.update(
        SECRET_KEY=secrets.token_bytes(32),  # generated per process, never stored
        MAX_CONTENT_LENGTH=int(max_upload_mb) * 1024 * 1024,
        MAX_FORM_MEMORY_SIZE=int(max_upload_mb) * 1024 * 1024,  # werkzeug counts in-memory file parts too; total is capped by MAX_CONTENT_LENGTH
        MAX_FORM_PARTS=50,
        JSON_SORT_KEYS=False,
        PROPAGATE_EXCEPTIONS=False,
        TRAP_HTTP_EXCEPTIONS=False,
        FAULTLINE_CSRF_TOKEN=secrets.token_urlsafe(32),
        FAULTLINE_ALLOWED_HOSTS=set(LOOPBACK_NAMES),  # None disables the Host check
    )
    app.debug = False
    app.jinja_env.autoescape = True

    samples_path = Path(samples_dir) if samples_dir is not None else DEFAULT_SAMPLES
    analyze = analyze_fn or _default_analyze
    slots = threading.BoundedSemaphore(2)
    state: dict[str, str | None] = {"tmpdir": None}
    tmp_lock = threading.Lock()
    base_css = (ASSETS / "report.css").read_text(encoding="utf-8")

    def private_tmpdir() -> str:
        with tmp_lock:
            d = state["tmpdir"]
            if d is None or not os.path.isdir(d):
                d = tempfile.mkdtemp(prefix="faultline-")  # created 0700
                os.chmod(d, 0o700)
                state["tmpdir"] = d
                atexit.register(shutil.rmtree, d, True)
            return d

    app.config["FAULTLINE_TMPDIR_GETTER"] = private_tmpdir

    # ---------------------------------------------------------------- guards
    @app.before_request
    def _guards():
        g.nonce = secrets.token_urlsafe(18)
        allowed = app.config.get("FAULTLINE_ALLOWED_HOSTS")
        if allowed is not None and _host_only(request.host) not in allowed:
            raise UserError("This address is not allowed. Open Faultline at http://127.0.0.1 instead.", 400, "Unknown host")
        if request.method == "POST":
            origin = request.headers.get("Origin")
            if origin and origin != "null":
                o = urlsplit(origin)
                if (o.netloc or "").lower() != (request.host or "").lower():
                    raise UserError("Requests from other websites are refused.", 403, "Request blocked")

    def check_csrf(supplied: str | None) -> None:
        expected = app.config["FAULTLINE_CSRF_TOKEN"]
        if not supplied or not hmac.compare_digest(supplied.encode("utf-8", "replace"), expected.encode("utf-8")):
            raise UserError("This form has expired or did not come from Faultline. Reload the page and try again.", 403, "Request blocked")

    # --------------------------------------------------------------- headers
    @app.after_request
    def _headers(resp: Response) -> Response:
        csp = getattr(g, "csp", None)
        if csp is None:
            nonce = getattr(g, "nonce", "")
            csp = (
                "default-src 'self'; "
                f"script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
                "img-src 'self' data:; font-src 'none'; connect-src 'self'; object-src 'none'; "
                "frame-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
            )
        h = resp.headers
        h["Content-Security-Policy"] = csp
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["Referrer-Policy"] = "no-referrer"
        h["Cache-Control"] = "no-store"
        h["Pragma"] = "no-cache"
        h["Cross-Origin-Opener-Policy"] = "same-origin"
        h["Cross-Origin-Resource-Policy"] = "same-origin"
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), usb=(), payment=()"
        return resp

    # ---------------------------------------------------------------- pages
    def page(template: str, code: int = 200, **ctx) -> Response:
        html = render_template(template, nonce=g.nonce, base_css=base_css, favicon=FAVICON_DATA_URI, **ctx)
        return Response(html, status=code, mimetype="text/html")

    def message(status: int, title: str, text: str) -> Response:
        if request.path.startswith("/api/"):
            return Response(json.dumps({"error": title, "message": text}), status=status, mimetype="application/json")
        return page("message.html", status, status=status, title=title, text=text)

    def report_response(report: dict) -> Response:
        rendered = build_page(report, embedded_in_app=True)
        g.csp = rendered.csp
        return Response(rendered.html, mimetype="text/html")

    # -------------------------------------------------------------- analysis
    def read_options(src) -> tuple[bool, str]:
        redact = str(src.get("redact", "")).lower() in ("1", "on", "true", "yes")
        sensitivity = str(src.get("sensitivity", "normal")).lower()
        if sensitivity not in SENSITIVITIES:
            sensitivity = "normal"
        return redact, sensitivity

    def run_analysis(path: str, display_name: str, redact: bool, sensitivity: str) -> dict:
        if not slots.acquire(blocking=False):
            raise UserError("Faultline is already analysing two captures. Wait for them to finish, then try again.", 503, "Busy")
        try:
            capture_error = _capture_error_type()
            try:
                result = analyze(path, _make_options(redact, sensitivity), display_name)
            except Exception as exc:
                if capture_error is not None and isinstance(exc, capture_error):
                    msg = str(exc).replace(path, display_name)
                    tmp = state["tmpdir"]
                    if tmp:
                        msg = msg.replace(tmp, "")
                    raise UserError(msg[:400] or "The capture could not be read.", 422, "This capture could not be read") from None
                raise
        finally:
            slots.release()
        report = result.to_dict() if hasattr(result, "to_dict") else result
        if not isinstance(report, dict):
            raise RuntimeError("analysis returned no report")
        report = _scrub(report, path, display_name)
        tmp = state["tmpdir"]
        if tmp:
            report = _scrub(report, tmp, "")
        return report

    def analyze_file(f, redact: bool, sensitivity: str, what: str = "capture") -> dict:
        """Write one uploaded FileStorage to a private temp file, validate it, analyse, delete."""
        if f is None or not f.filename:
            raise UserError(f"Choose a {what} file first.", 400, "No file selected")
        display = sanitize_display_name(f.filename)
        ext = allowed_extension(display)
        if ext is None:
            raise UserError("Faultline reads .pcap, .pcapng and .cap files, optionally gzip-compressed (.pcap.gz).", 400, "Unsupported file type")
        fd, path = tempfile.mkstemp(prefix="upload-", suffix=ext, dir=private_tmpdir())
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)  # mkstemp already uses 0600; be explicit
            with os.fdopen(fd, "wb") as out:
                shutil.copyfileobj(f.stream, out, 1024 * 1024)
            if os.path.getsize(path) == 0:
                raise UserError(f"The {what} file is empty.", 400, "Empty file")
            if sniff_capture(path) is None:
                raise UserError(f"The {what} file is not a packet capture. Faultline checks the first bytes of the file: it must be pcap, pcapng, or one of those compressed with gzip.", 400, "Not a capture file")
            return run_analysis(path, display, redact, sensitivity)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    def analyze_upload() -> dict:
        redact, sensitivity = read_options(request.form)
        return analyze_file(request.files.get("capture"), redact, sensitivity)

    # --------------------------------------------------------------- compare
    STATUS_WORDS = {"under_attack": "Under attack", "faulty": "Faulty", "minor_issues": "Minor issues", "healthy": "Healthy"}

    def _side(report: dict, name: str, link: str | None) -> dict:
        verdict = report.get("verdict") if isinstance(report.get("verdict"), dict) else {}
        status = verdict.get("status") if verdict.get("status") in STATUS_WORDS else "healthy"
        counts = verdict.get("counts") if isinstance(verdict.get("counts"), dict) else {}
        findings = []
        for f in report.get("findings") or []:
            if not isinstance(f, dict):
                continue
            cat = f.get("category") if f.get("category") in ("attack", "fault", "misconfig", "info") else "info"
            findings.append({"id": str(f.get("id", ""))[:12], "title": str(f.get("title", ""))[:200], "category": cat,
                             "severity_name": str(f.get("severity_name", ""))[:12], "summary": str(f.get("summary", ""))[:400]})
        score = verdict.get("score")
        capture = report.get("capture") if isinstance(report.get("capture"), dict) else {}
        top = None
        for f in report.get("findings") or []:
            if isinstance(f, dict) and f.get("category") in ("attack", "fault", "misconfig"):
                top = _top_finding(f)
                break
        return {
            "name": name, "link": link, "status": status, "word": STATUS_WORDS[status],
            "headline": str(verdict.get("headline") or "")[:300], "score": int(score) if isinstance(score, (int, float)) else None,
            "counts": {k: int(counts.get(k) or 0) for k in ("attack", "fault", "misconfig", "info")},
            "findings": findings[:40], "packets": capture.get("packets"), "top": top,
        }

    def _top_finding(f: dict) -> dict:
        """The evidence scoreboard of one finding, reduced to plain, bounded values for the template."""
        cat = f["category"]
        raw_scores = f.get("scores") if isinstance(f.get("scores"), dict) else {}
        scores = {}
        for k in ("attack", "fault", "misconfig"):
            v = raw_scores.get(k)
            scores[k] = round(max(0.0, float(v)), 1) if isinstance(v, (int, float)) and v == v else 0.0
        total = sum(scores.values())
        widths = {k: int(round(100 * v / total)) if total else 0 for k, v in scores.items()}
        indicators = []
        for i in (f.get("indicators") or [])[:40]:
            if not isinstance(i, dict):
                continue
            w = i.get("weight")
            indicators.append({"text": str(i.get("text", ""))[:300],
                               "supports": i.get("supports") if i.get("supports") in ("attack", "fault", "misconfig", "info") else "info",
                               "weight": max(0.0, min(3.0, float(w))) if isinstance(w, (int, float)) and w == w else 0.0})
        indicators.sort(key=lambda i: -i["weight"])
        alternatives = []
        for a in (f.get("alternatives") or [])[:6]:
            if isinstance(a, dict):
                alternatives.append({"title": str(a.get("title", ""))[:120], "why_not": str(a.get("why_not", ""))[:400],
                                     "category": a.get("category") if a.get("category") in ("attack", "fault", "misconfig", "info") else "info"})
        names = {"attack": "Attack", "fault": "Fault", "misconfig": "Misconfiguration"}
        others = [f"{scores[k]:.1f} for {names[k].lower()}" for k in ("attack", "fault", "misconfig") if k != cat and scores[k] > 0]
        lead = f"{names[cat]} wins with {scores[cat]:.1f} points of evidence" + (
            ", against " + " and ".join(others) + "." if others else ". Nothing pointed anywhere else.")
        conf = f.get("confidence")
        return {
            "id": str(f.get("id", ""))[:12], "title": str(f.get("title", ""))[:200], "category": cat,
            "severity_name": str(f.get("severity_name", ""))[:12],
            "confidence": int(round(100 * max(0.0, min(1.0, float(conf))))) if isinstance(conf, (int, float)) and conf == conf else None,
            "explanation": str(f.get("explanation") or f.get("summary") or "")[:600],
            "scores": scores, "widths": widths, "total": total, "lead": lead,
            "indicators": indicators, "alternatives": alternatives,
        }

    def _finding_brief(f: dict) -> dict:
        cat = f.get("category") if f.get("category") in ("attack", "fault", "misconfig", "info") else "info"
        return {"id": str(f.get("id", ""))[:12], "title": str(f.get("title", ""))[:200], "category": cat,
                "severity_name": str(f.get("severity_name", ""))[:12]}

    def compare_response(ra: dict, name_a: str, link_a: str | None, rb: dict, name_b: str, link_b: str | None,
                         before_after: bool = False) -> Response:
        """Two verdicts side by side. ``before_after`` adds the "what changed from A to B" diff;
        otherwise the page contrasts the top finding of each side (same symptom, different evidence)."""
        a, b = _side(ra, name_a, link_a), _side(rb, name_b, link_b)
        diff = None
        if before_after and (a["findings"] or b["findings"]):
            try:
                from faultline.diff import diff_reports

                raw = diff_reports(ra, rb)
                diff = {
                    "fixed": [_finding_brief(f) for f in raw.get("fixed", [])],
                    "new": [_finding_brief(f) for f in raw.get("new", [])],
                    "persisting": [{"before": _finding_brief(p["before"]), "after": _finding_brief(p["after"]),
                                    "trend": p.get("trend") if p.get("trend") in ("better", "same", "worse") else "same"}
                                   for p in raw.get("persisting", [])],
                    "conclusion": str(raw.get("conclusion") or "")[:300],
                }
            except Exception:  # the diff is a bonus; never fail the page over it
                log.warning("diff_reports failed for compare view", exc_info=True)
                diff = None
        return page("compare.html", a=a, b=b, diff=diff)

    # ---------------------------------------------------------------- routes
    @app.get("/")
    def index():
        return page("index.html", samples=sample_gallery(samples_path), csrf_token=app.config["FAULTLINE_CSRF_TOKEN"],
                    max_upload_mb=int(max_upload_mb))

    @app.post("/analyze")
    def analyze_form():
        check_csrf(request.form.get("csrf_token"))
        return report_response(analyze_upload())

    @app.post("/api/analyze")
    def analyze_api():
        check_csrf(request.headers.get("X-Faultline-Token"))
        return Response(json.dumps(analyze_upload(), ensure_ascii=False, allow_nan=False, default=str),
                        mimetype="application/json")

    @app.get("/sample/<path:name>")
    def sample(name: str):
        allow = list_samples(samples_path)
        target = allow.get(name)
        if target is None:
            abort(404)
        redact, sensitivity = read_options(request.args)
        return report_response(run_analysis(str(target), name, redact, sensitivity))

    @app.get("/compare")
    def compare_samples():
        allow = list_samples(samples_path)
        name_a, name_b = request.args.get("a", ""), request.args.get("b", "")
        ta, tb = allow.get(name_a), allow.get(name_b)
        if ta is None or tb is None:
            abort(404)
        redact, sensitivity = read_options(request.args)
        qs = ("?redact=1" if redact else "") + (("&" if redact else "?") + "sensitivity=" + sensitivity if sensitivity != "normal" else "")
        ra = run_analysis(str(ta), name_a, redact, sensitivity)
        rb = run_analysis(str(tb), name_b, redact, sensitivity)
        return compare_response(ra, name_a, "/sample/" + quote(name_a) + qs, rb, name_b, "/sample/" + quote(name_b) + qs,
                                before_after=request.args.get("mode") == "diff")

    @app.post("/compare")
    def compare_upload():
        check_csrf(request.form.get("csrf_token"))
        redact, sensitivity = read_options(request.form)
        fa, fb = request.files.get("capture_a"), request.files.get("capture_b")
        if fa is None or not fa.filename or fb is None or not fb.filename:
            raise UserError("Choose two capture files to compare.", 400, "Two files needed")
        ra = analyze_file(fa, redact, sensitivity, "first")
        rb = analyze_file(fb, redact, sensitivity, "second")
        return compare_response(ra, sanitize_display_name(fa.filename), None, rb, sanitize_display_name(fb.filename), None,
                                before_after=request.form.get("mode", "diff") != "contrast")

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok")

    # ---------------------------------------------------------------- errors
    @app.errorhandler(UserError)
    def _user_error(e: UserError):
        return message(e.status, e.title, e.message)

    @app.errorhandler(HTTPException)
    def _http_error(e: HTTPException):
        code = e.code or 500
        if code == 413:
            return message(413, "File too large", f"Captures up to {int(max_upload_mb)} MB can be analysed here. "
                           "For bigger files, use the command line: faultline analyze big.pcap")
        if code == 404:
            return message(404, "Not found", "There is nothing at this address.")
        if code == 405:
            return message(405, "Not allowed", "This address does not accept that kind of request.")
        return message(code, "Request not accepted", "The request could not be processed.")

    @app.errorhandler(Exception)
    def _crash(e: Exception):
        log.error("unhandled error during %s %s: %s", request.method, request.path, type(e).__name__, exc_info=e)
        return message(500, "Something went wrong", "Faultline hit an internal error while handling this request. "
                       "Nothing was saved. Try again, or run the command-line tool for details.")

    return app


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def run(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True, **app_kwargs) -> None:
    app = create_app(**app_kwargs)
    if not _is_loopback(host):
        print(
            "\n  WARNING: Faultline is listening on %s, not just this computer.\n"
            "  Anyone who can reach this address can upload files to it and read the reports.\n"
            "  Use the default (127.0.0.1) unless you really need remote access.\n" % host,
            file=sys.stderr,
        )
        app.config["FAULTLINE_ALLOWED_HOSTS"] = None  # remote clients use arbitrary host names
    url_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    url = f"http://{('[' + url_host + ']') if ':' in url_host else url_host}:{port}/"
    print(f"  Faultline dashboard: {url}  (Ctrl+C to stop)")
    print(f"  API token for POST /api/analyze (header X-Faultline-Token): {app.config['FAULTLINE_CSRF_TOKEN']}")
    if open_browser:
        import webbrowser

        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":  # pragma: no cover
    run()
