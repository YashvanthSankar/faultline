"""Application layer: cleartext credentials, TLS handshake failures, deprecated
TLS versions, HTTP errors (server faults, password guessing, content scans).

Privacy: credentials are never available here (the decoder only says *that*
a login happened and with which protocol), and every string copied from a
packet (SNI, Host, path) is attacker-controlled, so it is stripped of control
characters and truncated before it goes into a finding.

Discriminators
--------------
* Cleartext login = misconfiguration (risk), but many separate logins from
  one client to one server within a minute = password guessing (T1110).
* TLS alerts: the *sender* matters. A client sending unknown_ca /
  bad_certificate rejects the server's certificate (self-signed, missing
  intermediate, inspection proxy, or MITM); when many unrelated servers fail
  the same way at once, something in the middle is re-signing traffic.
  A server sending handshake_failure / protocol_version means no common
  version or cipher (misconfiguration).
* HTTP: 5xx = server-side fault. 401/403 bursts on one or two URLs at a high,
  irregular rate with no successes = brute force; the same request repeating
  at a steady interval = an app with a stale saved password. Many 404s over
  many *different top-level* names = wordlist content scan; many 404s under
  one folder = a broken page.
"""

from __future__ import annotations

from collections import Counter, deque

from ..context import is_private
from .base import (
    AnalysisContext, BoundedDict, Category, Detector, Evidence, Finding, Indicator, Packet,
    Severity, Variant, fmt_pct, plural, register,
)

BRUTE_WINDOW = 60.0
BRUTE_HTTP = 20  # 401/403 from one client to one server within BRUTE_WINDOW
BRUTE_CONNS = 15  # separate cleartext logins (connections) within BRUTE_WINDOW
BRUTE_PKTS = 30  # cleartext credential packets within BRUTE_WINDOW (protocols with one login per message)
SCAN_404 = 50
HTTP_5XX = 3
HTTP_5XX_RATIO = 0.10

CRED_PORTS = {21: "FTP", 23: "Telnet", 25: "SMTP", 80: "HTTP", 110: "POP3", 143: "IMAP", 587: "SMTP", 8080: "HTTP",
              8000: "HTTP", 2323: "Telnet"}
CRED_FIX = {
    "FTP": ["Replace FTP with SFTP (file transfer over SSH) or FTPS (FTP over TLS); most servers support one of them.",
            "Disable plain FTP logins on the server (e.g. vsftpd `ssl_enable=YES`, `force_local_logins_ssl=YES`)."],
    "Telnet": ["Turn off Telnet on the device and use SSH instead (on network gear: `transport input ssh`).",
               "If the device cannot do SSH, put it on a separate management network only admins can reach."],
    "HTTP Basic": ["Serve the site over HTTPS only (redirect port 80 to 443) so the login header is encrypted.",
                   "Prefer a proper login form or token over HTTP Basic, and enable HSTS."],
    "POP3": ["Switch the mail client to POP3S (port 995) or STARTTLS, and disable plain-text login on the server."],
    "IMAP": ["Switch the mail client to IMAPS (port 993) or STARTTLS, and disable plain-text login on the server."],
    "SMTP AUTH": ["Send mail through port 587 with STARTTLS (or 465 with TLS) and refuse AUTH before TLS on the server."],
}
LOGIN_PROTOCOLS = {"FTP", "Telnet", "HTTP Basic", "POP3", "IMAP", "SMTP AUTH"}

TLS_VERSIONS = {0x0002: "SSL 2.0", 0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2",
                0x0304: "TLS 1.3"}
TLS_PORTS = {443, 465, 563, 636, 853, 989, 990, 992, 993, 994, 995, 5061, 8443}

# description -> (name, plain explanation, category, is_certificate_problem)
ALERTS = {
    10: ("unexpected_message", "one side received a message out of order: a software bug or a broken middlebox",
         Category.FAULT, False),
    20: ("bad_record_mac", "data was corrupted in transit or the two sides disagree on keys", Category.FAULT, False),
    21: ("decryption_failed", "data could not be decrypted", Category.FAULT, False),
    22: ("record_overflow", "a message was too large", Category.FAULT, False),
    40: ("handshake_failure", "the two sides could not agree on a common encryption method (cipher)",
         Category.MISCONFIG, False),
    41: ("no_certificate", "a certificate was required but not sent", Category.MISCONFIG, True),
    42: ("bad_certificate", "the certificate is damaged or does not match", Category.MISCONFIG, True),
    43: ("unsupported_certificate", "the certificate type is not supported", Category.MISCONFIG, True),
    44: ("certificate_revoked", "the certificate was cancelled (revoked) by whoever issued it", Category.MISCONFIG, True),
    45: ("certificate_expired", "the website's certificate has expired", Category.MISCONFIG, True),
    46: ("certificate_unknown", "the certificate was rejected for an unspecified reason (often an untrusted or "
         "self-signed certificate)", Category.MISCONFIG, True),
    47: ("illegal_parameter", "one side sent an invalid setting", Category.MISCONFIG, False),
    48: ("unknown_ca", "the device doesn't trust who signed the certificate, often a corporate/antivirus inspection "
         "proxy or a man-in-the-middle", Category.MISCONFIG, True),
    49: ("access_denied", "the server refused the client's certificate", Category.MISCONFIG, True),
    50: ("decode_error", "a message could not be understood", Category.FAULT, False),
    51: ("decrypt_error", "a signature or key check failed", Category.FAULT, False),
    70: ("protocol_version", "the two sides support no common TLS version (one is too old or too strict)",
         Category.MISCONFIG, False),
    71: ("insufficient_security", "the server demands stronger encryption than the client offered",
         Category.MISCONFIG, False),
    80: ("internal_error", "the other side had an internal software error", Category.FAULT, False),
    86: ("inappropriate_fallback", "a connection was retried with a weaker version than both support (possible "
         "downgrade attempt)", Category.MISCONFIG, False),
    109: ("missing_extension", "a required TLS feature was missing", Category.MISCONFIG, False),
    110: ("unsupported_extension", "an unsupported TLS feature was used", Category.MISCONFIG, False),
    112: ("unrecognized_name", "the server does not host the requested site name (SNI)", Category.MISCONFIG, False),
    113: ("bad_certificate_status_response", "the certificate's revocation status could not be confirmed",
          Category.MISCONFIG, True),
    115: ("unknown_psk_identity", "the pre-shared key is unknown", Category.MISCONFIG, False),
    116: ("certificate_required", "the server requires a client certificate", Category.MISCONFIG, True),
    120: ("no_application_protocol", "the two sides support no common application protocol (ALPN)",
          Category.MISCONFIG, False),
}
BENIGN_ALERTS = {0, 90, 100}  # close_notify, user_canceled, no_renegotiation (warnings)
TRUST_ALERTS = {42, 46, 48}

HTTP_5XX_TEXT = {
    500: "the web application crashed while handling the request (a bug or a broken dependency)",
    501: "the server does not support the requested feature",
    502: "a proxy/load balancer could not get a valid answer from the application server behind it",
    503: "the server is overloaded or in maintenance and refused to serve",
    504: "a proxy/load balancer gave up waiting for the application server (it is too slow or down)",
}


def clean(s, n: int = 100) -> str:
    """Untrusted packet text -> safe plain text (no control characters, <= n chars)."""
    if s is None:
        return ""
    s = "".join(ch if ch.isprintable() else "?" for ch in str(s)[: n + 16])
    return s if len(s) <= n else s[: n - 3] + "..."


def _norm_version(v: int) -> int | None:
    if v is None:
        return None
    if (v & 0x0F0F) == 0x0A0A:
        return None  # GREASE
    if (v >> 8) == 0x7F or v == 0xFB1A:
        return 0x0304  # TLS 1.3 drafts
    return v


def _vname(v: int | None) -> str:
    return TLS_VERSIONS.get(v, f"0x{v:04x}") if v is not None else "unknown"


class _Cred:
    __slots__ = ("proto", "server", "count", "ev", "clients", "conns", "first", "last", "win_conns", "win_pkts",
                 "peak_conns", "peak_pkts", "peak_client")

    def __init__(self, proto: str, server: str) -> None:
        self.proto, self.server = proto, server
        self.count = 0
        self.ev = Evidence()
        self.clients: Counter = Counter()
        self.conns: set = set()
        self.first = self.last = None
        self.win_conns: dict[str, deque] = {}
        self.win_pkts: dict[str, deque] = {}
        self.peak_conns = self.peak_pkts = 0
        self.peak_client = None


class _TlsFail:
    __slots__ = ("server", "count", "descs", "senders", "clients", "snis", "ev", "first", "last")

    def __init__(self, server: str) -> None:
        self.server = server
        self.count = 0
        self.descs: Counter = Counter()
        self.senders: Counter = Counter()  # (desc, "client"|"server")
        self.clients: set = set()
        self.snis: set = set()
        self.ev = Evidence()
        self.first = self.last = None


class _OldTls:
    __slots__ = ("server", "negotiated", "offered", "clients", "snis", "ev")

    def __init__(self, server: str) -> None:
        self.server = server
        self.negotiated: Counter = Counter()  # versions the server picked
        self.offered: Counter = Counter()  # max versions clients offered (when < 1.2)
        self.clients: set = set()
        self.snis: set = set()
        self.ev = Evidence()


class _HttpSrv:
    __slots__ = ("server", "responses", "s5", "s4", "paths5", "names", "clients", "ev5", "ev4", "first5", "last5")

    def __init__(self, server: str) -> None:
        self.server = server
        self.responses = 0
        self.s5: Counter = Counter()
        self.s4: Counter = Counter()
        self.paths5: Counter = Counter()
        self.names: Counter = Counter()
        self.clients: set = set()
        self.ev5 = Evidence()
        self.ev4 = Evidence()
        self.first5 = self.last5 = None


class _ClientSrv:
    __slots__ = ("total", "ok", "c401", "c403", "c404", "auth_win", "auth_peak", "auth_times", "paths_auth",
                 "nf_win", "nf_peak", "paths_404", "tops_404", "ev_auth", "ev_404", "names")

    def __init__(self) -> None:
        self.total = self.ok = self.c401 = self.c403 = self.c404 = 0
        self.auth_win: deque = deque()
        self.auth_peak = 0
        self.auth_times: list[float] = []  # first 200, for regularity
        self.paths_auth: Counter = Counter()
        self.nf_win: deque = deque()
        self.nf_peak = 0
        self.paths_404: set = set()
        self.tops_404: set = set()
        self.ev_auth = Evidence()
        self.ev_404 = Evidence()
        self.names: Counter = Counter()


def _window_add(dq: deque, t: float, width: float, cap: int = 5000) -> int:
    dq.append(t)
    while dq and dq[0] < t - width:
        dq.popleft()
    while len(dq) > cap:
        dq.popleft()
    return len(dq)


def _top_segment(path: str) -> str:
    p = (path or "/").lstrip("/")
    return p.split("/", 1)[0].lower()[:40]


@register
class AppDetector(Detector):
    name = "app"

    def __init__(self) -> None:
        self.creds: BoundedDict = BoundedDict(2_000)
        self.hellos: BoundedDict = BoundedDict(100_000)  # (client, cport, server, sport) -> sni
        self.tls_fail: BoundedDict = BoundedDict(5_000)
        self.old_tls: BoundedDict = BoundedDict(5_000)
        self.reqs: BoundedDict = BoundedDict(100_000)  # flow -> deque[(method, host, path)]
        self.http: BoundedDict = BoundedDict(10_000)
        self.pairs: BoundedDict = BoundedDict(20_000)  # (client, server) -> _ClientSrv
        self.tls_alerts_total = 0

    # ------------------------------------------------------------------ #
    def on_packet(self, pkt: Packet, ctx: AnalysisContext) -> None:
        if pkt.src is None or pkt.dst is None:
            return
        if pkt.cred:
            self._cred(pkt)
        if pkt.tls is not None and pkt.tcp is not None:
            self._tls(pkt)
        if pkt.http is not None and pkt.tcp is not None:
            self._http(pkt)

    # -- credentials ----------------------------------------------------- #
    def _cred(self, pkt: Packet) -> None:
        proto = clean(pkt.cred, 24)
        sport, dport = pkt.sport, pkt.dport
        if dport in CRED_PORTS or sport not in CRED_PORTS:
            server, sp, client, cp = pkt.dst, dport, pkt.src, sport
        else:
            server, sp, client, cp = pkt.src, sport, pkt.dst, dport
        key = (proto, server, sp)
        c = self.creds.get(key)
        if c is None:
            c = self.creds[key] = _Cred(proto, f"{server}:{sp}" if sp is not None else server)
        t = pkt.ts or 0.0
        c.count += 1
        c.ev.add(pkt)
        c.first = t if c.first is None else min(c.first, t)
        c.last = t if c.last is None else max(c.last, t)
        if len(c.clients) < 256 or client in c.clients:
            c.clients[client] += 1
        conn = (client, cp)
        if conn not in c.conns and len(c.conns) < 8192:
            c.conns.add(conn)
            if len(c.win_conns) < 256 or client in c.win_conns:
                n = _window_add(c.win_conns.setdefault(client, deque()), t, BRUTE_WINDOW)
                if n > c.peak_conns:
                    c.peak_conns, c.peak_client = n, client
        if proto in ("FTP", "POP3", "IMAP", "SMTP AUTH") and (len(c.win_pkts) < 256 or client in c.win_pkts):
            n = _window_add(c.win_pkts.setdefault(client, deque()), t, BRUTE_WINDOW)
            if n > c.peak_pkts:
                c.peak_pkts = n
                if c.peak_client is None or n >= BRUTE_PKTS:
                    c.peak_client = client

    # -- TLS ------------------------------------------------------------- #
    def _tls(self, pkt: Packet) -> None:
        tl = pkt.tls
        src, dst, sport, dport = pkt.src, pkt.dst, pkt.sport, pkt.dport
        hs = tl.handshake_types or []
        if 1 in hs:  # ClientHello
            sni = clean(tl.sni) if tl.sni else ""
            self.hellos[(src, sport, dst, dport)] = sni
            sv = [x for x in (_norm_version(v) for v in (tl.supported_versions or [])) if x is not None]
            maxv = max(sv) if sv else tl.client_version
            if maxv is not None and maxv < 0x0303:
                o = self._old(f"{dst}:{dport}")
                o.offered[maxv] += 1
                if len(o.clients) < 256:
                    o.clients.add(src)
                if sni and len(o.snis) < 32:
                    o.snis.add(sni)
                o.ev.add(pkt)
        if 2 in hs:  # ServerHello
            sv = [x for x in (_norm_version(v) for v in (tl.supported_versions or [])) if x is not None]
            neg = sv[0] if sv else (tl.client_version or tl.record_version or None)
            if neg is not None and 0 < neg < 0x0303:
                o = self._old(f"{src}:{sport}")
                o.negotiated[neg] += 1
                if len(o.clients) < 256:
                    o.clients.add(dst)
                sni = self.hellos.get((dst, dport, src, sport))
                if sni and len(o.snis) < 32:
                    o.snis.add(sni)
                o.ev.add(pkt)
        if tl.alerts:
            for level, desc in tl.alerts[:8]:
                if desc in BENIGN_ALERTS and level != 2:
                    continue
                if desc == 0:
                    continue
                self._alert(pkt, level, desc)

    def _old(self, server: str) -> _OldTls:
        o = self.old_tls.get(server)
        if o is None:
            o = self.old_tls[server] = _OldTls(server)
        return o

    def _alert(self, pkt: Packet, level, desc) -> None:
        src, dst, sport, dport = pkt.src, pkt.dst, pkt.sport, pkt.dport
        sni = self.hellos.get((src, sport, dst, dport))
        if sni is not None:
            sender, server, client = "client", f"{dst}:{dport}", src
        else:
            sni = self.hellos.get((dst, dport, src, sport))
            if sni is not None:
                sender, server, client = "server", f"{src}:{sport}", dst
            elif sport in TLS_PORTS or (sport or 0) < (dport or 0):
                sender, server, client = "server", f"{src}:{sport}", dst
            else:
                sender, server, client = "client", f"{dst}:{dport}", src
        self.tls_alerts_total += 1
        f = self.tls_fail.get(server)
        if f is None:
            f = self.tls_fail[server] = _TlsFail(server)
        t = pkt.ts or 0.0
        f.count += 1
        f.descs[desc] += 1
        f.senders[(desc, sender)] += 1
        if len(f.clients) < 256:
            f.clients.add(client)
        if sni and len(f.snis) < 16:
            f.snis.add(sni)
        f.ev.add(pkt)
        f.first = t if f.first is None else min(f.first, t)
        f.last = t if f.last is None else max(f.last, t)

    # -- HTTP ------------------------------------------------------------ #
    def _http(self, pkt: Packet) -> None:
        h = pkt.http
        src, dst, sport, dport = pkt.src, pkt.dst, pkt.sport, pkt.dport
        t = pkt.ts or 0.0
        if h.is_request:
            key = (src, sport, dst, dport)
            q = self.reqs.get(key)
            if q is None:
                q = self.reqs[key] = deque(maxlen=8)
            q.append((clean(h.method, 12), clean(h.host, 80), clean(h.path or "/", 100)))
            return
        status = h.status
        if not isinstance(status, int):
            return
        q = self.reqs.get((dst, dport, src, sport))
        req = q.popleft() if q else None
        server = f"{src}:{sport}"
        s = self.http.get(server)
        if s is None:
            s = self.http[server] = _HttpSrv(server)
        s.responses += 1
        if len(s.clients) < 512:
            s.clients.add(dst)
        method, host, path = req if req else ("", "", "")
        if host and (len(s.names) < 16 or host in s.names):
            s.names[host] += 1
        if 500 <= status <= 599:
            s.s5[status] += 1
            s.ev5.add(pkt)
            s.first5 = t if s.first5 is None else min(s.first5, t)
            s.last5 = t if s.last5 is None else max(s.last5, t)
            if path and (len(s.paths5) < 64 or path in s.paths5):
                s.paths5[f"{method} {path}".strip()] += 1
        elif 400 <= status <= 499:
            s.s4[status] += 1
            s.ev4.add(pkt)
        cs = self.pairs.get((dst, server))
        if cs is None:
            cs = self.pairs[(dst, server)] = _ClientSrv()
        cs.total += 1
        if host and len(cs.names) < 8:
            cs.names[host] += 1
        if 200 <= status <= 399:
            cs.ok += 1
        elif status in (401, 403):
            if status == 401:
                cs.c401 += 1
            else:
                cs.c403 += 1
            n = _window_add(cs.auth_win, t, BRUTE_WINDOW)
            cs.auth_peak = max(cs.auth_peak, n)
            if len(cs.auth_times) < 200:
                cs.auth_times.append(t)
            if len(cs.paths_auth) < 64 or path in cs.paths_auth:
                cs.paths_auth[path or "?"] += 1
            cs.ev_auth.add(pkt)
        elif status == 404:
            cs.c404 += 1
            n = _window_add(cs.nf_win, t, BRUTE_WINDOW)
            cs.nf_peak = max(cs.nf_peak, n)
            if path and len(cs.paths_404) < 2048:
                cs.paths_404.add(path)
                if len(cs.tops_404) < 512:
                    cs.tops_404.add(_top_segment(path))
            cs.ev_404.add(pkt)

    # ------------------------------------------------------------------ #
    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        sc = ctx.config.scale
        out: list[Finding] = []
        for c in sorted(self.creds.values(), key=lambda x: -x.count)[:50]:
            out.append(self._cred_finding(c, sc))
        trust_servers = {s for s, f in self.tls_fail.items()
                         if any(d in TRUST_ALERTS and who == "client" for (d, who) in f.senders)}
        for f in sorted(self.tls_fail.values(), key=lambda x: -x.count)[:50]:
            r = self._tls_finding(f, trust_servers)
            if r is not None:
                out.append(r)
        for o in sorted(self.old_tls.values(), key=lambda x: -(sum(x.negotiated.values()) * 10 + sum(x.offered.values())))[:25]:
            out.append(self._old_finding(o))
        explained: set[str] = set()  # servers whose 4xx are explained by a brute force / content scan
        for (client, server), cs in list(self.pairs.items()):
            for r in (self._brute_finding(client, server, cs, sc), self._dirscan_finding(client, server, cs, sc)):
                if r is not None:
                    out.append(r)
                    explained.add(server)
        for s in sorted(self.http.values(), key=lambda x: -sum(x.s5.values()))[:50]:
            r = self._http5_finding(s)
            if r is not None:
                out.append(r)
            if s.server not in explained:
                r = self._http4_finding(s)
                if r is not None:
                    out.append(r)
        return out

    # -- credential finding ---------------------------------------------- #
    def _cred_finding(self, c: _Cred, sc: float) -> Finding:
        proto = c.proto
        server_ip = c.server.rsplit(":", 1)[0] if c.server.count(":") == 1 else c.server
        clients = [ip for ip, _ in c.clients.most_common(10)]
        nconn = len(c.conns)
        public = not is_private(server_ip)
        login = proto in LOGIN_PROTOCOLS
        ind = [Indicator(f"{plural(c.count, 'login message')} for {proto} to {c.server} travelled without "
                         f"encryption ({plural(nconn, 'session')}, {plural(len(clients), 'client')})",
                         Category.MISCONFIG, 2.5),
               Indicator("Risk: anyone who can see this traffic (shared Wi-Fi, a compromised switch, the ISP) can read "
                         "the password as plain text", Category.MISCONFIG, 1.0)]
        if public:
            ind.append(Indicator(f"The server {server_ip} is on the internet, so the password crossed networks "
                                 "you do not control", Category.MISCONFIG, 1.0))
        brute_c = c.peak_conns >= max(5, round(BRUTE_CONNS * sc))
        brute_p = c.peak_pkts >= max(10, round(BRUTE_PKTS * sc))
        if brute_c or brute_p:
            what = (f"{c.peak_conns} separate logins" if brute_c else f"{c.peak_pkts} login messages")
            ind.append(Indicator(f"{c.peak_client} made {what} to {c.server} within {int(BRUTE_WINDOW)} s: someone is "
                                 "guessing passwords, not logging in once", Category.ATTACK, 2.5))
        sev = Severity.HIGH if login else Severity.MEDIUM
        fixes = list(CRED_FIX.get(proto, ["Switch this service to an encrypted version (TLS/SSH)."]))
        fixes.append(f"Change the passwords that were used here: they must be considered exposed "
                     f"({plural(len(clients), 'device')} logged in: {', '.join(clients[:3])}).")
        fixes.append("Check the server's logs for logins from unknown addresses.")
        title = f"Passwords are being sent unencrypted ({proto} to {c.server})"
        summary = (f"{plural(nconn, 'login')} to the {proto} server {c.server} sent the username and password as "
                   "readable text.")
        expl = (f"{proto} is an old protocol that sends your login exactly as typed, without encryption. Anyone who "
                "can capture traffic on the way (as this capture just did) could read and reuse the password. "
                "Faultline only detected that a login happened; it never stores or shows the password itself.")
        cause = f"The {proto} service on {c.server} accepts logins without TLS/SSH encryption."
        mitre_bf = "T1110 Brute Force"
        variants = {Category.MISCONFIG: Variant(title, summary, expl, cause, fixes, severity=sev,
                                                analogy="Like writing your PIN on a postcard: every postman on the "
                                                        "way can read it.")}
        if brute_c or brute_p:
            variants[Category.ATTACK] = Variant(
                f"Password guessing against {proto} on {c.server}",
                f"{c.peak_client} tried to log in to {c.server} {max(c.peak_conns, c.peak_pkts)} times within a minute.",
                "Someone is trying password after password against this login (a brute-force attack). Because the "
                "protocol is unencrypted, any password that works is also visible to anyone on the path.",
                f"A password-guessing tool on {c.peak_client}.",
                [f"Block {c.peak_client} at the firewall and check if it is one of your devices (malware?).",
                 "Enable login rate-limiting / lockout (e.g. fail2ban) on the server.",
                 "Change the account passwords and move the service to an encrypted protocol."] + fixes[:1],
                mitre=mitre_bf, severity=Severity.HIGH,
                analogy="Like someone trying every key on a giant key ring, one after another, on your front door.")
        f = Finding(kind="cred.cleartext", category=Category.MISCONFIG, severity=sev, title=title, summary=summary,
                    explanation=expl, cause=cause, fix=fixes,
                    technical=(f"{c.count} packets flagged as {proto} credentials to {c.server} over {nconn} TCP "
                               f"sessions from {len(c.clients)} clients ({', '.join(clients[:5])}) between "
                               f"{(c.last or 0) - (c.first or 0):.1f} s; peak {c.peak_conns} sessions / {c.peak_pkts} "
                               f"credential packets per {int(BRUTE_WINDOW)} s from one client. Secret not retained."),
                    analogy=variants[Category.MISCONFIG].analogy,
                    hosts=[server_ip] + clients[:9],
                    metrics={"protocol": proto, "server": c.server, "packets": c.count, "sessions": nconn,
                             "clients": clients, "server_public": public, "peak_sessions_per_min": c.peak_conns,
                             "peak_packets_per_min": c.peak_pkts},
                    indicators=ind, variants=variants)
        return c.ev.apply(f)

    # -- TLS failure finding --------------------------------------------- #
    def _tls_finding(self, f: _TlsFail, trust_servers: set) -> Finding | None:
        cert = sum(n for d, n in f.descs.items() if ALERTS.get(d, ("", "", Category.FAULT, False))[3])
        if f.count < 2 and cert < 1:
            return None
        top_desc = f.descs.most_common(1)[0][0]
        name, plain, cat, _ = ALERTS.get(top_desc, (f"alert {top_desc}", "the connection was refused for a "
                                                     "technical reason", Category.FAULT, False))
        snis = sorted(f.snis)[:5]
        site = snis[0] if snis else f.server
        clients = sorted(f.clients)[:10]
        ind: list[Indicator] = []
        for d, n in f.descs.most_common(5):
            nm, pl, c, _ = ALERTS.get(d, (f"alert {d}", "an unrecognised TLS error", Category.FAULT, False))
            who = [w for (dd, w), _ in f.senders.items() if dd == d]
            ind.append(Indicator(f"{plural(n, 'TLS alert')} '{nm}' sent by the {'/'.join(sorted(set(who)))}: {pl}",
                                 c, 2.0 if n >= 2 else 1.5))
        client_trust = sum(n for (d, w), n in f.senders.items() if d in TRUST_ALERTS and w == "client")
        if client_trust:
            ind.append(Indicator("The browser/app refused the certificate it was shown; a man-in-the-middle presenting "
                                 "its own certificate produces exactly this", Category.ATTACK, 0.5))
            if len(trust_servers) >= 3:
                ind.append(Indicator(f"{len(trust_servers)} unrelated servers fail the certificate check at the same "
                                     "time: something between the clients and the internet is re-signing traffic "
                                     "(an inspection proxy/antivirus, or an attacker)", Category.ATTACK, 1.5))
        if f.descs.get(86):
            ind.append(Indicator("'inappropriate_fallback' means a connection was retried with a weaker TLS version "
                                 "than both sides support, which a downgrade attack provokes", Category.ATTACK, 1.0))
        if len(f.clients) >= 2:
            ind.append(Indicator(f"{len(f.clients)} different clients hit the same error, so the problem is on the "
                                 "server side, not one device", Category.FAULT if cat is Category.FAULT else
                                 Category.MISCONFIG, 1.0))
        sev = Severity.MEDIUM if (f.count >= 3 or len(f.clients) >= 2) else Severity.LOW
        title = {45: f"This website's security certificate has expired ({site})",
                 44: f"This website's security certificate was revoked ({site})",
                 48: f"Devices don't trust the certificate of {site}",
                 70: f"No common TLS version with {site}"}.get(
            top_desc, f"Secure connection fails: {site} ({name.replace('_', ' ')})")
        summary = f"{plural(f.count, 'secure (TLS) connection')} to {f.server} failed; main reason: {plain}."
        expl = ("Before a secure (https) connection starts, both sides agree on encryption and the server proves its "
                f"identity with a certificate. Here it failed: {plain}. Users see a security warning or the app "
                "simply cannot connect.")
        fix_by = {
            45: ["Renew the server's certificate (e.g. `certbot renew`) and reload the web server.",
                 "Set up automatic renewal and an expiry alert.",
                 "Also check the client clock: a wrong date makes valid certificates look expired."],
            48: ["Check who issued the certificate the client sees (browser padlock > certificate details).",
                 "If it is your company's inspection proxy/antivirus, install its root certificate on the device "
                 "(or exempt the site).",
                 "If nobody on the network re-signs traffic, treat it as a man-in-the-middle: check ARP/DNS findings "
                 "and the gateway, and do not ignore the warning.",
                 "On the server, make sure the full certificate chain (with intermediates) is installed."],
            40: ["Enable modern cipher suites on the server (e.g. Mozilla 'intermediate' configuration).",
                 "Update the client software/library if it only offers old ciphers.",
                 "Test with `openssl s_client -connect " + f.server + "` to see what is offered."],
            70: ["Enable TLS 1.2 and 1.3 on both sides; update old clients/devices that only speak TLS 1.0.",
                 "Test with `openssl s_client -tls1_2 -connect " + f.server + "`."],
        }
        fix = fix_by.get(top_desc) or fix_by.get(48 if top_desc in TRUST_ALERTS else -1) or [
            "Test the server with `openssl s_client -connect " + f.server + "` and read the error.",
            "Check the server's TLS configuration and certificate (expiry, chain, hostname).",
            "Update the client software and check its date/time.",
            "Check the server logs at the time of the failures."]
        cause = {Category.FAULT: f"A problem on {f.server}: {plain}.",
                 Category.MISCONFIG: f"A TLS configuration mismatch between the clients and {f.server}: {plain}."}[
            cat if cat in (Category.FAULT, Category.MISCONFIG) else Category.FAULT]
        variants = {cat: Variant(title, summary, expl, cause, fix, severity=sev,
                                 analogy="Like a bouncer refusing entry because the ID card is expired or from a "
                                         "country he does not recognise.")}
        other = Category.MISCONFIG if cat is Category.FAULT else Category.FAULT
        variants[other] = Variant(title, summary, expl, cause, fix, severity=sev)
        if client_trust:
            variants[Category.ATTACK] = Variant(
                f"Possible interception: certificates for {site} are not trusted",
                f"{plural(client_trust, 'connection')} rejected the certificate presented for {site}.",
                "Clients refused the certificate they received. If no inspection proxy is expected on this network, "
                "someone in the middle may be presenting a fake certificate to read encrypted traffic.",
                "A man-in-the-middle (ARP/DNS spoofing, rogue Wi-Fi) or an undeclared TLS inspection proxy.",
                fix_by[48], mitre="T1557 Adversary-in-the-Middle", severity=Severity.HIGH,
                analogy="Like a letter arriving with a seal you have never seen: maybe the sender changed it, maybe "
                        "someone opened it on the way.")
        fnd = Finding(kind="tls.failure", category=cat, severity=sev, title=title, summary=summary, explanation=expl,
                      cause=cause, fix=fix,
                      technical=(f"Server {f.server} (SNI {', '.join(snis) or 'n/a'}): {f.count} cleartext TLS alerts "
                                 f"in {(f.last or 0) - (f.first or 0):.1f} s; by description "
                                 + ", ".join(f"{ALERTS.get(d, (str(d),))[0]}({d})={n}" for d, n in f.descs.most_common(6))
                                 + "; senders " + ", ".join(f"{ALERTS.get(d, (str(d),))[0]}:{w}={n}"
                                                            for (d, w), n in f.senders.most_common(6))
                                 + f"; clients {', '.join(clients[:5])}."),
                      analogy=variants[cat].analogy, hosts=[f.server.rsplit(":", 1)[0]] + clients[:9],
                      metrics={"server": f.server, "sni": snis, "alerts": f.count,
                               "by_alert": {ALERTS.get(d, (str(d),))[0]: n for d, n in f.descs.most_common(8)},
                               "clients": clients, "certificate_errors": cert, "client_rejected_cert": client_trust},
                      indicators=ind, variants=variants)
        return f.ev.apply(fnd)

    # -- deprecated TLS finding ------------------------------------------ #
    def _old_finding(self, o: _OldTls) -> Finding:
        neg = sum(o.negotiated.values())
        worst = min(list(o.negotiated) + list(o.offered))
        vname = _vname(worst)
        snis = sorted(o.snis)[:5]
        clients = sorted(o.clients)[:10]
        site = snis[0] if snis else o.server
        ind = []
        if neg:
            ind.append(Indicator(f"The server {o.server} agreed to use {', '.join(_vname(v) for v in sorted(o.negotiated))} "
                                 f"in {plural(neg, 'connection')}: these versions have known weaknesses and are "
                                 "officially retired", Category.MISCONFIG, 2.5))
        if o.offered:
            ind.append(Indicator(f"{plural(len(o.clients), 'client')} offered at most "
                                 f"{', '.join(_vname(v) for v in sorted(o.offered))}: outdated software or device",
                                 Category.MISCONFIG, 1.5 if not neg else 1.0))
        sev = Severity.HIGH if worst <= 0x0300 and neg else (Severity.MEDIUM if neg else Severity.LOW)
        title = f"Outdated encryption: {site} uses {vname}"
        summary = (f"{plural(neg, 'connection')} to {o.server} were secured with {vname}" if neg else
                   f"{plural(len(o.clients), 'device')} tried to reach {o.server} offering only {vname}") + \
            ", which is no longer considered safe."
        expl = (f"{vname} is an old version of the encryption used for https and other secure connections. It has "
                "known weaknesses (attacks such as POODLE and BEAST) and browsers no longer accept it. Traffic still "
                "works today, but it is easier to break than with TLS 1.2 or 1.3.")
        fix = ["On the server, disable SSLv3, TLS 1.0 and TLS 1.1 and enable TLS 1.2 + 1.3 "
               "(nginx: `ssl_protocols TLSv1.2 TLSv1.3;`, Apache: `SSLProtocol -all +TLSv1.2 +TLSv1.3`).",
               "Update or replace clients/devices that only support old versions (old printers, IoT, Java 6/7 apps).",
               f"Verify with `openssl s_client -connect {o.server} -tls1_2` and an online TLS checker.",
               "If an old device cannot be updated, isolate it on its own network segment."]
        cause = ("The server still allows deprecated protocol versions." if neg else
                 "Old client software or firmware that does not support TLS 1.2.")
        f = Finding(kind="tls.deprecated", category=Category.MISCONFIG, severity=sev, title=title, summary=summary,
                    explanation=expl, cause=cause, fix=fix,
                    technical=(f"Server {o.server} (SNI {', '.join(snis) or 'n/a'}): negotiated "
                               f"{dict((_vname(k), v) for k, v in o.negotiated.items())}; client max offered "
                               f"{dict((_vname(k), v) for k, v in o.offered.items())}; clients {', '.join(clients[:5])}."),
                    analogy="Like locking your bike with an old lock that thieves know how to open in seconds.",
                    hosts=[o.server.rsplit(":", 1)[0]] + clients[:9],
                    metrics={"server": o.server, "sni": snis, "negotiated": {_vname(k): v for k, v in o.negotiated.items()},
                             "offered_max": {_vname(k): v for k, v in o.offered.items()}, "clients": clients,
                             "worst_version": vname},
                    indicators=ind,
                    variants={Category.MISCONFIG: Variant(title, summary, expl, cause, fix, severity=sev)})
        return o.ev.apply(f)

    # -- HTTP findings --------------------------------------------------- #
    def _http5_finding(self, s: _HttpSrv) -> Finding | None:
        n5 = sum(s.s5.values())
        if n5 < HTTP_5XX or n5 / max(s.responses, 1) < HTTP_5XX_RATIO:
            return None
        ratio = n5 / s.responses
        code = s.s5.most_common(1)[0][0]
        plain = HTTP_5XX_TEXT.get(code, "the server reported an internal error")
        name = s.names.most_common(1)[0][0] if s.names else s.server
        paths = [p for p, _ in s.paths5.most_common(5)]
        ind = [Indicator(f"{plural(n5, 'request')} ({fmt_pct(ratio)} of {s.responses}) to {name} failed with server "
                         f"errors ({', '.join(f'{c}x{n}' for c, n in s.s5.most_common(3))}): {plain}",
                         Category.FAULT, 2.5 if ratio >= 0.3 else 2.0)]
        if len(s.clients) >= 2:
            ind.append(Indicator(f"{len(s.clients)} different clients got these errors, so the server is at fault, not "
                                 "one user", Category.FAULT, 1.0))
        if code in (502, 504):
            ind.append(Indicator("A 502/504 comes from a proxy or load balancer: its link to the application server "
                                 "(address, port, timeout) may be misconfigured", Category.MISCONFIG, 0.5))
        sev = Severity.HIGH if (ratio >= 0.5 and n5 >= 20) else Severity.MEDIUM
        title = f"Website errors: {name} is failing ({code})"
        summary = f"{plural(n5, 'request')} to {name} ({fmt_pct(ratio)}) failed with HTTP {code} and similar server errors."
        expl = (f"Error codes in the 500s mean the problem is on the server side, not the user's: {plain}. The network "
                "delivered the request fine; the website itself could not answer properly.")
        fix = ["Check the web/application server error logs at the times of the failures (e.g. "
               "`journalctl -u <service>`, `/var/log/nginx/error.log`).",
               "Check that the application and its database/backend are running and not out of memory or disk.",
               "For 502/504: verify the proxy's upstream address/port and timeouts.",
               "Restart the failing service if needed and watch whether the errors stop."]
        cause = f"A server-side problem on {s.server}: {plain}."
        f = Finding(kind="http.errors", category=Category.FAULT, severity=sev, title=title, summary=summary,
                    explanation=expl, cause=cause, fix=fix,
                    technical=(f"Server {s.server} (Host {', '.join(n for n, _ in s.names.most_common(3)) or 'n/a'}): "
                               f"{s.responses} responses, 5xx {dict(s.s5)}, 4xx {dict(s.s4)}; failing requests "
                               f"{', '.join(paths) or 'n/a'}; {len(s.clients)} clients; 5xx between "
                               f"{(s.last5 or 0) - (s.first5 or 0):.1f} s."),
                    analogy="Like a restaurant where the waiter takes your order but the kitchen keeps burning the food.",
                    hosts=[s.server.rsplit(":", 1)[0]] + sorted(s.clients)[:9],
                    metrics={"server": s.server, "host": name, "responses": s.responses, "errors_5xx": n5,
                             "ratio_5xx": round(ratio, 3), "by_status": {str(k): v for k, v in s.s5.most_common(6)},
                             "failing_requests": paths, "clients": len(s.clients)},
                    indicators=ind,
                    variants={Category.FAULT: Variant(title, summary, expl, cause, fix, severity=sev)})
        if code in (502, 504):
            f.variants[Category.MISCONFIG] = Variant(
                f"Proxy cannot reach the application behind {name}", summary,
                "The front proxy or load balancer answers, but cannot talk to the application server behind it; "
                "often the backend address, port or timeout is configured wrongly.",
                "A wrong upstream/backend setting or timeout on the proxy.", fix, severity=sev)
        return s.ev5.apply(f)

    def _http4_finding(self, s: _HttpSrv) -> Finding | None:
        n4 = sum(s.s4.values())
        if n4 < 20 or n4 / max(s.responses, 1) < 0.5:
            return None
        name = s.names.most_common(1)[0][0] if s.names else s.server
        title = f"Many failed requests to {name} ({s.s4.most_common(1)[0][0]})"
        summary = f"{plural(n4, 'request')} to {name} ({fmt_pct(n4 / s.responses)}) were refused with 4xx errors."
        expl = ("Codes in the 400s mean the server rejected the request as wrong: missing pages (404), no permission "
                "(403) or login required (401). A few are normal; this many usually means broken links or an app "
                "using an outdated address or key.")
        fix = ["Look at which URLs fail (server access log) and fix the links or client configuration.",
               "If an app uses an API key or token, check it is still valid.",
               "If the requests come from an unknown client, check it is not scanning the site."]
        f = Finding(kind="http.errors", category=Category.FAULT, severity=Severity.LOW, title=title, summary=summary,
                    explanation=expl, cause="Broken links or a client using an outdated URL / credential.", fix=fix,
                    technical=f"Server {s.server}: {s.responses} responses, 4xx {dict(s.s4)}.",
                    hosts=[s.server.rsplit(":", 1)[0]],
                    metrics={"server": s.server, "host": name, "responses": s.responses, "errors_4xx": n4,
                             "by_status": {str(k): v for k, v in s.s4.most_common(6)}},
                    indicators=[Indicator(f"{fmt_pct(n4 / s.responses)} of responses are client errors (4xx)",
                                          Category.FAULT, 1.0)],
                    variants={Category.FAULT: Variant(title, summary, expl, "Broken links or outdated client "
                                                      "configuration.", fix, severity=Severity.LOW)})
        return s.ev4.apply(f)

    def _brute_finding(self, client: str, server: str, cs: _ClientSrv, sc: float) -> Finding | None:
        thr = max(5, round(BRUTE_HTTP * sc))
        if cs.auth_peak < thr:
            return None
        nauth = cs.c401 + cs.c403
        ok_ratio = cs.ok / max(cs.total, 1)
        paths = cs.paths_auth.most_common(3)
        focused = len(cs.paths_auth) <= 3
        times = cs.auth_times
        gaps = [b - a for a, b in zip(times, times[1:]) if b >= a]
        rate = (len(times) - 1) / max(times[-1] - times[0], 0.001) if len(times) >= 2 else 0.0
        regular = False
        if len(gaps) >= 5:
            mean = sum(gaps) / len(gaps)
            var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
            regular = mean >= 1.0 and (var ** 0.5) / max(mean, 1e-6) < 0.2
        if ok_ratio >= 0.4:
            return None  # many successes: an auth challenge per request (NTLM/Kerberos/Digest), not guessing
        name = cs.names.most_common(1)[0][0] if cs.names else server
        ind = [Indicator(f"{client} was refused (401/403) {cs.auth_peak} times within {int(BRUTE_WINDOW)} s by {name}",
                         Category.ATTACK, 2.0 if cs.auth_peak >= 3 * thr else 1.5)]
        if focused:
            ind.append(Indicator(f"Almost all refusals are for the same page ({', '.join(p for p, _ in paths)}): "
                                 "repeated login attempts", Category.ATTACK, 1.0))
        if ok_ratio < 0.2:
            ind.append(Indicator(f"Only {fmt_pct(ok_ratio)} of this client's requests succeeded", Category.ATTACK, 0.5))
        if rate >= 2 and not regular:
            ind.append(Indicator(f"Attempts came at {rate:.1f} per second, faster than anyone types a password",
                                 Category.ATTACK, 1.0))
        if regular:
            ind.append(Indicator("The same request repeats at a steady interval, like an app or script retrying with "
                                 "an old saved password", Category.MISCONFIG, 3.0 if rate < 1 else 1.5))
        if not focused and ok_ratio >= 0.2:
            ind.append(Indicator(f"Refusals are spread over {len(cs.paths_auth)} different pages: more like missing "
                                 "permissions than guessing", Category.MISCONFIG, 1.0))
        att = sum(i.weight for i in ind if i.supports is Category.ATTACK)
        other = sum(i.weight for i in ind if i.supports is not Category.ATTACK)
        if not focused and other >= att:
            return None
        title_a = f"Password guessing: {client} keeps trying to log in to {name}"
        sum_a = f"{client} got {nauth} 'access denied' answers from {name}, up to {cs.auth_peak} per minute."
        expl_a = ("The website answered 'wrong login / not allowed' (HTTP 401/403) to the same client again and "
                  "again in a short time. That is what a tool trying many passwords (brute force) looks like.")
        fix_a = [f"Block {client} at the firewall or web application firewall, and check whether it is one of your devices.",
                 "Enable rate limiting / account lockout on the login (e.g. fail2ban, nginx `limit_req`).",
                 "Make sure the targeted accounts have strong passwords and multi-factor authentication.",
                 "Check the server logs for a successful login from this address."]
        title_m = f"An app on {client} keeps failing to log in to {name}"
        sum_m = f"{client} received {nauth} 401/403 errors from {name}, repeating at a steady pace."
        expl_m = ("A program on this device keeps retrying a login that is refused, probably because its saved "
                  "password expired or changed. It is not an attack, but it can lock the account.")
        fix_m = [f"Find the app or script on {client} that talks to {name} and update its credentials.",
                 "Check whether the account is now locked and unlock it.", "Remove the job if it is no longer needed."]
        cat = Category.ATTACK if att > other else Category.MISCONFIG
        mitre = "T1110 Brute Force"
        v = {Category.ATTACK: Variant(title_a, sum_a, expl_a, f"A password-guessing tool on {client}.", fix_a,
                                      mitre=mitre, severity=Severity.HIGH,
                                      analogy="Like someone trying every key on a giant key ring on your front door."),
             Category.MISCONFIG: Variant(title_m, sum_m, expl_m, "Stale credentials saved in an app or script.", fix_m,
                                         severity=Severity.LOW,
                                         analogy="Like a colleague who keeps typing last month's door code.")}
        cv = v[cat]
        f = Finding(kind="http.errors", category=cat, severity=cv.severity, title=cv.title, summary=cv.summary,
                    explanation=cv.explanation, cause=cv.cause, fix=cv.fix, analogy=cv.analogy,
                    mitre=mitre if cat is Category.ATTACK else None,
                    technical=(f"{client} -> {server} (Host {name}): {cs.total} responses, {cs.c401}x401, {cs.c403}x403, "
                               f"{cs.ok} 2xx/3xx ({fmt_pct(ok_ratio)}); peak {cs.auth_peak} refusals/{int(BRUTE_WINDOW)} s "
                               f"(threshold {thr}); paths {', '.join(f'{p} ({n})' for p, n in paths)}; rate {rate:.2f}/s; "
                               f"regular interval {regular}."),
                    hosts=[client, server.rsplit(":", 1)[0]],
                    metrics={"client": client, "server": server, "host": name, "refusals": nauth, "c401": cs.c401,
                             "c403": cs.c403, "peak_per_window": cs.auth_peak, "success_ratio": round(ok_ratio, 3),
                             "paths": [p for p, _ in paths], "rate_per_s": round(rate, 2), "regular": regular},
                    indicators=ind, variants=v)
        return cs.ev_auth.apply(f)

    def _dirscan_finding(self, client: str, server: str, cs: _ClientSrv, sc: float) -> Finding | None:
        thr = max(10, round(SCAN_404 * sc))
        if cs.nf_peak < thr or len(cs.paths_404) < 0.8 * thr:
            return None
        nf_ratio = cs.c404 / max(cs.total, 1)
        tops = len(cs.tops_404)
        if nf_ratio < 0.7 or tops < 20:
            return None  # a broken page (many missing files in one folder) rather than a wordlist
        name = cs.names.most_common(1)[0][0] if cs.names else server
        ind = [Indicator(f"{client} asked {name} for {len(cs.paths_404)} different pages that do not exist "
                         f"(up to {cs.nf_peak} per minute)", Category.ATTACK, 2.0),
               Indicator(f"The missing pages are spread over {tops} unrelated names (like /admin, /backup, /.git): a "
                         "word list, not a broken link", Category.ATTACK, 1.5),
               Indicator(f"{fmt_pct(nf_ratio)} of its requests failed; a real visitor follows links that work",
                         Category.ATTACK, 0.5)]
        title = f"Website scan: {client} is guessing hidden pages on {name}"
        summary = f"{client} requested {cs.c404} non-existent pages on {name} ({len(cs.paths_404)} different names)."
        expl = ("Instead of following links, this client tried a long list of possible page names to find hidden "
                "admin panels, backups or forgotten files. Tools such as dirb or gobuster do this before an attack.")
        fix = [f"Block {client} at the firewall / web application firewall if it is not your own security test.",
               "Remove backup files, admin panels and old pages that should not be public; protect admin pages with a login and IP allow-list.",
               "Enable rate limiting for 404s (e.g. fail2ban nginx-botsearch).",
               "Check the access log for any of these requests that returned 200."]
        mitre = "T1595.003 Active Scanning: Wordlist Scanning"
        f = Finding(kind="http.errors", category=Category.ATTACK, severity=Severity.MEDIUM, title=title, summary=summary,
                    explanation=expl, cause=f"A web content scanner on {client}.", fix=fix, mitre=mitre,
                    analogy="Like someone trying every drawer in an office looking for the one with the spare keys.",
                    technical=(f"{client} -> {server}: {cs.total} responses, {cs.c404}x404 ({fmt_pct(nf_ratio)}), "
                               f"{len(cs.paths_404)} distinct paths, {tops} distinct top-level names, peak "
                               f"{cs.nf_peak}/{int(BRUTE_WINDOW)} s (threshold {thr})."),
                    hosts=[client, server.rsplit(":", 1)[0]],
                    metrics={"client": client, "server": server, "host": name, "not_found": cs.c404,
                             "distinct_paths": len(cs.paths_404), "top_level_names": tops,
                             "sample_paths": sorted(cs.paths_404)[:10], "peak_per_window": cs.nf_peak},
                    indicators=ind,
                    variants={Category.ATTACK: Variant(title, summary, expl, f"A web content scanner on {client}.",
                                                       fix, mitre=mitre, severity=Severity.MEDIUM)})
        return cs.ev_404.apply(f)
