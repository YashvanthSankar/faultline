"""DNS detectors: timeouts, error rcodes, slow resolution, unusual NXDOMAIN
(typo / stale config vs. DGA malware), forged answers (hijack / spoofing race)
and DNS tunneling.

Queries are matched to responses by (client ip, client port, server ip, txid).
A looser (client ip, txid, qname) key finds responses from servers the client
never asked. Pending queries are expired in time order (bounded state); a query
is "unanswered" when no response arrived within ``TIMEOUT`` seconds.
"""

from __future__ import annotations

import random
import statistics
from collections import Counter, OrderedDict

from ..context import is_multicast_or_broadcast, is_private
from .arp import clip, clock, evidence_of, fmt_frac, make_finding, shannon
from .base import (
    AnalysisContext,
    BoundedDict,
    Category,
    Detector,
    Finding,
    Indicator,
    Packet,
    Severity,
    Variant,
    fmt_ms,
    plural,
    register,
)

INTERNAL_SUFFIXES = (".local", ".lan", ".internal", ".corp", ".home", ".home.arpa", ".intranet", ".private",
                     ".localdomain", ".domain", ".localhost", ".test", ".invalid", ".example")
SHORT_SLD = {"co", "com", "net", "org", "ac", "gov", "edu", "or", "ne", "go", "mil", "nic", "ltd", "plc", "sch", "gob"}
RCODE_NAMES = {1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
ERROR_RCODES = (1, 2, 4, 5)
ADDR_TYPES = (1, 28)  # A, AAAA
TXT_LIKE = (10, 16)   # NULL, TXT
VOWELS = set("aeiouy")


def registered_domain(name: str) -> str:
    """Approximate eTLD+1 without a public suffix list."""
    labels = [x for x in name.split(".") if x]
    if len(labels) <= 2:
        return ".".join(labels)
    if labels[-2] in SHORT_SLD and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_internal_name(name: str) -> bool:
    return "." not in name or name.endswith(INTERNAL_SUFFIXES) or name.endswith(".arpa")


def randomish(label: str) -> bool:
    """Heuristic: does a DNS label look machine-generated (DGA)?"""
    L = len(label)
    if L < 8:
        return False
    letters = [c for c in label if c.isalpha()]
    digits = sum(c.isdigit() for c in label)
    if not letters:
        return False
    vowel_ratio = sum(c in VOWELS for c in letters) / len(letters)
    ent = shannon(label)
    run = best = 0
    for c in label:
        if c.isalpha() and c not in VOWELS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    if L >= 12 and ent >= 3.5:
        return True
    if ent >= 3.0 and (vowel_ratio < 0.25 or best >= 5 or (digits >= 2 and len(letters) >= 4)):
        return True
    return False


class _Q:
    __slots__ = ("ts", "no", "client", "cport", "server", "qid", "qname", "qtype", "nq", "nresp", "first", "eth")

    def __init__(self, ts, no, client, cport, server, qid, qname, qtype, eth):
        self.ts, self.no, self.client, self.cport, self.server = ts, no, client, cport, server
        self.qid, self.qname, self.qtype, self.eth = qid, qname, qtype, eth
        self.nq = 1
        self.nresp = 0
        self.first = None  # dict describing the first response


class _Srv:
    __slots__ = ("queries", "answered", "timeouts", "rtts", "seen_rtts", "slow", "rcodes", "eth", "aa", "responses",
                 "last_ok", "to_since_ok", "first_to_since_ok", "first_to", "to_frames", "slow_frames", "err_frames",
                 "clients", "late", "retries", "ever_ok")

    def __init__(self) -> None:
        self.queries = self.answered = self.timeouts = self.slow = self.aa = self.responses = 0
        self.rtts: list[float] = []
        self.seen_rtts = 0
        self.rcodes: Counter = Counter()
        self.eth: Counter = Counter()
        self.last_ok: float | None = None
        self.to_since_ok = 0
        self.first_to_since_ok: float | None = None
        self.first_to: float | None = None
        self.to_frames: list[int] = []
        self.slow_frames: list[int] = []
        self.err_frames: list[int] = []
        self.clients: set[str] = set()
        self.late = 0
        self.retries = 0
        self.ever_ok = False

    def median(self) -> float | None:
        return statistics.median(self.rtts) if self.rtts else None


class _Dom:
    __slots__ = ("queries", "subs", "sum_len", "sum_ent", "txt", "clients", "frames", "samples", "last_ts",
                 "iv_n", "iv_sum", "iv_sq", "bytes", "first_ts")

    def __init__(self, ts: float) -> None:
        self.queries = self.txt = self.bytes = 0
        self.subs: set[int] = set()
        self.sum_len = 0
        self.sum_ent = 0.0
        self.clients: set[str] = set()
        self.frames: list[int] = []
        self.samples: list[str] = []
        self.last_ts: float | None = None
        self.first_ts = ts
        self.iv_n = 0
        self.iv_sum = self.iv_sq = 0.0


@register
class DnsDetector(Detector):
    name = "dns"

    TIMEOUT = 3.0
    HOLD = 10.0          # keep answered queries this long to catch racing/duplicate answers
    MAX_PENDING = 200_000

    def __init__(self) -> None:
        self.pending: OrderedDict = OrderedDict()  # exact key -> _Q
        self.loose: dict = {}                       # (client, qid, qname) -> exact key
        self.servers: BoundedDict = BoundedDict(4096)
        self.recent_q: BoundedDict = BoundedDict(50_000)  # (client, qname, qtype) -> last _Q
        self.now: float | None = None
        self.end_ts: float | None = None
        self.queries = 0
        self.responses = 0      # first responses + unmatched responses
        self.unmatched = 0
        self.retries = 0
        self.expired_late = 0
        self.timeouts_ignored_tail = 0
        self.rng = random.Random(1234)
        # rcode / nxdomain
        self.errors: Counter = Counter()
        self.err_names: Counter = Counter()
        self.err_frames: list[int] = []
        self.err_ts: list[float] = []
        self.nx = 0
        self.nx_names: Counter = Counter()        # qname -> count (bounded below)
        self.nx_clients: Counter = Counter()
        self.nx_frames: list[int] = []
        self.nx_ts: list[float] = []
        # hijack evidence
        self.races: list[dict] = []
        self.race_total = 0
        self.unexpected: list[dict] = []
        self.unexpected_total = 0
        self.pubpriv: dict[str, dict] = {}         # private answer ip -> info
        self.public_answers: set[str] = set()      # registered domains that resolved public (bounded)
        self.answer_eth: Counter = Counter()
        # tunneling
        self.domains: BoundedDict = BoundedDict(20_000)

    # ------------------------------------------------------------------ #
    def on_packet(self, pkt: Packet, ctx: AnalysisContext) -> None:
        d = pkt.dns
        if d is None:
            return
        sp, dp = pkt.sport, pkt.dport
        if sp != 53 and dp != 53:
            return  # mDNS / LLMNR / odd ports
        if not pkt.src or not pkt.dst:
            return
        ts = pkt.ts if pkt.ts is not None else 0.0
        if self.now is None or ts > self.now:
            self.now = ts
        self._expire(self.now - self.HOLD)
        qname = (d.qname or "").lower().rstrip(".")
        if not d.qr:
            if dp != 53 or is_multicast_or_broadcast(pkt.dst):
                return
            self._query(pkt, d, qname, ts)
        else:
            if sp != 53:
                return
            self._response(pkt, d, qname, ts)

    # -- queries ---------------------------------------------------------- #
    def _srv(self, ip: str) -> _Srv:
        s = self.servers.get(ip)
        if s is None:
            s = self.servers[ip] = _Srv()
        return s

    def _query(self, pkt: Packet, d, qname: str, ts: float) -> None:
        self.queries += 1
        client, server, cport = pkt.src, pkt.dst, pkt.sport or 0
        key = (client, cport, server, d.id)
        rk = (client, qname, d.qtype)
        prev = self.recent_q.get(rk)
        is_retry = prev is not None and prev.first is None and 0 <= ts - prev.ts <= 5.0
        if is_retry:
            self.retries += 1
            s = self.servers.get(server)
            if s is not None:
                s.retries += 1
        q = self.pending.get(key)
        if q is not None:
            q.nq += 1  # same txid/port re-sent
        else:
            if len(self.pending) >= self.MAX_PENDING:
                k0, q0 = self.pending.popitem(last=False)
                self._settle(k0, q0)
            q = _Q(ts, pkt.no, client, cport, server, d.id, qname, d.qtype, pkt.eth_src)
            self.pending[key] = q
            if len(self.loose) < self.MAX_PENDING:
                self.loose[(client, d.id, qname)] = key
        self.recent_q[rk] = q
        self._tunnel(pkt, d, qname, client, ts)

    def _tunnel(self, pkt: Packet, d, qname: str, client: str, ts: float) -> None:
        if not qname or qname.endswith(".arpa") or "." not in qname:
            return
        reg = registered_domain(qname)
        if not reg or len(qname) <= len(reg) + 1:
            return
        sub = qname[: -(len(reg) + 1)]
        dm = self.domains.get(reg)
        if dm is None:
            dm = self.domains[reg] = _Dom(ts)
        else:
            self.domains.move_to_end(reg)
        dm.queries += 1
        dm.bytes += len(qname)
        if d.qtype in TXT_LIKE:
            dm.txt += 1
        if len(dm.clients) < 16:
            dm.clients.add(client)
        if dm.last_ts is not None:
            iv = ts - dm.last_ts
            if 0 <= iv < 3600:
                dm.iv_n += 1
                dm.iv_sum += iv
                dm.iv_sq += iv * iv
        dm.last_ts = ts
        h = hash(sub)
        if h not in dm.subs and len(dm.subs) < 5000:
            dm.subs.add(h)
            flat = sub.replace(".", "")
            dm.sum_len += len(flat)
            dm.sum_ent += shannon(flat)
            if len(dm.samples) < 5:
                dm.samples.append(clip(qname, 100))
        if len(dm.frames) < 200:
            dm.frames.append(pkt.no)

    # -- responses ---------------------------------------------------------- #
    def _response(self, pkt: Packet, d, qname: str, ts: float) -> None:
        server, client, cport = pkt.src, pkt.dst, pkt.dport
        key = (client, cport, server, d.id)
        q = self.pending.get(key)
        sig = (d.rcode, frozenset(a.data for a in d.answers[:32] if a.rtype in (1, 5, 28) and a.data))
        addrs = [a.data for a in d.answers[:32] if a.rtype in ADDR_TYPES and a.data]
        ttls = [a.ttl for a in d.answers[:32] if a.ttl is not None]
        info = {"ts": ts, "no": pkt.no, "sig": sig, "addrs": addrs, "eth": pkt.eth_src, "server": server,
                "ttl": min(ttls) if ttls else None, "aa": bool(d.aa), "rcode": d.rcode}
        if q is None:
            lk = self.loose.get((client, d.id, qname))
            lq = self.pending.get(lk) if lk is not None else None
            if lq is not None and lq.server != server:
                self.unexpected_total += 1
                if len(self.unexpected) < 100:
                    self.unexpected.append({"q": _qinfo(lq), "resp": info})
                if lq.first is None:
                    lq.first = dict(info, unexpected=True)
                    lq.nresp += 1
                self._first_response_stats(pkt, d, qname, ts, server, client, info, lq, unexpected=True)
                return
            self.unmatched += 1
            self._first_response_stats(pkt, d, qname, ts, server, client, info, None)
            return
        q.nresp += 1
        if q.first is None:
            info["rtt"] = ts - q.ts
            q.first = info
            self._first_response_stats(pkt, d, qname, ts, server, client, info, q)
            return
        # second (or later) response to the same transaction
        if q.first.get("unexpected"):
            return
        if sig != q.first["sig"] and q.nresp > q.nq:
            info["rtt"] = ts - q.ts
            self.race_total += 1
            if len(self.races) < 100:
                self.races.append({"q": _qinfo(q), "first": q.first, "second": info})

    def _first_response_stats(self, pkt: Packet, d, qname, ts, server, client, info, q, unexpected=False) -> None:
        self.responses += 1
        s = self._srv(server)
        s.responses += 1
        if d.aa:
            s.aa += 1
        if pkt.eth_src and (len(s.eth) < 4 or pkt.eth_src in s.eth):
            s.eth[pkt.eth_src] += 1
        rc = d.rcode
        s.rcodes[rc] += 1
        if rc in ERROR_RCODES:
            self.errors[rc] += 1
            if len(self.err_names) < 5000 or qname in self.err_names:
                self.err_names[qname] += 1
            if len(self.err_frames) < 200:
                self.err_frames.append(pkt.no)
                self.err_ts.append(ts)
            if len(s.err_frames) < 50:
                s.err_frames.append(pkt.no)
        elif rc == 3:
            if not qname.endswith(".arpa"):
                self.nx += 1
                if len(self.nx_names) < 5000 or qname in self.nx_names:
                    self.nx_names[qname] += 1
                if len(self.nx_clients) < 1000 or client in self.nx_clients:
                    self.nx_clients[client] += 1
                if len(self.nx_frames) < 200:
                    self.nx_frames.append(pkt.no)
                    self.nx_ts.append(ts)
        elif rc == 0 and info["addrs"] and qname:
            reg = registered_domain(qname)
            for ip in info["addrs"][:8]:
                if not is_private(ip):
                    if len(self.public_answers) < 50_000:
                        self.public_answers.add(reg)
                    continue
                if ip.startswith(("0.", "127.")) or ip in ("::", "::1"):
                    continue  # sinkhole / blocking, not redirection
                if is_internal_name(qname):
                    continue
                e = self.pubpriv.get(ip)
                if e is None:
                    if len(self.pubpriv) >= 256:
                        continue
                    e = self.pubpriv[ip] = {"names": set(), "domains": set(), "frames": [], "servers": Counter(),
                                            "eth": Counter(), "ttls": [], "aa": 0, "n": 0, "first": ts, "self": 0}
                e["n"] += 1
                if len(e["names"]) < 50:
                    e["names"].add(clip(qname, 100))
                if len(e["domains"]) < 200:
                    e["domains"].add(reg)
                if len(e["frames"]) < 100:
                    e["frames"].append(pkt.no)
                e["servers"][server] += 1
                if pkt.eth_src:
                    e["eth"][pkt.eth_src] += 1
                if info["ttl"] is not None and len(e["ttls"]) < 100:
                    e["ttls"].append(info["ttl"])
                if d.aa:
                    e["aa"] += 1
                if ip == server and q is not None and not unexpected:
                    e["self"] += 1  # the resolver the client asked answers with its own address

    # -- expiry -------------------------------------------------------------- #
    def _expire(self, cutoff: float) -> None:
        p = self.pending
        while p:
            k = next(iter(p))
            q = p[k]
            if q.ts > cutoff:
                break
            p.popitem(last=False)
            self._settle(k, q)

    def _settle(self, key, q: _Q, at_end: bool = False) -> None:
        lk = (q.client, q.qid, q.qname)
        if self.loose.get(lk) == key:
            del self.loose[lk]
        s = self._srv(q.server)
        if len(s.clients) < 64:
            s.clients.add(q.client)
        first = q.first
        if first is not None and not first.get("unexpected"):
            rtt = first.get("rtt")
            s.queries += 1
            s.answered += 1
            s.ever_ok = True
            s.last_ok = q.ts
            s.to_since_ok = 0
            s.first_to_since_ok = None
            if rtt is not None and rtt >= 0:
                s.seen_rtts += 1
                if len(s.rtts) < 2000:
                    s.rtts.append(rtt)
                else:
                    j = self.rng.randrange(s.seen_rtts)
                    if j < 2000:
                        s.rtts[j] = rtt
                if rtt >= 1.0:
                    s.slow += 1
                    if len(s.slow_frames) < 50:
                        s.slow_frames.append(first["no"])
                if rtt > self.TIMEOUT:
                    s.late += 1
            return
        if first is not None:
            return  # answered by an unexpected server; counted under hijack
        if at_end and self.end_ts is not None and q.ts > self.end_ts - self.TIMEOUT:
            self.timeouts_ignored_tail += 1
            return
        s.queries += 1
        s.timeouts += 1
        if s.first_to is None:
            s.first_to = q.ts
        if s.to_since_ok == 0:
            s.first_to_since_ok = q.ts
        s.to_since_ok += 1
        if len(s.to_frames) < 50:
            s.to_frames.append(q.no)

    # ------------------------------------------------------------------ #
    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        self.end_ts = self.now
        while self.pending:
            k, q = self.pending.popitem(last=False)
            self._settle(k, q, at_end=True)
        scale = ctx.config.scale
        out: list[Finding] = []
        for fn in (self._find_timeouts, self._find_errors, self._find_slow, self._find_nxdomain,
                   self._find_hijack, self._find_tunneling):
            try:
                r = fn(ctx, scale)
            except (ValueError, ZeroDivisionError, statistics.StatisticsError):  # pragma: no cover - defensive
                r = None
            if r:
                out.extend(r if isinstance(r, list) else [r])
        return out

    # -- timeouts ------------------------------------------------------------ #
    def _find_timeouts(self, ctx: AnalysisContext, scale: float):
        rows = [(ip, s) for ip, s in self.servers.items() if s.queries]
        total_q = sum(s.queries for _, s in rows)
        total_to = sum(s.timeouts for _, s in rows)
        if total_to < 3 or not total_q:
            return None
        ratio = total_to / total_q
        if not (total_to >= 5 * scale or ratio >= 0.2):
            return None
        bad = sorted([(ip, s) for ip, s in rows if s.timeouts], key=lambda r: -r[1].timeouts)
        good = [(ip, s) for ip, s in rows if s.answered and s.timeouts / max(1, s.queries) < 0.1]
        F, M = Category.FAULT, Category.MISCONFIG
        ind: list[Indicator] = []
        ip0, s0 = bad[0]
        stopped = s0.ever_ok and s0.last_ok is not None and s0.to_since_ok >= 3
        never = not s0.ever_ok
        ind.append(Indicator(f"{plural(total_to, 'DNS lookup')} out of {total_q:,} got no answer within "
                             f"{self.TIMEOUT:.0f} s", F, 1.5))
        if stopped:
            ind.append(Indicator(f"DNS server {ip0} answered normally until {clock(s0.last_ok)} and then stopped "
                                 f"({s0.to_since_ok} queries unanswered since)", F, 2.0))
        if good:
            ind.append(Indicator(f"Other DNS servers still work ({', '.join(ip for ip, _ in good[:2])}), so the problem "
                                 f"is the server {ip0}, not the whole connection", F, 1.0))
        host = ctx.hosts.hosts.get(ip0)
        silent = host is None or host.packets_sent == 0
        if never and silent and is_private(ip0):
            ind.append(Indicator(f"The configured DNS server {ip0} never sent a single packet: the address may "
                                 "simply be wrong", M, 1.5))
        elif never and len(bad) == 1 and good:
            ind.append(Indicator(f"{ip0} never answered at all while other servers did: likely a wrong DNS setting", M, 1.0))
        if self.retries:
            ind.append(Indicator(f"Devices retried {plural(self.retries, 'lookup')}, as they do when DNS goes quiet", F, 0.5))
        sev = Severity.HIGH if ratio >= 0.5 else Severity.MEDIUM if ratio >= 0.2 else Severity.LOW
        when = clock(s0.first_to_since_ok or s0.first_to)
        per = "; ".join(f"{ip}: {s.timeouts}/{s.queries} unanswered" for ip, s in bad[:4])
        backup = f", the backup {good[0][0]} works" if good else ""
        clients = sorted({c for _, s in bad for c in s.clients})[:10]
        fault = Variant(
            title=f"DNS server {ip0} stopped answering" if stopped or never else "DNS lookups are timing out",
            summary=(f"Your DNS server {ip0} stopped answering at {when}{backup}: "
                     f"{total_to} of {total_q:,} lookups ({fmt_frac(ratio)}) got no reply."),
            explanation=(
                "Before your device can open a website it asks a DNS server to turn the name (like example.com) "
                "into an address. These questions are going unanswered, so websites and apps seem 'down' even "
                "though the internet connection itself may be fine."),
            cause=(f"The DNS server {ip0} is down, overloaded or unreachable (or a firewall is dropping DNS)."),
            fix=[
                f"Test it directly: `nslookup example.com {ip0}`, then compare with `nslookup example.com 1.1.1.1`.",
                "If only your server fails, restart it (often the router) or switch DNS to a working one "
                "(router/DHCP settings, or the device's network settings).",
                "Check firewall rules that might block UDP/TCP port 53.",
                "On Windows run `ipconfig /flushdns`; check which DNS servers are configured with `ipconfig /all`.",
            ],
            analogy="Like phoning directory enquiries and nobody ever picks up.",
            severity=sev,
        )
        misconf = Variant(
            title=f"Devices are configured with a DNS server that doesn't answer ({ip0})",
            summary=f"{ip0} never answered any of {s0.queries} lookups; it is probably the wrong address.",
            explanation=("Devices are sending name lookups to an address that never replies. Usually this is a typo "
                         "or an old DNS server address in the router's DHCP settings or a device's static settings."),
            cause=f"A wrong or outdated DNS server address ({ip0}) in DHCP or static network settings.",
            fix=["Check the DNS servers handed out by your router/DHCP server.",
                 "On the device run `ipconfig /all` (Windows) or `resolvectl status` (Linux) and correct the DNS address.",
                 f"Test: `nslookup example.com {ip0}` versus `nslookup example.com 1.1.1.1`."],
            analogy="Like a phone book that lists a number nobody uses any more.",
            severity=Severity.MEDIUM if ratio >= 0.2 else Severity.LOW,
        )
        frames = [no for _, s in bad for no in s.to_frames]
        ev = evidence_of(frames, total=total_to, first_ts=min((s.first_to for _, s in bad if s.first_to), default=None),
                         last_ts=self.end_ts)
        tech = (f"Unanswered within {self.TIMEOUT:.0f} s: {per}. Working: "
                + (", ".join(f"{ip} ({s.answered} answered, median {fmt_ms(s.median())})" for ip, s in good[:3]) or "none")
                + f". Retries: {self.retries}; queries in the last {self.TIMEOUT:.0f} s ignored: {self.timeouts_ignored_tail}.")
        metrics = {"unanswered": total_to, "queries": total_q, "ratio": round(ratio, 3),
                   "servers": {ip: {"queries": s.queries, "unanswered": s.timeouts, "answered": s.answered,
                                    "last_ok": s.last_ok} for ip, s in (bad + good)[:10]},
                   "clients": clients, "retries": self.retries}
        variants = {F: fault}
        if never:
            variants[M] = misconf
        return make_finding("dns.timeout", variants, ind, technical=tech, hosts=[ip0] + clients[:5],
                            metrics=metrics, evidence=ev, default=F)

    # -- errors -------------------------------------------------------------- #
    def _find_errors(self, ctx: AnalysisContext, scale: float):
        n = sum(self.errors.values())
        if n < 3 or not self.responses or n / self.responses < 0.05:
            return None
        ratio = n / self.responses
        top_rc, top_n = self.errors.most_common(1)[0]
        doms = Counter()
        for name, c in self.err_names.items():
            doms[registered_domain(name) or name] += c
        top_dom, top_dom_n = doms.most_common(1)[0] if doms else ("", 0)
        refused = self.errors.get(5, 0)
        servfail = self.errors.get(2, 0)
        # REFUSED is a server policy, not a property of the domain being looked up
        concentrated = top_dom_n / n >= 0.8 and len(doms) <= 2 and refused / n < 0.5
        per_srv = [(ip, s, sum(s.rcodes[r] for r in ERROR_RCODES)) for ip, s in self.servers.items()]
        per_srv = sorted([x for x in per_srv if x[2]], key=lambda x: -x[2])
        F, M = Category.FAULT, Category.MISCONFIG
        ind = [Indicator(f"{n} of {self.responses:,} DNS answers were errors ({fmt_frac(ratio)}), mostly "
                         f"{RCODE_NAMES.get(top_rc, top_rc)}", F, 1.0)]
        if refused / n >= 0.5:
            ind.append(Indicator(f"{refused} answers were REFUSED: the server won't serve these devices "
                                 "(wrong DNS server or an access list)", M, 2.0))
        if servfail / n >= 0.5:
            ind.append(Indicator(f"{servfail} answers were SERVFAIL: the resolver could not get an answer upstream", F, 2.0))
        if self.errors.get(1, 0) / n >= 0.5:
            ind.append(Indicator("Mostly FORMERR: something between client and server is mangling DNS packets", F, 1.0))
        if concentrated:
            ind.append(Indicator(f"Almost all errors are for one domain ({clip(top_dom, 60)}), so that domain's own DNS "
                                 "is broken, not your network", F, 1.0))
        elif len(doms) >= 5:
            ind.append(Indicator(f"Errors affect {len(doms)} different domains", F, 0.5))
        sev = Severity.LOW if concentrated else Severity.HIGH if ratio >= 0.5 else Severity.MEDIUM if ratio >= 0.2 else Severity.LOW
        srv0 = per_srv[0][0] if per_srv else "?"
        rcname = RCODE_NAMES.get(top_rc, str(top_rc))
        fault = Variant(
            title=f"DNS server {srv0} is returning errors ({rcname})",
            summary=f"{n} DNS lookups ({fmt_frac(ratio)}) failed with an error, mostly {rcname} from {srv0}.",
            explanation=(
                "The DNS server answered, but with 'I couldn't do it' instead of an address. Websites whose names "
                "fail like this won't load. SERVFAIL usually means the server can't reach the internet's DNS "
                "(or a domain's own DNS is broken)."),
            cause=(f"The domain {clip(top_dom, 60)} has broken DNS (or DNSSEC) on its side" if concentrated
                   else f"The resolver {srv0} cannot reach upstream DNS servers (upstream outage or DNSSEC failure)"),
            fix=[f"Compare: `nslookup example.com {srv0}` and `nslookup example.com 1.1.1.1` (or `dig example.com @{srv0}`).",
                 "Restart the DNS server / router; check its upstream (WAN) connection.",
                 "Temporarily switch devices to a public resolver (1.1.1.1 / 8.8.8.8) to confirm.",
                 "If only one domain fails, the problem is on that domain's side: contact its owner or wait."],
            analogy="Like directory enquiries answering 'sorry, our system is down' to every call.",
            severity=sev,
        )
        misconf = Variant(
            title=f"DNS server {srv0} refuses to answer these devices",
            summary=f"{refused} DNS lookups were REFUSED by {srv0}.",
            explanation=("REFUSED means the server works but won't answer you, typically because it isn't meant to be "
                         "your resolver (an authoritative-only server) or because an access list blocks your network."),
            cause=f"Devices point to a DNS server ({srv0}) that does not allow recursive queries from them.",
            fix=["Check which DNS servers DHCP hands out (`ipconfig /all`).",
                 f"Allow this subnet in {srv0}'s recursion ACL, or point devices to the correct resolver.",
                 f"Test with `dig example.com @{srv0}`: look for 'status: REFUSED'."],
            analogy="Like ringing a company's private line: it answers, but only to say it won't take your call.",
            severity=Severity.MEDIUM if ratio >= 0.2 else Severity.LOW,
        )
        ev = evidence_of(self.err_frames, total=n, first_ts=min(self.err_ts) if self.err_ts else None,
                         last_ts=max(self.err_ts) if self.err_ts else None)
        tech = ("Error rcodes: " + ", ".join(f"{RCODE_NAMES.get(r, r)}={c}" for r, c in self.errors.most_common())
                + f" of {self.responses} answers. Per server: "
                + ", ".join(f"{ip} {c}" for ip, _, c in per_srv[:4])
                + ". Top names: " + ", ".join(f"{clip(nm, 60)} ({c})" for nm, c in self.err_names.most_common(4)) + ".")
        metrics = {"errors": n, "responses": self.responses, "ratio": round(ratio, 3),
                   "rcodes": {RCODE_NAMES.get(r, str(r)): c for r, c in self.errors.items()},
                   "servers": {ip: c for ip, _, c in per_srv[:10]},
                   "top_names": [[clip(nm, 100), c] for nm, c in self.err_names.most_common(10)]}
        variants = {F: fault}
        if refused:
            variants[M] = misconf
        return make_finding("dns.errors", variants, ind, technical=tech, hosts=[ip for ip, _, _ in per_srv[:5]],
                            metrics=metrics, evidence=ev, default=M if refused / n >= 0.5 else F)

    # -- slow ------------------------------------------------------------------ #
    def _find_slow(self, ctx: AnalysisContext, scale: float):
        slow = []
        fast = []
        for ip, s in self.servers.items():
            med = s.median()
            if med is None or s.answered < 3:
                continue
            if (s.answered >= 5 and med >= 0.3) or s.slow >= 3:
                slow.append((ip, s, med))
            elif med < 0.1 and s.answered >= 3:
                fast.append((ip, s, med))
        if not slow:
            return None
        slow.sort(key=lambda r: -r[2])
        ip0, s0, med0 = slow[0]
        F, M = Category.FAULT, Category.MISCONFIG
        ind = [Indicator(f"DNS server {ip0} takes {fmt_ms(med0)} per answer (median of {s0.answered})", F, 1.5)]
        if s0.slow >= 3:
            ind.append(Indicator(f"{s0.slow} answers took longer than 1 second", F, 1.0))
        if s0.late:
            ind.append(Indicator(f"{s0.late} answers came after {self.TIMEOUT:.0f} s, when devices had already given up", F, 0.5))
        if fast:
            ind.append(Indicator(f"Another DNS server on this network ({fast[0][0]}) answers in {fmt_ms(fast[0][2])}: "
                                 "devices could use it instead", M, 1.0))
        sev = Severity.MEDIUM if med0 >= 0.5 or s0.slow >= 10 else Severity.LOW
        fault = Variant(
            title=f"DNS lookups are slow ({fmt_ms(med0)} via {ip0})",
            summary=f"Your DNS server {ip0} needs {fmt_ms(med0)} on average to answer ({s0.slow} answers took over 1 s).",
            explanation=("Every new website first needs a DNS lookup. When the DNS server is slow, every page feels "
                         "sluggish to start loading even though downloads themselves are fast."),
            cause=f"The DNS server {ip0} is overloaded, far away, or its upstream connection is congested.",
            fix=[f"Measure: `dig example.com @{ip0}` and look at 'Query time'; compare with `dig example.com @1.1.1.1`.",
                 "Restart the router / DNS server; check its CPU load and upstream link.",
                 "Switch to a faster resolver in the DHCP or device settings if the problem persists."],
            analogy="Like a librarian who takes minutes to find each book's shelf number.",
            severity=sev,
        )
        misconf = Variant(
            title=f"Devices use a slow DNS server ({ip0}) while a fast one is available",
            summary=f"{ip0} answers in {fmt_ms(med0)} but {fast[0][0] if fast else 'another server'} answers much faster.",
            explanation="Devices are configured with a slow DNS server although a faster one exists on this network.",
            cause="Suboptimal DNS server order in DHCP or device settings.",
            fix=["Put the faster DNS server first in the DHCP settings.", "Renew leases (`ipconfig /renew`)."],
            analogy="Like queueing at the slow counter when the next one is empty.",
            severity=Severity.LOW,
        )
        frames = [no for _, s, _ in slow for no in s.slow_frames]
        ev = evidence_of(frames, total=sum(s.slow for _, s, _ in slow))
        tech = "Per server: " + "; ".join(
            f"{ip} median {fmt_ms(m)}, {s.slow} ≥1 s, {s.late} after timeout, n={s.answered}" for ip, s, m in slow[:4])
        if fast:
            tech += "; fast: " + ", ".join(f"{ip} {fmt_ms(m)}" for ip, _, m in fast[:3])
        metrics = {"servers": {ip: {"median_ms": round(m * 1000, 1), "over_1s": s.slow, "answered": s.answered}
                               for ip, s, m in slow[:10]},
                   "fast_servers": [ip for ip, _, _ in fast[:5]]}
        variants = {F: fault}
        if fast:
            variants[M] = misconf
        return make_finding("dns.slow", variants, ind, technical=tech, hosts=[ip for ip, _, _ in slow[:5]],
                            metrics=metrics, evidence=ev, default=F)

    # -- NXDOMAIN ---------------------------------------------------------------- #
    def _find_nxdomain(self, ctx: AnalysisContext, scale: float):
        if self.nx < 20 * scale or not self.responses or self.nx / self.responses < 0.3:
            return None
        ratio = self.nx / self.responses
        names = list(self.nx_names)
        multi = [n for n in names if "." in n]
        # Chrome's random single-label probes and other single-label names are not DGA material
        dga_cands = [n for n in multi if not n.endswith(INTERNAL_SUFFIXES)]
        rnd = [n for n in dga_cands if randomish(n.split(".")[0] if len(n.split(".")) <= 2 else
                                                  max(n.split(".")[:-1], key=len))]
        rnd_domains = {registered_domain(n) for n in rnd}
        suffixes = Counter()
        for n in multi:
            parts = n.split(".")
            if len(parts) >= 3:
                suffixes[".".join(parts[-2:])] += self.nx_names[n]
        top_suffix, top_suffix_n = suffixes.most_common(1)[0] if suffixes else ("", 0)
        single = [n for n in names if "." not in n]
        A, M = Category.ATTACK, Category.MISCONFIG
        ind = [Indicator(f"{self.nx} lookups ({fmt_frac(ratio)} of answers) were for names that don't exist", M, 0.5)]
        rnd_frac = len(rnd) / max(1, len(dga_cands))
        if len(rnd_domains) >= 10 and rnd_frac >= 0.5:
            ind.append(Indicator(f"{len(rnd_domains)} different random-looking domains failed (e.g. "
                                 f"{', '.join(sorted(rnd)[:2])}), the pattern of malware searching for its "
                                 "command server (DGA)", A, 3.0))
        elif len(rnd_domains) >= 5:
            ind.append(Indicator(f"{len(rnd_domains)} random-looking domains failed", A, 1.0))
        clients = self.nx_clients.most_common(3)
        if clients and clients[0][1] / self.nx >= 0.8 and len(rnd_domains) >= 5:
            ind.append(Indicator(f"Most failures come from one device ({clients[0][0]})", A, 0.5))
        if top_suffix and top_suffix_n / self.nx >= 0.5 and (is_internal_name("x." + top_suffix) or
                                                             len({registered_domain(n) for n in multi}) <= 3):
            ind.append(Indicator(f"Most failed names end in the same suffix '{clip(top_suffix, 40)}': a search "
                                 "domain is being appended to every lookup", M, 2.0))
        uniq = len(names)
        if uniq and self.nx / uniq >= 3:
            ind.append(Indicator(f"Only {uniq} different names fail, over and over: a device has a stale or "
                                 "mistyped setting", M, 1.5))
        if single and len(single) / max(1, uniq) >= 0.3:
            ind.append(Indicator(f"{len(single)} single-word names (like '{clip(single[0], 30)}') were sent to DNS: "
                                 "a missing search domain", M, 1.0))
        if len(rnd_domains) < 3:
            ind.append(Indicator("The failing names look human-made, not random", M, 1.0))
        top = [clip(n, 80) for n, _ in self.nx_names.most_common(5)]
        misconf = Variant(
            title="Many lookups for names that don't exist",
            summary=f"{self.nx} DNS lookups ({fmt_frac(ratio)}) failed with 'no such name', mostly {', '.join(top[:2])}.",
            explanation=("Devices keep asking for names that don't exist. Usually a setting points at an old server "
                         "name, a typo, or a 'search domain' is added to every name. It wastes time and can slow "
                         "down apps that wait for these lookups."),
            cause="A stale or mistyped hostname in an app/device setting, or a wrong DNS search domain.",
            fix=["Look at the failing names below and find which app or device uses them (`ipconfig /all` shows the "
                 "DNS suffix search list).",
                 "Correct the hostname in that app/device, or remove the wrong search domain from DHCP settings.",
                 "Test a name directly: `nslookup <name>`."],
            analogy="Like repeatedly looking up a friend in the phone book under a misspelled name.",
            severity=Severity.LOW if ratio < 0.6 else Severity.MEDIUM,
        )
        attack = Variant(
            title="Possible malware: lookups for random-looking domains (DGA)",
            summary=f"{len(rnd)} random-looking names across {len(rnd_domains)} domains failed, e.g. {', '.join(sorted(rnd)[:2])}.",
            explanation=(
                "Some malware generates hundreds of random domain names each day and tries them all, because its "
                "operator registers only one. Almost all of them fail with 'no such name'. A device doing this "
                "is very likely infected."),
            cause=f"Malware with a domain generation algorithm on {clients[0][0] if clients else 'a device'}.",
            fix=[f"Isolate {clients[0][0] if clients else 'the device'} from the network.",
                 "Run a full anti-malware scan (or reinstall) on it.",
                 "Block the domains at your DNS resolver and watch for the same pattern on other devices.",
                 "Change passwords used on that device."],
            analogy="Like a burglar trying hundreds of random phone numbers to find the one that reaches his boss.",
            mitre="T1568.002 Dynamic Resolution: Domain Generation Algorithms",
            severity=Severity.HIGH,
        )
        ev = evidence_of(self.nx_frames, total=self.nx, first_ts=min(self.nx_ts) if self.nx_ts else None,
                         last_ts=max(self.nx_ts) if self.nx_ts else None)
        tech = (f"{self.nx} NXDOMAIN of {self.responses} answers; {uniq} distinct names; {len(rnd)} random-looking "
                f"across {len(rnd_domains)} registered domains; top suffix {clip(top_suffix, 40) or '-'} "
                f"({top_suffix_n}); top clients " + ", ".join(f"{c} ({n})" for c, n in clients) + ".")
        metrics = {"nxdomain": self.nx, "responses": self.responses, "ratio": round(ratio, 3), "distinct_names": uniq,
                   "random_names": len(rnd), "random_domains": len(rnd_domains), "top_names": top,
                   "top_suffix": clip(top_suffix, 60), "clients": [c for c, _ in clients]}
        variants = {M: misconf}
        if len(rnd_domains) >= 5:
            variants[A] = attack
        return make_finding("dns.nxdomain", variants, ind, technical=tech, hosts=[c for c, _ in clients],
                            metrics=metrics, evidence=ev, default=M)

    # -- hijack -------------------------------------------------------------------- #
    def _find_hijack(self, ctx: AnalysisContext, scale: float):
        races = self.races
        unexpected = self.unexpected
        # private answers for public domains, grouped per answer IP
        groups = []
        for ip, e in self.pubpriv.items():
            doms = {d for d in e["domains"] if d not in self.public_answers}
            if not doms:
                continue
            groups.append((ip, e, doms))
        all_priv_domains = set().union(*(g[2] for g in groups)) if groups else set()
        own_domain_like = len(all_priv_domains) <= 2 and not races and not unexpected
        linked = []   # (ip, why)
        portal = None
        A, M = Category.ATTACK, Category.MISCONFIG
        gw_ips, _ = ctx.hosts.gateway()
        real_gw = _real_gateways(ctx, gw_ips)
        several_dhcp = len(ctx.hosts.dhcp_servers) >= 2
        for ip, e, doms in groups:
            eth = e["eth"].most_common(1)[0][0] if e["eth"] else None
            h = ctx.hosts.hosts.get(ip)
            if e["self"] >= max(1, e["n"] // 2):
                if several_dhcp and h is not None and "dhcp-server" in h.roles and ip not in real_gw:
                    linked.append((ip, "the DNS server handed out by a second (rogue) DHCP server, answering "
                                       "with its own address"))
                elif len(doms) >= 5:
                    portal = (ip, e, doms, "resolver")
                continue
            if ip in gw_ips:
                if len(doms) >= 5:
                    portal = (ip, e, doms, "gateway")
                continue
            if eth and (ip in ctx.hosts.mac_ips.get(eth, ()) or eth in ctx.hosts.arp_claims.get(ip, {})):
                linked.append((ip, f"the very device ({eth}) that delivered the DNS answers"))
            elif h is not None and "dhcp-server" in h.roles:
                linked.append((ip, "a device that is also running its own DHCP server"))
        fire_attack = bool(races) or self.unexpected_total >= 3 or bool(linked) or \
            (len(all_priv_domains) >= 3 and not own_domain_like and portal is None)
        fire_misconf = portal is not None
        if not fire_attack and not fire_misconf:
            return None

        ind: list[Indicator] = []
        forged_ips: Counter = Counter()
        legit_ips: Counter = Counter()
        forger_eth: Counter = Counter()
        names: list[str] = []
        frames: list[int] = []
        fast = 0
        for r in races:
            f, s = self._which_forged(r)
            forged_ips.update(f["addrs"][:3])
            legit_ips.update(s["addrs"][:3])
            if f.get("eth"):
                forger_eth[f["eth"]] += 1
            srv = self.servers.get(r["q"]["server"])
            med = srv.median() if srv else None
            if f.get("rtt") is not None and f["rtt"] < 0.001 and med is not None and med >= 0.01:
                fast += 1
            if len(names) < 20:
                names.append(r["q"]["qname"])
            frames += [r["q"]["no"], r["first"]["no"], r["second"]["no"]]
        if races:
            r0 = races[0]
            f0, s0 = self._which_forged(r0)
            ind.append(Indicator(
                f"{plural(self.race_total, 'lookup')} got two different answers to the same question (e.g. "
                f"{clip(r0['q']['qname'], 60)}: {', '.join(f0['addrs'][:2]) or RCODE_NAMES.get(f0['rcode'], 'empty')} "
                f"and {', '.join(s0['addrs'][:2]) or RCODE_NAMES.get(s0['rcode'], 'empty')})", A, 3.0))
            if fast:
                ind.append(Indicator(f"{plural(fast, 'fake answer')} arrived in under 1 ms, far faster than the real "
                                     "server ever answers: it was sent from inside your network", A, 1.5))
            srv0 = self.servers.get(r0["q"]["server"])
            usual = srv0.eth.most_common(1)[0][0] if srv0 and srv0.eth else None
            if forger_eth and usual and forger_eth.most_common(1)[0][0] != usual:
                fe = forger_eth.most_common(1)[0][0]
                ind.append(Indicator(f"The fake answers came from MAC {fe}, not via {usual} like the server's normal answers", A, 1.5))
        if self.unexpected_total:
            u0 = unexpected[0]
            ind.append(Indicator(f"{plural(self.unexpected_total, 'answer')} came from a server the device never asked "
                                 f"(asked {u0['q']['server']}, answer from {u0['resp']['server']})", A,
                                 2.0 if self.unexpected_total >= 3 else 1.5))
            for u in unexpected[:20]:
                frames += [u["q"]["no"], u["resp"]["no"]]
                forged_ips.update(u["resp"]["addrs"][:3])
                if u["resp"].get("eth"):
                    forger_eth[u["resp"]["eth"]] += 1
                if len(names) < 20:
                    names.append(u["q"]["qname"])
        priv_groups = [g for g in groups if portal is None or g[0] != portal[0]]
        if priv_groups and (len(all_priv_domains) >= 3 or linked or races or unexpected) and not own_domain_like:
            ip, e, doms = max(priv_groups, key=lambda g: len(g[2]))
            ind.append(Indicator(f"Public websites resolved to a local address: {', '.join(sorted(e['names'])[:3])} "
                                 f"→ {ip}", A, 1.0))
            for g in priv_groups[:5]:
                forged_ips[g[0]] += g[1]["n"]
                frames += g[1]["frames"][:30]
                names += sorted(g[1]["names"])[:5]
                if g[1]["eth"]:
                    forger_eth.update(g[1]["eth"])
        for ip, why in linked[:2]:
            ind.append(Indicator(f"The fake address {ip} is {why}, not the router", A, 2.0))
        ttls = [t for g in priv_groups for t in g[1]["ttls"]] + [r["first"]["ttl"] for r in races if r["first"].get("ttl") is not None]
        if ttls and (max(ttls) <= 10 or (len(ttls) >= 3 and len(set(ttls)) == 1 and (ttls[0] <= 30 or ttls[0] >= 604800))):
            ind.append(Indicator(f"The suspicious answers carry an odd, fixed time-to-live ({ttls[0]} s)", A, 0.5))
        aa_srv = []
        for ip, e, _ in priv_groups:
            for srv_ip, cnt in e["servers"].items():
                s = self.servers.get(srv_ip)
                if s and e["aa"] and s.responses >= 5 and s.aa / s.responses < 0.5:
                    aa_srv.append(srv_ip)
        if aa_srv:
            ind.append(Indicator(f"The suspicious answers claim to be authoritative, unlike {aa_srv[0]}'s normal answers", A, 1.0))
        if portal is not None:
            pip, pe, pdoms, what = portal
            ind.append(Indicator(f"{len(pdoms)} different websites all resolve to {pip}, which is the "
                                 f"{'DNS server itself' if what == 'resolver' else 'router'}: typical of a captive "
                                 "portal (guest/hotel Wi-Fi login page) or DNS-based filtering", M, 2.5))
            frames += pe["frames"][:40]
            names += sorted(pe["names"])[:5]
        if not races:
            ind.append(Indicator("No lookup received two conflicting answers", M, 0.5 if fire_attack else 1.0))

        sc_names = []
        for n in names:
            if n not in sc_names:
                sc_names.append(n)
        fi = [ip for ip, _ in forged_ips.most_common(5)]
        li = [ip for ip, _ in legit_ips.most_common(5)]
        fe = forger_eth.most_common(1)[0][0] if forger_eth else None
        forger_ip = None
        if fe:
            cand = [ip for ip in ctx.hosts.mac_ips.get(fe, ()) if is_private(ip)]
            forger_ip = sorted(cand)[0] if cand else None
        who = f"{forger_ip} ({fe})" if forger_ip else (fe or "a device on your network")
        dom_txt = ", ".join(clip(n, 60) for n in sc_names[:3]) or "some websites"
        attack = Variant(
            title="DNS answers are being forged",
            summary=(f"Someone is sending fake DNS answers for {dom_txt}"
                     + (f", pointing them to {', '.join(fi[:2])}" if fi else "") + "."),
            explanation=(
                "DNS is the internet's phone book: it turns names into addresses. Here a device is answering name "
                "lookups with fake addresses before (or instead of) the real server, so you may land on a copy of a "
                "website built to steal passwords, or have your traffic secretly routed through the attacker."),
            cause=f"DNS spoofing from {who}, typically combined with ARP spoofing or a rogue DHCP server "
                  "(tools such as ettercap dns_spoof, bettercap, dnschef).",
            fix=[
                f"Find and disconnect {who}: look up its MAC in the switch MAC table or router client list.",
                f"Check what real DNS says: `nslookup {clip(sc_names[0], 60) if sc_names else 'example.com'} 1.1.1.1` "
                "and compare with what your device got.",
                "Flush DNS caches on affected devices (`ipconfig /flushdns`; macOS `sudo dscacheutil -flushcache`).",
                "Check for ARP spoofing / rogue DHCP (`arp -a`, `ipconfig /all`); enable DHCP snooping and Dynamic ARP Inspection.",
                "Use encrypted DNS (DoH/DoT) and HTTPS; treat credentials entered meanwhile as exposed.",
            ],
            analogy="Like someone swapping the numbers in your phone book so your calls to the bank reach a fraudster.",
            mitre="T1557 Adversary-in-the-Middle",
            severity=Severity.CRITICAL if (races and fi and any(is_private(i) for i in fi)) or linked else Severity.HIGH,
        )
        pip = portal[0] if portal else (fi[0] if fi else "?")
        misconf = Variant(
            title="Captive portal or split-horizon DNS is redirecting names",
            summary=(f"{len(portal[2]) if portal else len(all_priv_domains)} public domains resolve to the local address {pip}."),
            explanation=("On guest/hotel Wi-Fi the network answers every name with the address of its login page "
                         "until you sign in; some company networks also answer public names with internal "
                         "addresses on purpose. Nothing malicious is required to explain this."),
            cause="A captive portal (login page) or DNS filtering / split-horizon DNS on the network.",
            fix=["Open a browser and go to http://neverssl.com to trigger the Wi-Fi login page; sign in.",
                 f"Compare with `nslookup example.com 1.1.1.1`: once logged in, names should resolve normally.",
                 "If you don't expect a portal on this network, treat it as DNS hijacking and check the router."],
            analogy="Like a hotel receptionist sending every visitor to the front desk before letting them in.",
            severity=Severity.LOW,
        )
        ev = evidence_of(frames, total=self.race_total * 2 + self.unexpected_total + sum(g[1]["n"] for g in groups))
        tech = (f"Conflicting answers to one transaction: {self.race_total}; answers from unqueried servers: "
                f"{self.unexpected_total}; private answers for public domains: "
                + ", ".join(f"{ip} ← {len(doms)} domains" for ip, _, doms in groups[:4])
                + f". Forged IPs: {', '.join(fi) or '-'}; legit IPs: {', '.join(li) or '-'}; forging MAC: {fe or '-'}"
                + (f" ({forger_ip})" if forger_ip else "")
                + (f"; portal {portal[0]} ({portal[3]})" if portal else "") + ".")
        metrics = {"races": self.race_total, "unexpected_server": self.unexpected_total, "domains": [clip(n, 100) for n in sc_names[:10]],
                   "forged_ips": fi, "legit_ips": li, "forger_mac": fe, "forger_ip": forger_ip,
                   "portal_ip": portal[0] if portal else None, "fast_forgeries": fast}
        variants = {}
        if fire_attack:
            variants[A] = attack
        variants[M] = misconf
        hosts = ([forger_ip] if forger_ip else []) + fi[:3] + ([portal[0]] if portal else [])
        return make_finding("dns.hijack", variants, ind, technical=tech, hosts=hosts, metrics=metrics, evidence=ev,
                            default=A if fire_attack else M)

    def _which_forged(self, r: dict) -> tuple[dict, dict]:
        """Return (forged, legit) responses of a race."""
        a, b = r["first"], r["second"]
        srv = self.servers.get(r["q"]["server"])
        usual = srv.eth.most_common(1)[0][0] if srv and srv.eth else None
        if usual:
            if a.get("eth") != usual and b.get("eth") == usual:
                return a, b
            if b.get("eth") != usual and a.get("eth") == usual:
                return b, a
        pa = any(is_private(x) for x in a["addrs"])
        pb = any(is_private(x) for x in b["addrs"])
        if pb and not pa:
            return b, a
        return a, b  # the faster one is usually the forgery

    # -- tunneling ---------------------------------------------------------------- #
    def _find_tunneling(self, ctx: AnalysisContext, scale: float):
        out = []
        min_subs = max(10, int(round(50 * scale)))
        min_txt_subs = max(10, int(round(30 * scale)))
        for reg, dm in self.domains.items():
            nsub = len(dm.subs)
            if nsub < min_txt_subs:
                continue
            mean_len = dm.sum_len / nsub
            mean_ent = dm.sum_ent / nsub
            txt_ratio = dm.txt / dm.queries
            classic = nsub >= min_subs and mean_len >= 20 and mean_ent >= 3.5
            txty = txt_ratio >= 0.5 and dm.queries >= 50 * scale and mean_len >= 12 and mean_ent >= 3.0
            if not (classic or txty):
                continue
            A = Category.ATTACK
            dur = max(1.0, (dm.last_ts or dm.first_ts) - dm.first_ts)
            ind = [Indicator(f"{nsub} different sub-names were looked up under {clip(reg, 60)}", A, 2.0)]
            if mean_len >= 20 and mean_ent >= 3.5:
                ind.append(Indicator(f"The sub-names are long ({mean_len:.0f} characters on average) and random-looking "
                                     f"({mean_ent:.1f} bits/char), like encoded data", A, 1.5))
            if txt_ratio >= 0.3:
                ind.append(Indicator(f"{fmt_frac(txt_ratio)} of the lookups ask for TXT/NULL records, which carry "
                                     "arbitrary data back", A, 1.5))
            cv = None
            if dm.iv_n >= 20:
                m = dm.iv_sum / dm.iv_n
                if m > 0:
                    cv = max(0.0, dm.iv_sq / dm.iv_n - m * m) ** 0.5 / m
                    if cv < 0.3:
                        ind.append(Indicator(f"Lookups repeat at a steady rhythm (every {m:.1f} s), like a "
                                             "program beaconing home", A, 1.0))
            if len(dm.clients) == 1:
                ind.append(Indicator(f"All of it comes from one device ({next(iter(dm.clients))})", A, 0.5))
            clients = sorted(dm.clients)
            attack = Variant(
                title=f"Data hidden in DNS lookups (DNS tunneling via {clip(reg, 50)})",
                summary=(f"{clients[0] if clients else 'A device'} made {dm.queries:,} lookups for {nsub} random-looking "
                         f"names under {clip(reg, 60)} ({dm.bytes:,} bytes of names)."),
                explanation=(
                    "DNS lookups are almost always allowed through firewalls, so malware and tunneling tools hide data "
                    "inside the names they look up (for example 'a8f3k2...data.evil.com'). Thousands of unique, random "
                    "names under one domain are the tell-tale sign of data being smuggled in or out this way."),
                cause=f"A DNS tunnel (iodine, dnscat2, DNSExfiltrator) or malware command channel on "
                      f"{', '.join(clients[:3]) or 'a device'} using {clip(reg, 60)}.",
                fix=[f"Isolate {clients[0] if clients else 'the device'} and check it for malware or tunneling software.",
                     f"Block {clip(reg, 60)} on your DNS resolver/firewall.",
                     "Only allow DNS to your own resolver (block outbound port 53 elsewhere) and log queries.",
                     "If the domain belongs to your antivirus or a known service, confirm with the vendor before blocking."],
                analogy="Like smuggling notes out of a building by writing them on the envelopes of letters to the same address.",
                mitre="T1071.004 Application Layer Protocol: DNS",
                severity=Severity.HIGH,
            )
            ev = evidence_of(dm.frames, total=dm.queries, first_ts=dm.first_ts, last_ts=dm.last_ts)
            tech = (f"{reg}: {dm.queries} queries, {nsub} unique subdomains, mean length {mean_len:.1f}, mean entropy "
                    f"{mean_ent:.2f} bits/char, TXT/NULL ratio {txt_ratio:.2f}, {dm.queries / dur:.2f} q/s"
                    + (f", inter-arrival CV {cv:.2f}" if cv is not None else "")
                    + f"; clients {', '.join(clients[:5])}; samples: {'; '.join(dm.samples[:3])}.")
            metrics = {"domain": clip(reg, 100), "queries": dm.queries, "unique_subdomains": nsub,
                       "mean_label_len": round(mean_len, 1), "entropy": round(mean_ent, 2),
                       "txt_ratio": round(txt_ratio, 3), "clients": clients[:10], "samples": dm.samples[:5],
                       "bytes": dm.bytes}
            out.append(make_finding("dns.tunneling", {A: attack}, ind, technical=tech, hosts=clients[:5],
                                    metrics=metrics, evidence=ev, default=A))
        out.sort(key=lambda f: -f.metrics["queries"])
        return out[:5]


def _real_gateways(ctx: AnalysisContext, gw_ips) -> set[str]:
    """Gateway IPs whose ARP owner really forwards internet traffic. ``HostTable.gateway()``
    also trusts DHCP router options, which a rogue DHCP server controls."""
    fwd = {mac for mac, ips in ctx.hosts.mac_ips.items() if sum(1 for i in ips if not is_private(i)) >= 3}
    out = set()
    for ip in gw_ips:
        claims = ctx.hosts.arp_claims.get(ip)
        if claims and claims.most_common(1)[0][0] in fwd:
            out.add(ip)
        elif not claims and ip in {i for m in fwd for i in ctx.hosts.mac_ips.get(m, ()) if is_private(i)}:
            out.add(ip)
    return out


def _qinfo(q: _Q) -> dict:
    return {"ts": q.ts, "no": q.no, "client": q.client, "server": q.server, "qname": clip(q.qname, 100), "qid": q.qid}
