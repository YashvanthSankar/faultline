"""Per-connection timing: where does the time go?

Two independent clocks are read from every TCP connection:

1. **Handshake RTT, split at the capture point.** SYN → SYN/ACK is the round
   trip from the capture point to the *server* and back; SYN/ACK → ACK is the
   round trip from the capture point to the *client* and back. Comparing the
   two legs tells whether delay sits on the near (LAN / Wi-Fi / VPN client)
   side or the far (WAN / ISP / server) side of where the capture was taken.
   Samples follow Karn's rule: a retransmitted SYN or SYN/ACK is ambiguous and
   skipped.

2. **Server think time.** For request/response traffic the client "has the
   turn" while it sends a request; the time from the request's last new byte
   to the server's first new response byte, minus the capture-to-server
   round trip, is time the server spent working. Turns with retransmitted
   requests or a missing first response segment are skipped (otherwise the
   network's loss recovery would be blamed on the server).

Kinds produced: ``latency.high_rtt``, ``latency.slow_server``.
"""

from __future__ import annotations

import math

from ..context import is_private
from .base import (
    AnalysisContext, BoundedDict, Category, Detector, Evidence, Finding, Indicator,
    Packet, Severity, fmt_ms, plural, register,
)

MASK = 0xFFFFFFFF
HALF = 0x80000000
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10

#: request/response services where "first response byte" is meaningful for
#: opaque (non-HTTP) payloads; push/stream protocols are deliberately absent
REQRESP_PORTS = frozenset({
    80, 443, 8000, 8008, 8080, 8443, 8888, 3000, 5000, 9000, 389, 636, 1433, 1521, 3306, 5432,
    5984, 7474, 9200, 9300,
})
MAX_SAMPLES = 2000
MAX_THINK = 60.0  # beyond this it's long-polling / push, not processing


def sdiff(a: int, b: int) -> int:
    return ((a - b + HALF) & MASK) - HALF


def scaled(n: float, ctx: AnalysisContext) -> int:
    return max(1, math.ceil(n * ctx.config.scale))


def _cap(s, n: int = 100) -> str:
    s = "" if s is None else str(s)
    return "".join(ch if ch.isprintable() else " " for ch in s)[:n]


def pct(sorted_vals: list, q: float) -> float | None:
    """Linear-interpolated percentile of an already sorted list."""
    if not sorted_vals:
        return None
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    pos = (len(sorted_vals) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(sorted_vals) - 1)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (pos - lo)


def ms(x: float | None) -> float | None:
    return None if x is None else round(x * 1000, 1)


class _LFlow:
    __slots__ = (
        "client", "syn_ts", "syn_count", "synack_ts", "synack_count", "synack_no", "hs_done",
        "base", "nxt", "turn", "req_first", "req_last", "req_no", "req_bad", "srv_last", "http", "rtt_s",
        "eligible", "fid",
    )

    def __init__(self, fid: int) -> None:
        self.client = None
        self.syn_ts = None
        self.syn_count = 0
        self.synack_ts = None
        self.synack_count = 0
        self.synack_no = None
        self.hs_done = False
        self.base = [False, False]
        self.nxt = [0, 0]
        self.turn = None
        self.req_first = self.req_last = None
        self.req_no = None
        self.req_bad = False
        self.srv_last = None
        self.http = False
        self.rtt_s = None
        self.eligible = None
        self.fid = fid


class _Srv:
    __slots__ = ("hs", "resp", "client_think", "port_hint")

    def __init__(self) -> None:
        self.hs: list = []  # (total, server_leg, client_leg, synack_no, ts)
        self.resp: list = []  # (think, adjusted, http, fid, req_no, resp_no, status, ts, rtt_s)
        self.client_think: list = []
        self.port_hint = None


@register
class LatencyDetector(Detector):
    name = "latency"

    def __init__(self) -> None:
        self.flows: BoundedDict = BoundedDict(200_000)
        self.rtt_by_ip: BoundedDict = BoundedDict(20_000)  # server ip -> _Srv (handshakes)
        self.svc: BoundedDict = BoundedDict(20_000)  # (server ip, port) -> _Srv (responses)
        self._fid = 0

    # ------------------------------------------------------------------ #
    def on_packet(self, pkt: Packet, ctx: AnalysisContext) -> None:
        t = pkt.tcp
        if t is None or pkt.src is None or pkt.dst is None:
            return
        sport, dport, seq = t.sport, t.dport, t.seq
        if sport is None or dport is None or seq is None:
            return
        ts = pkt.ts if isinstance(pkt.ts, (int, float)) else 0.0
        fl = t.flags or 0
        plen = t.plen or 0
        if (pkt.src, sport) <= (pkt.dst, dport):
            key, d = (pkt.src, sport, pkt.dst, dport), 0
        else:
            key, d = (pkt.dst, dport, pkt.src, sport), 1
        f = self.flows.get(key)
        if f is None or (fl & SYN and not fl & ACK and f.client is not None and f.client == d and f.hs_done):
            self._fid += 1
            f = self.flows[key] = _LFlow(self._fid)

        if fl & RST:
            f.turn = None
            return
        if fl & SYN:
            if not fl & ACK:
                if f.client is None:
                    f.client = d
                f.syn_count += 1
                if f.syn_count == 1:
                    f.syn_ts = ts
                f.base[d], f.nxt[d] = True, seq + 1 + plen
            else:
                if f.client is None:
                    f.client = 1 - d
                f.synack_count += 1
                if f.synack_count == 1:
                    f.synack_ts, f.synack_no = ts, pkt.no
                    if f.syn_ts is not None and f.syn_count == 1 and ts >= f.syn_ts:
                        f.rtt_s = ts - f.syn_ts
                f.base[d], f.nxt[d] = True, seq + 1
            return

        if not f.hs_done and f.client is not None and d == f.client and fl & ACK and f.synack_ts is not None:
            f.hs_done = True
            if f.syn_count == 1 and f.synack_count == 1 and f.syn_ts is not None and ts >= f.synack_ts >= f.syn_ts:
                self._hs_sample(key, d, f, ts)

        if plen <= 0:
            return
        # new data or not?
        if not f.base[d]:
            f.base[d] = True
            f.nxt[d] = seq + plen
            new, gap = True, True  # unknown history: usable as a request, not as a response
        else:
            seq_u = f.nxt[d] + sdiff(seq, f.nxt[d] & MASK)
            end_u = seq_u + plen
            if plen <= 1 and seq_u == f.nxt[d] - 1:
                return  # keepalive
            new = end_u > f.nxt[d]
            gap = seq_u > f.nxt[d]
            if end_u > f.nxt[d]:
                f.nxt[d] = end_u
        if f.client is None:  # mid-stream: guess the client from the ports
            a_srv = key[1] in REQRESP_PORTS
            b_srv = key[3] in REQRESP_PORTS
            if a_srv == b_srv:
                return
            f.client = 1 if a_srv else 0
        if pkt.http is not None and pkt.http.is_request and d == f.client:
            f.http = True
        if f.eligible is None:
            srv_port = key[3] if f.client == 0 else key[1]
            f.eligible = srv_port in REQRESP_PORTS
        if not (f.eligible or f.http):
            return

        if d == f.client:
            if new:
                if f.turn != "c":
                    f.req_first, f.req_bad, f.req_no = ts, False, pkt.no
                    if f.srv_last is not None and ts >= f.srv_last:
                        srv = self._svc(key, f)
                        if len(srv.client_think) < MAX_SAMPLES:
                            srv.client_think.append(ts - f.srv_last)
                f.turn = "c"
                f.req_last = ts
            elif f.turn == "c":
                f.req_bad = True  # request retransmitted: timing would include loss recovery
        else:
            if not new:
                return
            if f.turn == "c" and not gap and not f.req_bad and f.req_last is not None:
                think = ts - f.req_last
                if 0 <= think <= MAX_THINK:
                    adj = max(0.0, think - (f.rtt_s or 0.0))
                    srv = self._svc(key, f)
                    status = pkt.http.status if (pkt.http is not None and not pkt.http.is_request) else None
                    if len(srv.resp) < MAX_SAMPLES:
                        srv.resp.append((think, adj, f.http, f.fid, f.req_no, pkt.no, status, ts, f.rtt_s))
            f.turn = "s"
            f.srv_last = ts

    def _svc(self, key, f: _LFlow) -> _Srv:
        sk = (key[2], key[3]) if f.client == 0 else (key[0], key[1])
        s = self.svc.get(sk)
        if s is None:
            s = self.svc[sk] = _Srv()
        return s

    def _hs_sample(self, key, d, f: _LFlow, ts: float) -> None:
        server = key[2] if d == 0 else key[0]
        s = self.rtt_by_ip.get(server)
        if s is None:
            s = self.rtt_by_ip[server] = _Srv()
            s.port_hint = key[3] if d == 0 else key[1]
        if len(s.hs) < MAX_SAMPLES:
            sl = f.synack_ts - f.syn_ts
            cl = ts - f.synack_ts
            s.hs.append((sl + cl, sl, cl, f.synack_no, f.synack_ts))

    # ------------------------------------------------------------------ #
    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        out: list[Finding] = []
        for fn in (self._f_high_rtt, self._f_slow_server):
            try:
                out.extend(fn(ctx))
            except Exception:  # pragma: no cover - never let one finding break the report
                continue
        return out

    # ================================================================== #
    # latency.high_rtt
    # ================================================================== #
    @staticmethod
    def _rtt_stats(samples: list) -> dict:
        tot = sorted(x[0] for x in samples)
        sl = sorted(x[1] for x in samples)
        cl = sorted(x[2] for x in samples)
        return {"n": len(tot), "median": pct(tot, 0.5), "p10": pct(tot, 0.1), "p90": pct(tot, 0.9),
                "server_leg": pct(sl, 0.5), "client_leg": pct(cl, 0.5), "max": tot[-1] if tot else None}

    def _rtt_trigger(self, st: dict, samples: list, ctx) -> str | None:
        n = st["n"]
        if n < scaled(3, ctx):
            return None
        if st["median"] >= 0.300:
            return "median"
        slow = sum(1 for x in samples if x[0] >= 0.5)
        if st["p90"] >= 0.500 and slow >= 2 and slow >= 0.2 * n:
            return "p90"
        if n >= 5 and st["p90"] >= 0.200 and st["p10"] > 0 and st["p90"] / st["p10"] >= 5:
            return "jitter"
        if n >= 5 and st["p90"] >= 0.200 and st["p10"] == 0:
            return "jitter"
        return None

    def _f_high_rtt(self, ctx: AnalysisContext) -> list[Finding]:
        affected = []
        all_samples = []
        for ip, s in self.rtt_by_ip.items():
            if not s.hs:
                continue
            all_samples.extend(s.hs)
            st = self._rtt_stats(s.hs)
            why = self._rtt_trigger(st, s.hs, ctx)
            if why:
                affected.append((ip, st, why, s))
        # Pooled view: many destinations with only a connection or two each. If the
        # median over *all* connections is high, the shared path is slow. (Jitter is
        # not evaluated on the pool: mixing near and far servers fakes jitter.)
        if all_samples and len(all_samples) >= scaled(3, ctx):
            glob = self._rtt_stats(all_samples)
            if glob["median"] >= 0.300:
                have = {a[0] for a in affected}
                for ip, s in self.rtt_by_ip.items():
                    if s.hs and ip not in have:
                        st = self._rtt_stats(s.hs)
                        if st["median"] >= 0.300:
                            affected.append((ip, st, "pooled", s))
        if not affected:
            return []
        affected.sort(key=lambda a: -a[1]["median"])
        samples = [x for a in affected for x in a[3].hs]
        st = self._rtt_stats(samples)
        glob = self._rtt_stats(all_samples)
        n_srv = len(affected)
        if st["p10"]:
            jitter = st["p90"] / st["p10"] >= 5 and st["p90"] >= 0.2
        else:
            jitter = st["p90"] >= 0.2
        steady = bool(st["p10"]) and st["p90"] / st["p10"] < 1.5
        med = st["median"]
        tot = max(med, 1e-9)
        side = "server" if st["server_leg"] >= 0.6 * tot else "client" if st["client_leg"] >= 0.6 * tot else "both"
        first_ip = _cap(affected[0][0], 45)
        if n_srv == 1:
            title = f"Connections to {first_ip} take a long time to answer ({fmt_ms(med)})"
            who = first_ip
        else:
            title = f"Connections to {n_srv} servers are slow to answer (median {fmt_ms(med)})"
            who = f"{n_srv} servers"
        if side == "client":
            where = ("between the local device(s) and the capture point (the near side: Wi-Fi, LAN, or a VPN/tunnel "
                     "on the client)")
        elif side == "server":
            where = "between the capture point and the server(s) (the far side: Internet uplink, ISP, VPN exit or the server's network)"
        else:
            where = "on both sides of the capture point"
        causes = []
        if steady and 0.48 <= med <= 0.9:
            causes.append("a geostationary satellite link (constant ~500-700 ms delay)")
        if steady:
            causes.append("a long-distance path or a VPN that routes traffic far away (constant extra delay)")
        if jitter or not steady:
            causes.append("queueing on a congested link or 'bufferbloat' in the router/modem (delay that "
                          "rises and falls with load)")
        if side == "client":
            causes.insert(0, "a congested or weak Wi-Fi link or an overloaded device close to the client")
        cause = "Most likely " + "; or ".join(causes[:3]) + "."
        all_public = all(not is_private(a[0]) for a in affected)
        distance_only = (n_srv == 1 and side == "server" and steady and med < 0.5 and all_public)
        if distance_only:
            sev = Severity.LOW
        elif med >= 0.5 or n_srv >= 3 or side == "client" or (jitter and st["p90"] >= 0.3):
            sev = Severity.MEDIUM
        else:
            sev = Severity.LOW
        if med >= 1.5:
            sev = Severity.HIGH
        target = first_ip if n_srv == 1 else "8.8.8.8"
        fix = [
            f"Measure the delay yourself and see where it starts: `mtr -rwc 50 {target}` (Linux/macOS) or "
            f"`pathping {target}` (Windows); the first hop where latency jumps is the culprit.",
        ]
        if side in ("client", "both"):
            fix.append("Compare with a wired connection; if the delay disappears, it is the Wi-Fi (move closer, "
                       "change channel, or reduce the number of busy devices).")
        fix.append("Run a load test while pinging the router (`ping -c 30 <router-ip>` during a speed test); if "
                   "latency shoots up under load, enable SQM/QoS (e.g. fq_codel or CAKE) on the router to fix bufferbloat.")
        fix.append("If you use a VPN or proxy, test without it; pick a VPN exit closer to the servers.")
        fix.append("If the delay only concerns one far-away server, consider a closer server/CDN region; that "
                   "part is physics, not a fault.")
        f = Finding(
            kind="latency.high_rtt", category=Category.FAULT, severity=sev,
            title=title[:120],
            summary=(f"Setting up a connection to {who} took {fmt_ms(med)} (median over {st['n']} connections); "
                     f"most of that delay is {'near the client' if side == 'client' else 'beyond the capture point' if side == 'server' else 'spread over both sides'}."),
            explanation=(
                "Before any data flows, TCP does a three-way \"hello\" handshake, so its duration is a clean "
                "measurement of the round-trip time (RTT): how long a packet takes to go there and back. A healthy "
                "round trip inside one country is usually under 50-100 ms. Here it is much longer, so every page, "
                f"click or API call waits that long several times over. The delay sits {where}."
            ),
            analogy="Like talking over a walkie-talkie with a long delay: every question and answer has an awkward pause.",
            cause=cause,
            fix=fix[:5],
            technical=(
                f"Handshake RTT over {st['n']} Karn-valid connections to {plural(n_srv, 'server')}: median {fmt_ms(med)}, "
                f"p10 {fmt_ms(st['p10'])}, p90 {fmt_ms(st['p90'])}, max {fmt_ms(st['max'])}. Split at the capture point: "
                f"capture→server→capture (SYN→SYN/ACK) median {fmt_ms(st['server_leg'])}, capture→client→capture "
                f"(SYN/ACK→ACK) median {fmt_ms(st['client_leg'])}. All connections in the capture: median "
                f"{fmt_ms(glob['median'])} over {glob['n']}. Triggers: "
                + ", ".join(f"{_cap(a[0], 45)}={a[2]}" for a in affected[:5]) + "."
            ),
            hosts=[a[0] for a in affected[:10]],
            metrics={
                "connections": st["n"], "servers": n_srv,
                "median_rtt_ms": ms(med), "p10_rtt_ms": ms(st["p10"]), "p90_rtt_ms": ms(st["p90"]),
                "capture_to_server_ms": ms(st["server_leg"]), "capture_to_client_ms": ms(st["client_leg"]),
                "delay_side": side, "jitter_ratio": round(st["p90"] / st["p10"], 2) if st["p10"] else None,
                "all_connections_median_ms": ms(glob["median"]),
                "per_server": [{"ip": _cap(a[0], 45), "connections": a[1]["n"], "median_ms": ms(a[1]["median"]),
                                "p90_ms": ms(a[1]["p90"]), "trigger": a[2]} for a in affected[:10]],
            },
            indicators=[
                Indicator(f"Handshake round trip of {fmt_ms(med)} measured on {plural(st['n'], 'connection')}",
                          Category.FAULT, 1.5),
                Indicator("Measured from ordinary connection set-up of normal clients; no attack pattern",
                          Category.FAULT, 0.5),
            ],
        )
        if distance_only:
            f.indicators.append(Indicator("Constant delay to a single remote server: likely just geographic distance",
                                          Category.INFO, 1.0))
        ev = Evidence()
        for _, _, _, s in affected:
            for x in sorted(s.hs, key=lambda x: -x[0])[:40]:
                if x[3] is not None:
                    ev.packets.append(x[3])
                    ev.total += 1
                    ev.first_ts = x[4] if ev.first_ts is None else min(ev.first_ts, x[4])
                    ev.last_ts = x[4] if ev.last_ts is None else max(ev.last_ts, x[4])
        ev.apply(f)
        return [f]

    # ================================================================== #
    # latency.slow_server
    # ================================================================== #
    def _f_slow_server(self, ctx: AnalysisContext) -> list[Finding]:
        out = []
        for (ip, port), s in self.svc.items():
            if not s.resp:
                continue
            total = len(s.resp)
            slow = [r for r in s.resp if r[1] >= 1.0]
            ns = len(slow)
            if ns < 2:
                continue
            conns = {r[3] for r in slow}
            http = any(r[2] for r in slow)
            ok = (ns >= scaled(3, ctx) or ns / total >= 0.30) and len(conns) >= 2
            if not http and ns < 3:
                ok = False
            if ok:
                out.append((ns, ip, port, s, slow, total, conns, http))
        out.sort(key=lambda x: -x[0])
        return [self._slow_finding(*x) for x in out[:5]]

    def _slow_finding(self, ns, ip, port, s: _Srv, slow, total, conns, http) -> Finding:
        target = f"[{_cap(ip, 45)}]:{port}" if ":" in str(ip) else f"{_cap(ip, 45)}:{port}"
        ipc = _cap(ip, 45)
        adj_all = sorted(r[1] for r in s.resp)
        adj_slow = sorted(r[1] for r in slow)
        med_slow = pct(adj_slow, 0.5)
        hs = self.rtt_by_ip.get(ip)
        rtts = sorted(x[0] for x in hs.hs) if hs and hs.hs else sorted(r[8] for r in s.resp if r[8] is not None)
        net = pct(rtts, 0.5)
        ct = sorted(s.client_think)
        client_think = pct(ct, 0.5)
        net_ok = net is not None and net < 0.3
        statuses = [r[6] for r in slow if r[6] is not None]
        s5xx = sum(1 for x in statuses if 500 <= x <= 599)
        # constant delays near DNS/resolver timeouts are a classic server misconfiguration
        near_timeout = sum(1 for x in adj_slow if any(abs(x - k) <= 0.5 for k in (5, 10, 15, 20, 30)))
        sev = Severity.HIGH if med_slow >= 5.0 or (ns / total >= 0.5 and med_slow >= 3.0) else Severity.MEDIUM
        net_txt = fmt_ms(net) if net is not None else "unknown"
        ind = [
            Indicator(f"{ns} of {total} requests waited {fmt_ms(med_slow)} (median) for the server's first byte"
                      + (f" while the network round trip was only {net_txt}" if net_ok else ""),
                      Category.FAULT, 2.0 if net_ok else 1.0),
        ]
        if s5xx:
            ind.append(Indicator(f"{s5xx} of the slow responses were HTTP 5xx errors: the server is struggling",
                                 Category.FAULT, 1.0))
        if near_timeout >= max(2, 0.7 * ns):
            ind.append(Indicator("Delays cluster at round values (5/10/30 s), typical of the server waiting for a "
                                 "timeout such as a failing DNS lookup", Category.MISCONFIG, 1.0))
        ind.append(Indicator(f"Slow answers seen on {len(conns)} separate connections from normal clients; no flood or "
                             "attack pattern", Category.FAULT, 0.5))
        cause = ("The server application itself is slow: overloaded CPU, slow database queries, a blocked worker "
                 "pool, or waiting on another backend.")
        if near_timeout >= max(2, 0.7 * ns):
            cause += (" The delays sit at round timeout values, so the server is probably waiting for something that "
                      "times out, often a reverse DNS lookup or an unreachable backend.")
        f = Finding(
            kind="latency.slow_server", category=Category.FAULT, severity=sev,
            title=f"The server {target} is slow to answer requests ({fmt_ms(med_slow)})"[:120],
            summary=(f"{ns} of {total} requests to {target} waited {fmt_ms(med_slow)} (median) for the server to start "
                     f"answering, while the network round trip was {net_txt}."),
            explanation=(
                "We can split each request's waiting time into the time the packets spend travelling (the network "
                "round trip, measured from the connection handshake) and the time the server spends thinking before "
                f"it sends the first byte of its answer. Here the travelling part is {net_txt}"
                + (", which is healthy" if net_ok else "")
                + f", but the server needed about {fmt_ms(med_slow)} to start answering. "
                + ("The network is fine; the server is slow." if net_ok else
                   "The server is slow on top of a slow network.")
            ),
            analogy=("Like a restaurant where your order reaches the kitchen in seconds, but the cook takes "
                     "ages before the first plate comes out."),
            cause=cause,
            fix=[
                f"Check the load on {ipc} while it is slow: CPU, memory, disk I/O (`top`, `iostat -x 1`, Task Manager).",
                "Look at the application/web server logs for slow requests (e.g. nginx `$request_time`, Apache "
                "`%D`, application APM traces) and the database's slow-query log.",
                f"Time a single request to separate network from server: `curl -o /dev/null -s -w "
                f"'connect=%{{time_connect}} ttfb=%{{time_starttransfer}}\\n' http{'s' if port in (443, 8443) else ''}://{ipc}:{port}/`.",
                "If delays are round numbers like 5 s, check the server's DNS resolver settings and any reverse-DNS "
                "lookups (e.g. `UseDNS no` for sshd, `HostnameLookups Off` for Apache).",
                "Scale the server (more workers/threads, more capacity) or fix the slow backend it depends on.",
            ],
            technical=(
                f"{total} request/response turns measured on {target} ({'HTTP' if http else 'opaque request/response'}). "
                f"Server think time = first new response byte − last new request byte − capture→server RTT. "
                f"Slow (≥1 s) turns: {ns} on {len(conns)} connections, median {fmt_ms(med_slow)}, max {fmt_ms(adj_slow[-1])}; "
                f"all turns median {fmt_ms(pct(adj_all, 0.5))}. Blame split: network RTT {net_txt} vs server "
                f"processing {fmt_ms(med_slow)} vs client think time {fmt_ms(client_think)} (median gap between a "
                "response and the next request). Turns with retransmitted requests or missing response segments "
                "were discarded."
            ),
            hosts=[ip],
            metrics={
                "service": target, "requests": total, "slow_requests": ns, "slow_share": round(ns / total, 3),
                "network_rtt_ms": ms(net), "server_processing_s": round(med_slow, 3),
                "server_processing_all_median_s": round(pct(adj_all, 0.5), 3),
                "client_think_s": None if client_think is None else round(client_think, 3),
                "blame": "server" if net_ok or net is None or med_slow > 3 * net else "server+network",
                "http_5xx": s5xx, "connections": len(conns),
                "slowest": [{"request_frame": r[4], "response_frame": r[5], "server_s": round(r[1], 3),
                             "status": r[6]} for r in sorted(slow, key=lambda r: -r[1])[:10]],
            },
            indicators=ind,
        )
        ev = Evidence()
        for r in sorted(slow, key=lambda r: -r[1])[:100]:
            for no in (r[4], r[5]):
                if no is not None:
                    ev.packets.append(no)
                    ev.total += 1
            ev.first_ts = r[7] if ev.first_ts is None else min(ev.first_ts, r[7])
            ev.last_ts = r[7] if ev.last_ts is None else max(ev.last_ts, r[7])
        ev.total = max(ev.total, ns * 2)
        ev.apply(f)
        return f
