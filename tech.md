# Faultline: technical design

## Stack

- **Python ≥ 3.10.** The core analysis engine uses **only the standard library**: our own capture reader, our own protocol decoders and our own detection logic. Nothing wraps Wireshark, tshark, Scapy or Zeek output.
- **rich** for the CLI's terminal UI and **Flask** (with Jinja2 autoescape) for the local web dashboard.
- **pytest** for tests, plus a fuzz harness.
- Front end: a self-contained HTML report with vanilla JS and no CDN or external requests. It ships with a strict CSP and renders through `textContent` only.

## Architecture

```
            ┌──────────────┐   frames   ┌──────────────┐  Packet  ┌───────────────┐
 .pcap ───▶ │ capture/     │──────────▶ │ capture/     │────────▶ │ engine        │
 .pcapng    │ reader.py    │ (bounded)  │ decode.py    │ (typed)  │  HostTable    │
 .pcap.gz   │ hardened     │            │ L2→L7        │          │  detectors[]  │
            └──────────────┘            └──────────────┘          └──────┬────────┘
                                                                         │ Finding[]
                                    ┌────────────────────────────────────▼────────┐
                                    │ verdict.py: Fault / Misconfig / Attack     │
                                    │ hypothesis scoring from Indicators         │
                                    │ correlate.py: incidents, root cause,       │
                                    │ symptom suppression, health score          │
                                    └────────────────────────────┬───────────────┘
                                                                 │ Report (dict)
                     ┌───────────────────┬───────────────────────┼──────────────┐
                     ▼                   ▼                       ▼              ▼
                 CLI (rich)        HTML report (static)     Web dashboard     JSON
                                                            (Flask, local)
```

## Package layout

```
faultline/
  capture/reader.py     pcap, pcapng and gzip reader; hardened; streaming
  capture/decode.py     Ethernet/VLAN/SLL/Raw/Null → ARP, IPv4/6, TCP, UDP, ICMP/v6, DNS, DHCP, TLS, HTTP, cleartext auth
  capture/writer.py     pcap writer (evidence export, lab)
  model.py              Packet slots classes, Finding, Indicator, Severity, Category, Incident
  context.py            AnalysisContext, HostTable (ip↔mac, roles: gateway / dns / dhcp)
  detectors/base.py     Detector interface, registry, Evidence helper
  detectors/tcp.py      TCP state tracker + retrans / dup-ACK / lost segment / RST / refused / zero-window / handshake failure
  detectors/latency.py  handshake RTT, server response time, stalls, blame split
  detectors/mtu.py      ICMP frag-needed / PTB, PMTUD black hole, MSS mismatch, fragmentation
  detectors/arp.py      IP conflict vs. ARP spoofing, ARP scan, unanswered ARP, gratuitous ARP storm
  detectors/dns.py      timeouts, rcode failures, slow DNS, hijack/spoofing (race, unexpected server, answer mismatch), tunneling
  detectors/dhcp.py     rogue server vs. misconfiguration, no server, NAK storm, starvation
  detectors/scan.py     TCP SYN/FIN/NULL/Xmas/connect scans, UDP scans, host sweeps, ping sweeps
  detectors/flood.py    SYN flood, ICMP flood, broadcast storm
  detectors/icmp.py     unreachables, TTL exceeded / routing loop, ICMP redirect
  detectors/app.py      TLS alerts / deprecated TLS, HTTP 5xx/4xx, cleartext credentials
  verdict.py            hypothesis engine
  correlate.py          incidents, root cause vs. symptom, health score, overall verdict
  engine.py             analyze(path, options) → Report
  report/json.py, report/html.py, report/terminal.py, report/redact.py
  web/app.py            Flask app: upload, samples, report, evidence download
  lab/craft.py          byte-level packet builders (Ethernet/ARP/IP/TCP/UDP/ICMP/DNS/DHCP)
  lab/scenarios.py      labelled scenario generators → samples/*.pcap + samples/labels.json
  bench.py              precision / recall / false-alarm benchmark over the lab
  cli.py                analyze | web | diff | lab | bench
```

## Data contracts

`Packet` (slots, one per frame; payload bytes are **not** kept, for memory and privacy):
`no` (1-based frame number, same as Wireshark), `ts`, `caplen`, `wirelen`, `eth_src`, `eth_dst`, `vlan`, `arp`, `ip_ver`, `src`, `dst`, `ttl`, `ip_id`, `df`, `mf`, `frag_off`, `ip_len`, `proto`, `tcp`, `udp`, `icmp`, `dns`, `dhcp`, `tls`, `http`, `cred`, `payload_len`, `malformed`.

`Finding`: `kind` (for example `arp.spoofing`), `title`, `severity` (0 to 4), `category` (detector's hint), `confidence`, `summary`, `explanation`, `analogy`, `cause`, `fix[]`, `technical`, `hosts[]`, `packets[]` (capped evidence frame numbers), `packet_total`, `first_ts`, `last_ts`, `metrics{}`, `indicators[]`, `mitre`, plus `id`, `symptom_of` and `alternatives`, which the engine sets.

`Indicator(text, supports ∈ {fault, misconfig, attack}, weight 0..3)`: every detector states the evidence it saw **for each hypothesis**. The verdict engine, not the detector, decides the final category, so the logic stays consistent and explainable ("why attack, why not fault").

## Fault vs. attack hypothesis engine

For each finding, score(h) = Σ weight of indicators that support h, plus the detector's prior for its own hint category.
- The category is the argmax.
- Confidence = softmax margin, calibrated to [0.5, 0.99].
- `alternatives` lists the losing hypotheses together with the indicators that would have supported them, which become the "why not" text.

Typical discriminators:

| Symptom | Fault / misconfig indicators | Attack indicators |
|---|---|---|
| Two MACs for one IP | both MACs stable and alternating rarely; ARP probes / DAD; neither is the gateway | MAC claims the **gateway** IP; unsolicited replies at a high rate; one MAC claims **many** IPs; original MAC still active (flip-flop) |
| DNS not working | timeouts / SERVFAIL from the configured resolver; all clients affected | **two answers for one query** (race); answers from an IP never queried; public domain resolving to a private IP; TTL anomalies |
| DHCP oddities | one server, NAKs from a lease mismatch | **second server** offering a different router / DNS; offers for unknown MACs; starvation pattern |
| Many RSTs or SYNs | service down (RSTs from one server port to many clients) | one source to **many ports / hosts**; FIN / NULL / Xmas flags; SYNs never completed from spoofed sources |

## Correlation (root cause vs. symptoms)

- Findings that share a host or MAC within a time window are grouped into **incidents**.
- Chain rules, for example: `dhcp.rogue` / `arp.spoofing` + `dns.hijack` → **man-in-the-middle**; `dhcp.no_server` → `dns.*` / `tcp.*` failures from the affected client are symptoms; `arp.unanswered` (gateway) → everything else is a symptom; `scan.*` followed by connections to opened ports → recon and then access.
- A finding marked `symptom_of` is shown under its root cause: "Fix this first".
- Health score = 100 − Σ(severity weight × confidence), clamped to 0..100.
- The overall verdict is `under_attack`, `faulty`, `minor_issues` or `healthy`.

## Security of the solution

- **Reader**:
  - magic and version validation; endianness and nanosecond-resolution handling;
  - every length is checked against the remaining bytes and against caps (record ≤ 256 KiB, pcapng block ≤ 16 MiB, total packets, file size);
  - corruption is reported with offset + count, and the reader stops gracefully, never with a traceback;
  - gzip is read as a stream with a decompressed-size cap (bomb guard).
- **Decoders**:
  - every parser is bounds-checked, and a malformed packet is counted (and flagged) rather than raised as an error;
  - DNS name decompression has loop and depth limits;
  - TLV loops have iteration caps.
- **Data handling**:
  - no payload retention;
  - credentials are detected but **never** stored or displayed (only the protocol name and that a credential was present);
  - `--redact` uses a keyed HMAC to give consistent pseudonyms for IPs and MACs, with a random key per run that is never written.
- **Reports and web**:
  - all capture-derived strings are untrusted; Jinja2 autoescape;
  - JSON is embedded with `<`, `>` and `&` escaped, and the JS renders with `textContent` only;
  - strict CSP and no external resources;
  - Flask binds to 127.0.0.1 by default, with an upload size limit and extension + magic validation;
  - uploads are written under a random temp name, never the user's filename, and deleted after analysis (evidence is cached in memory only, with a TTL);
  - no secrets in the repo, no network calls, no telemetry, no `eval` / `pickle` / `shell`.
- **Tests**: a fuzz harness (random mutations of valid captures plus hand-crafted malicious files) asserts there are no exceptions and that time stays bounded.

## Evidence

Each finding keeps ≤ 200 frame numbers. The engine re-reads the file once to export **per-finding evidence pcaps** (capped), which the HTML report and dashboard offer as downloads. In redact mode, raw evidence export is disabled.
