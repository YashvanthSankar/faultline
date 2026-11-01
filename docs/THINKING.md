# How we thought about this problem

This document is the engineering reasoning behind Faultline. The README tells you what it does; this tells you *why it is built the way it is*, and where each decision lives in the code.

## 1. Diagnosis is not detection

Most tools in this space *detect*: they emit an event when a pattern matches. "Retransmission." "Duplicate ACK." "SYN to closed port." Those are **symptoms**. A beginner looking at 4,000 "retransmission" rows in Wireshark knows exactly as much as before: something is wrong.

*Diagnosis* means going from symptoms to a **cause** and a **next step**. The office manager does not need to know what a duplicate ACK is. They need: "6 % of packets are being lost between this capture point and the server, which is on the far side of your Wi-Fi link. Move closer to the access point, change the channel, or plug in a cable." That sentence contains the symptom, the location, the probable cause and the fix.

So every Faultline finding is a structured answer, not an event (`faultline/model.py`, `Finding`): `summary` (one line), `explanation` (beginner), `analogy`, `technical` (expert), `cause`, `fix[]`, `packets[]` (evidence) and `confidence`. A detector that cannot fill in `cause` and `fix` is not finished.

The second half of diagnosis is **de-duplication of causes**. When the gateway disappears, every DNS lookup times out, every TCP connection to the internet fails, and every client retries DHCP. A detector-per-symptom tool reports forty findings. We report one root cause and list the rest as its symptoms (`correlate.py`, `Finding.symptom_of`, `Incident.first_fix`): "Fix this first".

## 2. An outage and an attack look the same. Competing hypotheses separate them.

This is the central idea of the project, and the reason it exists.

To a user, every network problem is "the internet is broken". To a packet, many faults and attacks are *literally the same bytes*:

- Two MACs answering for one IP is an **IP conflict** (someone set a static address inside the DHCP pool) *or* **ARP spoofing**.
- DNS not resolving is a **dead resolver** *or* a **hijack** that answers first with the wrong address.
- Two DHCP servers is **someone plugged in a second home router** *or* a **rogue DHCP server** that steers you through an attacker.
- A spike of SYNs is a **flash crowd** *or* a **SYN flood**.

A tool that only looks for faults will call the attack a fault; an IDS that only looks for attacks will call the misconfiguration an attack (and get muted for crying wolf). Neither one explains *why* it chose.

### The hypothesis engine

Detectors in Faultline do not decide. Each detector observes the traffic and emits **indicators**: `Indicator(text, supports, weight)` where `supports ∈ {fault, misconfig, attack}` and `weight ∈ [0.5, 3]` (`faultline/model.py`). It also supplies a **variant** per plausible reading: the title, explanation, cause, fix and MITRE technique that would be right *if* that hypothesis wins (`Variant`).

The verdict engine (`faultline/verdict.py`) scores each hypothesis as the sum of the weights of the indicators supporting it, plus a small prior for the detector's own hint. The highest score wins; the margin becomes a calibrated confidence; the losers are kept together with their indicators and rendered as **"Why not …?"** text. Concretely: prior 0.5, weights clamped to 3, softmax over the candidate hypotheses, confidence clamped to [0.5, 0.99], ties to the detector's default; a weakly supported attack (confidence < 0.6) is shown one severity step softer.

This design has three consequences we care about:

1. **Consistency.** One scoring rule for every detector. Nobody hand-tunes "if X and Y then attack" differently in ten files.
2. **Explainability.** The output is literally the list of things we saw for and against each reading. A judge or an admin can disagree with a weight; they can never be left wondering how the verdict appeared.
3. **Honesty under uncertainty.** When indicators are balanced, confidence is low and both readings are shown. We would rather say "probably a conflict, but check for spoofing" than confidently pick one.

### Worked example A: IP conflict vs. ARP spoofing

Both cases: ARP replies for `192.168.1.1` arrive from two different MACs.

| Observation | Supports | Why |
|---|---|---|
| The contested IP is the **gateway** | attack (3) | Nobody accidentally gives a printer the router's address; an attacker always wants the gateway |
| Unsolicited ARP replies at a steady high rate | attack (2) | Poisoning tools re-announce every 1–2 s to keep caches poisoned |
| The same MAC claims **several** IPs | attack (2) | One device, many identities = impersonation |
| The original MAC keeps transmitting (flip-flop) | attack (1) | In a real conflict the loser usually goes quiet or re-probes; in spoofing the victim is still alive |
| RFC 5227 probes (`who-has X tell 0.0.0.0`) or gratuitous ARP from both | fault (2) | That is what honest hosts do when they detect a conflict |
| Both MACs stable, alternation rare | fault (1) | Two static devices, not a flood |
| Neither device plays a server role | fault (1) | Nothing to gain by impersonating a laptop |

Printer-vs-laptop: fault 4, attack ≈ 0 → **Duplicate IP address** (fault), fix: "move the printer out of the DHCP range or reserve its address". Attacker-vs-router: attack 8, fault ≈ 0 → **ARP spoofing**, T1557.002, fix: "isolate the attacking MAC, enable Dynamic ARP Inspection / port security, verify the gateway's real MAC". Both outputs show the other column. (The table is a simplified view; the real indicator list and weights are in `detectors/arp.py` and `docs/DETECTORS.md`; in the code the "conflict" reading is categorised as *misconfig*.)

### Worked example B: DNS outage vs. DNS hijack

Both cases: users say "websites don't work".

| Observation | Supports |
|---|---|
| Queries to the configured resolver get **no response** or SERVFAIL, for all clients, for all names | fault |
| The resolver also fails ICMP/TCP, or the gateway ARP is unanswered | fault (and makes DNS a symptom of that root cause) |
| **Two responses** for one transaction, with different answers, the first arriving in under a millisecond (from inside the LAN) | attack |
| A response comes from a server that was **never queried** | attack |
| A **public** name resolves to a **private** address, and that address belongs to the very device that delivered the answer | attack |
| The suspicious answers carry an odd, fixed TTL and claim to be authoritative, unlike the resolver's normal answers | attack |
| The fake address is the DNS server advertised by a second (rogue) DHCP server | attack, and chain to that incident |
| *Every* name resolves to the resolver or the gateway itself | misconfig (captive portal / DNS filtering) |

An outage has no second answer to compare against; a hijack leaves a race, an impostor server, or a public name pointing at a LAN device. That asymmetry is the discriminator (`detectors/dns.py`, `_find_hijack`).

### Worked example C: a second router vs. a rogue DHCP server

Both cases: two DHCP servers send OFFERs.

| Observation | Supports |
|---|---|
| Both servers hand out **identical** settings on the same subnet | neither: treated as a failover pair and not reported |
| Second server offers a **different subnet**, names itself as the router and hands out public DNS, as a factory-default home router does | misconfig |
| Second server hands out addresses in the **same subnet** as the real one, but names itself (or another LAN host) as the router and points DNS at a LAN host | attack |
| Second server **answers first** in races, clients accept its leases, then use it as DNS and send internet traffic to its MAC | attack |
| The host advertised as DNS by the second server then answers queries with its own address | attack, chain to `dns.hijack` → man-in-the-middle incident |

Someone's home router plugged into the office LAN is annoying; its offers point at *itself* as the gateway for *its own* subnet and usually at a public DNS, and it does not coincide with hijacked answers. A rogue server blends into the real subnet, points at a LAN host, and the hijack follows (`detectors/dhcp.py`, `_server_finding`).

### Worked example D: SYN flood vs. flash crowd

| Observation | Supports |
|---|---|
| Many SYNs, **handshakes complete**, data flows, sources are a realistic mix with repeat visitors | fault (overload) |
| SYNs from a very large number of sources, **none complete**, sources are uniformly random, no retransmitted SYNs (real stacks retry) | attack |
| All the "different" senders arrive with the same TTL (one spoofing machine), or TTLs spread randomly; some come from impossible (bogon / LAND) addresses | attack |
| The server answered only a small share of SYNs: it is overwhelmed | fault (overload) |

Legitimate crowds finish handshakes. Floods don't (`detectors/flood.py`, `_syn_finding`).

## 3. Where the capture point sits, and why it matters

A packet capture is a view from one place in the network. Interpreting loss and latency correctly depends on *which side* of that place the problem is on.

- **Retransmission seen, original also seen** → the original left the capture point and was lost *after* it: **downstream loss**. The fault is between the capture point and the receiver.
- **Retransmission seen, original never seen** (sequence gap, SACK blocks / duplicate ACKs from the receiver referring to data we never saw) → the data was lost *before* reaching the capture point: **upstream loss**.
- **Handshake RTT split**: the time between SYN and SYN-ACK measures the far side; the time between SYN-ACK and ACK measures the near side. The ratio tells you whether the slow half is the Wi-Fi in the room or the WAN.
- **Server think time**: the gap between the client's request and the first byte of the response, minus the network RTT, is the server's time. If RTT is small and think time is large, the network is innocent.
- **Zero window**: the receiver says "stop", so the *application on the client* is the bottleneck, not the network.

This is why Faultline's "slow" findings come with a **blame split**: network vs. server vs. client vs. receive window. "It's slow" becomes "the server takes 1.8 s to answer, the network round trip is 12 ms; this is the application, not the Wi-Fi".

Limitation we state openly: this assumes a single capture point. A merged capture from two taps will confuse the logic.

## 4. Precision over recall

A security tool that cries wolf gets uninstalled. The brief says so in its own words: "telling an outage from an attack (keep false alarms low)".

Decisions that follow from that:

- **Clean captures are part of the benchmark.** `samples/clean_office.pcap`, `samples/busy_but_healthy.pcap`, `samples/pcapng_office.pcapng` and `samples/xss_payload.pcap` must produce *zero* findings. The benchmark (`bench.py`) marks a case failed if any expected finding is missed, misclassified, or any unexpected finding of severity ≥ medium appears; clean captures must stay silent, and hostile files must end in nothing worse than a `CaptureError`.
- **Thresholds are rates and ratios, not raw counts, wherever possible.** 50 retransmissions in a 10-second capture of a busy server is normal; 50 in a 2-packet-per-second link is a disaster. We compare to the flow's own volume and duration.
- **Thresholds scale with one knob.** `Config.sensitivity` (`faultline/context.py`) multiplies count thresholds by 1.6 (`low`), 1.0 (`normal`) or 0.6 (`high`). An admin on a noisy campus network can lower sensitivity without editing code.
- **Roles make indicators specific.** The `HostTable` infers which hosts are the gateway, DNS and DHCP servers (`faultline/context.py`). "Two MACs for an IP" is a weak signal; "two MACs for *the gateway*" is a strong one. Role-aware indicators let us keep generic thresholds high and still catch the attacks that matter.
- **Natural noise is modelled.** Real stacks retransmit occasionally, real DNS has NXDOMAINs (typos, Chrome's random probe names), real hosts send a few unanswered ARPs. Detectors have floors below which they stay silent.
- **Confidence is shown, never hidden.** A low-confidence finding is labelled as such and shows both readings.

## 5. Capture files are hostile input

The brief lists "reading captures safely (large/broken/malicious input without crashing or leaking data)" as the first challenge point. We treat a capture file like a file received from an attacker, because that is exactly what it might be: a malicious capture is a cheap way to attack the analyst.

`faultline/capture/reader.py`:

- Validates magic and version; handles both endiannesses and nanosecond pcap.
- **Never trusts a length field.** Every length is checked against the bytes remaining *and* against hard caps before anything is allocated: record ≤ 256 KiB, pcapng block ≤ 16 MiB, ≤ 10 M packets, ≤ 4 GiB file, ≤ 1024 interfaces, ≤ 100 k skipped blocks.
- Reads gzip through a `_BombGuard` stream that aborts past 2 GiB decompressed.
- Ends on corruption with a warning carrying the byte offset; everything read so far is still analysed. No tracebacks reach the user.
- Streams frames one at a time; the file is never loaded into memory.
- Rejects non-regular files (devices, FIFOs), empty files and files above the size limit before opening (`_validate_path`).

`faultline/capture/decode.py`: every parser is bounds-checked; a malformed layer sets `Packet.malformed` and counting continues; DNS name decompression has pointer-loop and depth limits; TCP/DHCP option loops and pcapng option loops are capped (`DNS_MAX_JUMPS` 32, `DNS_MAX_LABEL` 63, `DNS_MAX_NAME` 255, `DNS_MAX_ANSWERS` 32, `TCP_MAX_OPTIONS` 40, `DHCP_MAX_OPTIONS` 255, `TLS_MAX_RECORDS` 16, `TLS_MAX_EXTENSIONS` 64, `HTTP_MAX_HEADERS` 40, `MAX_VLAN_TAGS` 4, `MAX_IPV6_EXT` 8). Pointers may only jump backwards, which rules out loops by construction.

Detectors keep **bounded state**: `BoundedDict` evicts the oldest key once full, so a capture with a million random source addresses cannot exhaust memory; `Evidence` keeps 200 frame numbers and a count (`faultline/detectors/base.py`).

Reports: all capture-derived strings (host names from DHCP, DNS names, HTTP hosts, SNI) are untrusted. The HTML report embeds JSON with `<`, `>` and `&` escaped and renders only through `textContent`, under a strict CSP with no external resources; the Flask dashboard uses Jinja2 autoescape, binds to 127.0.0.1, limits upload size, validates extension and magic bytes, and stores uploads under random temporary names that are deleted after analysis. A capture containing `<script>alert(1)</script>` as a hostname is rendered as text. The report additionally escapes U+2028/U+2029 in the embedded JSON and pins the single inline script with the CSP. The dashboard also uses a per-process CSRF token on uploads.

A fuzz harness mutates valid captures (bit flips, truncation, length-field inflation) and feeds hand-crafted hostile files (`samples/malformed/`), asserting that only `CaptureError` may escape and that analysis time stays bounded (`tests/fuzzing.py`, `tests/test_fuzz.py`; seeds cover Ethernet, VLAN, ARP, IPv4/6, TCP, UDP, DNS, DHCP, ICMP/v6, TLS ClientHello, HTTP Basic auth and Linux SLL, in pcap, pcapng and gzip).

Full details in [`SECURITY.md`](../SECURITY.md).

## 6. Privacy by design

A diagnostic report is meant to be shared: with a vendor, a colleague, a forum. Reports that leak are a second incident.

- **No payload retention.** `Packet` (`faultline/model.py`) holds header fields only. The decoder reads what it needs (DNS names, HTTP method/host/path without the query string, TLS SNI) and discards the bytes. Memory stays small *and* nothing sensitive is ever held.
- **Credentials are detected, never extracted.** The cleartext-credential decoder sets `Packet.cred = "FTP"` or `"HTTP Basic"`; the username and password are never parsed into a field, never logged, never rendered. The finding says *that* a credential crossed the wire in the clear and *where*, which is all an admin needs to fix it.
- **Redaction.** `--redact` replaces IPs, MACs and names with consistent pseudonyms derived by HMAC with a random key generated per run and never written anywhere. Consistency is kept (the same host is `host-7` throughout) so the report remains readable; reversibility is impossible. Raw evidence pcap export is disabled in redact mode because packets cannot be redacted without rewriting them (`report/redact.py`: `secrets.token_bytes(32)` key, HMAC-SHA256, 6-hex-digit labels, special addresses such as broadcast/multicast/loopback kept readable).
- **Local only.** No telemetry, no network calls, dashboard bound to loopback.

## 7. Why our own parser and our own detection

The brief allows capture-reading libraries but requires the detection logic to be the team's own and explicitly says wrapping tshark does not count. We went further and wrote the reader and decoders too. Reasons:

1. **Safety.** The hardening in §5 is only possible when we own every length check. A library that throws on a bad length or allocates what the header claims is a liability we cannot patch at 3 a.m.
2. **Control over what is kept.** Full-featured dissectors keep everything; we keep header fields and drop payloads by construction (§6).
3. **Explainability.** Our detectors see exactly the fields our decoder produced. There is no hidden layer of "expert info" heuristics whose logic we cannot show a judge.
4. **Portability.** Standard library only for the engine means `pip install` never fails on a judge's laptop because of a native extension.
5. **Speed for our use.** Slots-based `Packet` objects, one streaming pass, bounded tables.

The cost is breadth: we decode the protocols the brief is about (ARP, IPv4/6, TCP, UDP, ICMP/v6, DNS, DHCPv4, TLS handshake, HTTP/1.x) and count the rest.

## 8. Trade-offs and what we'd do with more time

**Trade-offs we made on purpose**

- Heuristic thresholds instead of learned baselines: explainable and tunable in 24 hours; learned models would need labelled real traffic we do not have.
- Single capture point assumption: covers the realistic case (one laptop running tcpdump) and keeps the loss localisation logic sound.
- Synthetic lab instead of public pcaps: every byte is ours and labelled, there is no licensing or privacy question, and we can generate the *clean* cases that measure false alarms. The risk is over-fitting to our own generator; we mitigate it with natural-noise models in the clean scenarios and by testing against malformed and busy traffic.
- Breadth of protocols vs. depth of reasoning: we chose depth (hypotheses, correlation, localisation) over covering every protocol.

**With more time**

- IPv6 NDP spoofing and RA-guard style detection (the IPv6 twin of ARP spoofing and rogue DHCP).
- Baseline learning from a known-good capture of the same network ("what changed since last week").
- Live capture mode (the engine already streams; it needs an interface reader).
- A plug-in API for third-party detectors using the same `Indicator`/`Variant` contract.

## Judging criterion → what we built → where to look

| Criterion (weight) | What we built | Where to look |
|---|---|---|
| **Novelty (20 %)** | Fault vs. attack hypothesis engine with "why not" reasoning; root cause vs. symptom incidents; loss localisation and blame split; before/after diff; labelled lab with false-alarm benchmark | `faultline/verdict.py`, `faultline/correlate.py`, `faultline/detectors/tcp.py`, `faultline/detectors/latency.py`, `faultline/cli.py` (diff), `faultline/lab/`, `faultline/bench.py` |
| **Technical implementation (30 %)** | Own hardened pcap/pcapng/gzip reader; own L2–L7 decoders; ten detector modules of original logic; one streaming pass with bounded memory; typed data model; unit tests per detector via packet factories | `faultline/capture/`, `faultline/detectors/`, `faultline/model.py`, `tests/` |
| **Security (20 %)** | Length caps, bomb guard, graceful corruption handling, bounded detector state, no payload retention, credentials never extracted, HMAC redaction, XSS-proof reports, loopback-only dashboard, no secrets, fuzz harness | `faultline/capture/reader.py`, `faultline/detectors/base.py` (`BoundedDict`, `Evidence`), `faultline/report/`, `faultline/web/`, `SECURITY.md`, `tests/test_fuzz.py`, `scripts/fuzz.py`, `scripts/check_secrets.py` |
| **Feasibility (10 %)** | `pip install -e .` and one command; stdlib engine; runs offline; 37 labelled samples (31 scenarios, 6 hostile files); CLI, HTML, web and JSON outputs; CI exit codes | `README.md` Quick start, `pyproject.toml`, `samples/` |
| **Video presentation (20 %)** | Scripted demo: MITM chain in the dashboard, lossy link in the CLI, conflict vs. spoofing side by side, hostile input, redaction, benchmark | `docs/demo-script.md`, video link in README |
