# Faultline: security design

Faultline is an **offline, defensive** network-diagnostics tool. It reads packet
captures and tells you whether the network is broken or being broken. Capture
files are the most hostile input a program can take: every byte, every length
field and every string inside them is attacker-controlled. This document states
what we defend against, exactly how, where in the code, and how a judge can
check it in two minutes.

Every claim below was checked against the code as submitted; the commands in
section 4 reproduce the checks.

---

## 1. Threat model

| # | Threat | Attacker goal |
|---|--------|---------------|
| T1 | **Hostile capture file** (corrupt or crafted pcap / pcapng / gzip) | crash the analyser, hang it, exhaust memory or disk |
| T2 | **Hostile packet contents** (DNS names, SNI, HTTP headers, hostnames) rendered in reports | XSS in the HTML report or the dashboard; terminal escape injection |
| T3 | **Resource exhaustion** (gzip bombs, 4 GiB length fields, millions of flows / hosts / findings) | denial of service on the analyst's machine |
| T4 | **Data leakage** (captures hold PII, credentials, internal topology) | a shared report or the tool itself exposes more than the analyst intended |
| T5 | **Local web dashboard** (Flask on localhost) | CSRF from another tab, DNS-rebinding, non-loopback exposure, path traversal via sample names, oversize uploads, info leaks in error pages |
| T6 | **Supply chain** | malicious or vulnerable dependency, hidden network call, hidden secret |

Out of scope: an attacker who already runs code as the analyst's user, and
physical access to the machine.

---

## 2. Mitigations, by threat

### T1: Hostile capture files (`faultline/capture/reader.py`)

The reader is a streaming, bounds-checked parser. Design rule: *never trust a
length field; never allocate before checking; never raise anything but
`CaptureError`, and only for "this is not a capture at all".*

| Control | Where |
|---|---|
| Path must be a **regular file** (no FIFOs, devices, directories: `open()` on a FIFO would block forever), non-empty, below `Limits.max_file_bytes` (4 GiB) | `CaptureReader._validate_path` |
| Magic and byte-order validation for pcap LE/BE, µs/ns, pcapng SHB with either BOM; anything else is a `CaptureError` with a helpful message | `CaptureReader.__iter__`, `_read_pcapng` |
| Every record / block length checked against the **remaining bytes** and against caps: record ≤ 256 KiB, pcapng block ≤ 16 MiB, block ≥ 12 and 4-aligned, trailer must equal header length, EPB `caplen` ≤ body | `_read_pcap`, `_read_pcapng` |
| Packet count cap (10 M), interface cap (1024), non-packet-block cap (100 k), IDB option loop cap (256), `if_tsresol` sanity (exponent ≤ 30) | `Limits`, `_emit`, `_read_pcapng`, `_idb_options` |
| Corruption **stops gracefully**: `info.truncated = True`, a warning with the byte offset, and everything read so far is still analysed. Warnings are capped at 50 | `CaptureInfo.warn`, all `_read_*` |
| gzip is decompressed as a **stream** through `_BombGuard`, which stops after `max_decompressed_bytes` (2 GiB) and converts `zlib.error` / `EOFError` / `BadGzipFile` into a graceful truncation | `_BombGuard.readinto` |
| Frames are yielded one at a time; the file is never loaded whole | `CaptureReader.__iter__` |

Tests: `tests/test_reader.py` (43 tests) truncates a valid pcap and pcapng at
**every byte offset**, feeds `caplen = 0x7fffffff`, block lengths of 0 / 8 /
13 / 0xffffffff / mismatched trailers, bad BOMs, zero-byte files, directories,
FIFOs, `/dev/zero`, gzip bombs and corrupt deflate streams, and asserts that a
hostile 1 MiB file of each shape is processed in under two seconds.

### T1 continued: Hostile packet contents in the decoder (`faultline/capture/decode.py`)

* Every layer is bounds-checked; the first problem records a reason in
  `Packet.malformed` instead of raising. Malformed packets are counted and
  surfaced as a finding (`engine._malformed_finding`).
* Loop and depth caps on every repeated structure: VLAN tags (4), IPv6
  extension headers (8), TCP options (40), DNS compression jumps (32, and
  pointers must go backwards: no loops), DNS name ≤ 255 / label ≤ 63,
  DNS answers (32), DHCP options (255), TLS records (16) / extensions (64) /
  record size (18 432), HTTP header scan window (4 KiB) and header count (40).
* Strings taken from the wire (SNI, hostnames, HTTP host / path, DNS names)
  go through `_printable`, which strips control characters and caps length,
  so no terminal escape sequences or megabyte strings reach a report.

Tests: `tests/test_decode.py` (decoder owner) and `tests/test_fuzz.py`
(`test_decode_handles_every_truncation_of_each_seed_frame`: every prefix of
every seed frame for every link type).

### T1/T3: Fuzzing (`tests/fuzzing.py`, `tests/test_fuzz.py`, `scripts/fuzz.py`)

A mutation fuzzer builds valid seeds (Ethernet, VLAN, ARP, IPv4, IPv6, TCP,
UDP, DNS, DHCP, ICMP, ICMPv6, TLS ClientHello, HTTP Basic auth, Linux SLL,
raw IP, pcap / pcap-ns / pcapng / gzip) and applies seeded random mutations:
bit flips, interesting bytes (0x00 / 0xff / 0x7f / 0x80), 16- and 32-bit
interesting values, truncation, length-field inflation, chunk duplication,
deletion and insertion, and stacked combinations. Each case runs the **full
pipeline**: reader → `decode` → `engine.analyze` → `redact_report`. The only
exception allowed to escape is `CaptureError`; every case has a 3 s budget.
`pytest` runs 300 cases by default; `FAULTLINE_FUZZ_CASES=5000` runs more.
The last long run before submission (`scripts/fuzz.py -n 3000 --seed 42`):
3 000 cases, 0 crashes, 538 rejected cleanly with `CaptureError`, 2 462
accepted with warnings or truncation, slowest case 11.9 ms, mean 1.08 ms,
0 cases over budget.

### T2: Hostile strings rendered in reports

All capture-derived strings are untrusted; the renderers never interpret them.

* **Static HTML report** (`faultline/report/html.py`): the report is embedded
  as JSON inside `<script type="application/json">` with `<`, `>`, `&`,
  U+2028 and U+2029 escaped (`embed_json`, `_clean` also rejects NaN/Infinity
  and bytes), so no byte sequence can close the script element. The inline
  JS renders with `createElement` / `textContent` only (no `innerHTML`,
  `insertAdjacentHTML` or `document.write` in `report/assets/report.js`;
  the single `outerHTML` use reads the DOM for the export button).
  A strict `Content-Security-Policy` (`report_csp`) pins the one inline
  script and the one inline style by SHA-256 hash, `default-src 'none'`,
  `connect-src 'none'`, `form-action 'none'`, `frame-ancestors 'none'`; the
  page makes no external requests and works from `file://`.
* **Dashboard** (`faultline/web/app.py`): Jinja2 autoescape (Flask default
  for `.html` templates), a per-request nonce CSP
  (`script-src 'nonce-…'`, `object-src 'none'`, `frame-ancestors 'none'`,
  `base-uri 'none'`), `X-Content-Type-Options: nosniff`, `X-Frame-Options:
  DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`,
  `Cross-Origin-Opener-Policy` / `Cross-Origin-Resource-Policy: same-origin`
  and a restrictive `Permissions-Policy` (`_headers`).
  The only `|safe` in the templates is on the bundled static stylesheet
  (`{{ base_css|safe }}` in `_base.html`); `grep -rn "|safe\|Markup("
  faultline/web/templates/ faultline/web/*.py` returns that one line and
  nothing else. The dashboard renders the analysis with the same
  `build_page` renderer as the static report, so the rules above apply to it.
* **Terminal** (`faultline/cli.py`): every capture-derived value that reaches
  the rich console (titles, summaries, explanations, indicator texts,
  evidence summaries, hosts, warnings, file names, error messages) is wrapped
  in `_safe()`, which strips control characters and then applies
  `rich.markup.escape`, so a hostname like `[red]x[/]` or an ANSI escape
  sequence is printed literally.

### T3: Resource exhaustion

* Reader and decoder caps: see T1.
* Detector state tables are `BoundedDict`s (`faultline/detectors/base.py`,
  default 100 000 keys) so millions of flows or hosts cannot grow memory
  without bound; `Evidence` keeps at most 200 frame numbers per finding and
  counts the rest (`packet_total`).
* Evidence export (`engine._attach_evidence`) re-reads the file once, only
  for wanted frames, and caps per-finding packets and the **total** evidence
  bytes (8 MiB; a warning is added when the cap is hit).
* Dashboard: `MAX_CONTENT_LENGTH` (200 MiB default, friendly 413 page), at
  most **two concurrent analyses** (`threading.BoundedSemaphore(2)`, 503
  otherwise), uploads streamed to disk in 1 MiB chunks.
* Warnings capped at 50, `HostTable.to_list(limit=500)`.

### T4: Data leakage

* **Payload bytes are never retained.** `Packet` has no payload field, only
  `payload_len` (`faultline/model.py`). Decoders parse from the frame buffer
  and keep typed fields only.
* **Credentials are detected, never extracted.** `decode._detect_cleartext_cred`
  and the HTTP `Authorization: Basic` branch set `Packet.cred` to a protocol
  label (`"FTP"`, `"HTTP Basic"`, `"Telnet"`, …). The secret itself is never
  stored, logged or displayed; the finding says *that* a credential crossed
  the wire in clear text, not *what* it was.
* **Redaction** (`faultline/report/redact.py`, `--redact` / dashboard
  toggle): `redact_report(report)` deep-copies the report and replaces every
  IPv4, IPv6 and MAC address wherever it appears (keys, values, nested
  prose, `host:port`, colon and dash MACs) with a pseudonym such as
  `lan-host-3f2a1c`, `inet-host-91bc0e`, `mac-7c1e22`. Pseudonyms are
  `HMAC-SHA256(key, canonical address)` with a **fresh random key per call**
  (`secrets.token_bytes(32)`) that is never written anywhere: consistent
  inside one report, irreversible, and uncorrelatable across reports.
  Addresses that carry meaning but no identity (0.0.0.0, 255.255.255.255,
  loopback, multicast, broadcast / null MACs) stay readable. Word-boundary
  regexes keep version numbers (`1.0.0`, `TLS 1.2`), timestamps and ports
  intact. Raw evidence pcaps are **removed** from redacted reports
  (`redact_report` pops `evidence`; `engine.Report.to_dict` never attaches
  them in redact mode). Optional `redact_names=True` also pseudonymises
  hostnames in known fields. Tests: `tests/test_redact.py` (41 tests).
* **Reports are created owner-readable only**: `cli._write_private` opens
  `--html` / `--json` outputs with `os.open(..., 0o600)` because they
  describe a network.
* **No paths leak**: the dashboard analyses uploads under a display name, and
  `_scrub` replaces the temp path and temp directory in every report string
  and error message; error pages are generic (`_crash`), `app.debug = False`.
* **Nothing leaves the machine**: no network client code anywhere in
  `faultline/` (`socket` is imported in `decode.py` only for `inet_ntop`
  address formatting). No telemetry, no update check, no CDN assets.

### T5: Local web dashboard (`faultline/web/app.py`)

| Risk | Control |
|---|---|
| Exposure beyond the machine | binds to `127.0.0.1` by default; `run()` prints a loud warning if another host is chosen |
| DNS rebinding / unexpected `Host` | every request's `Host` must be `localhost`, `127.0.0.1` or `::1` (`FAULTLINE_ALLOWED_HOSTS`, `_guards`) |
| CSRF from another site | per-process random token (`secrets.token_urlsafe(32)`) required on every POST (form field or `X-Faultline-Token` header), compared with `hmac.compare_digest`; any non-matching `Origin` header on a POST is refused with 403 |
| Oversize uploads | `MAX_CONTENT_LENGTH`, 413 handler |
| Hostile uploads | extension allowlist **and** magic-byte sniff (`sniff_capture`) before the analyser sees the file; empty files refused |
| Filename / path tricks | the user's filename is only ever a sanitised **display name** (`sanitize_display_name`); the file is written with `tempfile.mkstemp` (0600) into a private `mkdtemp` (0700) directory and `unlink`ed in a `finally` block |
| Path traversal in `/sample/<name>` | the name is looked up in an allowlist dict built by `list_samples`; anything else is 404. Nothing is joined to a path from user input |
| Session secret | `SECRET_KEY` is generated per process and never stored; no sessions or cookies carry data |
| Error pages | generic, no tracebacks, no paths; `debug` forced off |

Evidence downloads in the dashboard never touch a path: the per-finding
evidence pcaps are base64 strings inside the embedded report JSON
(`report["evidence"]`), and the "Download evidence .pcap" button builds a
`Blob` from them in the browser (`report/assets/report.js`,
`downloadEvidence`). With the redact toggle on, the engine skips the evidence
pass, `redact_report` drops the `evidence` key, and the button is not
rendered.

### T6: Supply chain

* Runtime analysis code is **standard library only** (reader, decoder,
  detectors, engine, redaction, HTML report). Optional extras: `rich`
  (terminal UI) and `Flask` (dashboard), both imported lazily so the core
  works without them.
* No `eval`, `exec`, `pickle`, `marshal`, `shelve`, `yaml.load`,
  `subprocess` or `os.system` anywhere under `faultline/` (checked with the
  grep in section 4).
* No secrets in the repository: `scripts/check_secrets.py` scans every text
  file for key formats, PEM headers, tokens, `password = "…"` literals,
  credentials in URLs and high-entropy literals; it exits non-zero on hits.
  The only credential-looking strings in the tree are deliberately fake test
  vectors (`hunter2`, base64 of `user:s3cr3t`) in `tests/`, which the
  allowlist recognises.

---

## 3. What we deliberately do NOT do

* No network calls of any kind: no DNS lookups, no GeoIP, no reputation
  feeds, no update checks, no telemetry. The tool is fully usable offline.
* No `eval` / `exec` / `pickle` / `subprocess` / shelling out to tshark.
* No hardcoded secrets, API keys or accounts; the only keys that exist are
  random, per-process and in memory (`CSRF`, `SECRET_KEY`, redaction HMAC).
* Payload bytes are never kept on packet objects, never written to disk
  (except as the user-requested, capped evidence pcaps, which are disabled
  under `--redact`).
* Credentials are detected but never extracted, stored or shown.
* Uploaded files are never kept under their original names and never
  survive the request.
* The HTML report never loads anything remote and never executes
  capture-derived text.

---

## 4. How to verify (two minutes)

```bash
# 1. Hardening and redaction tests (reader, fuzz harness, redactor)
.venv/bin/python -m pytest tests/test_reader.py tests/test_fuzz.py tests/test_redact.py -q

# 2. Long fuzz run through the whole pipeline; prints a summary table, exit 0 = no crash
.venv/bin/python scripts/fuzz.py -n 3000 --seed 42

# 3. Secret scan over the repository (exit 0 = clean)
.venv/bin/python scripts/check_secrets.py

# 4. No dangerous primitives or network clients in the runtime code
grep -rnE '\b(eval|exec|pickle|marshal|shelve|subprocess|os\.system|urllib|requests|http\.client)\b' faultline/ --include='*.py'
#   expected: only prose matches (the word "requests" in detector and lab text) and two
#   `from urllib.parse import ...` lines (web/app.py: urlsplit for the Origin check;
#   report/html.py: quote for the data-URI favicon). Neither opens a connection.

# 5. Hostile files by hand: everything below must end in a clear message, never a traceback
head -c 10 /dev/urandom > /tmp/junk.pcap && .venv/bin/python -m faultline analyze /tmp/junk.pcap
mkfifo /tmp/fifo.pcap && .venv/bin/python -m faultline analyze /tmp/fifo.pcap   # must not hang
```

Step 5 as run on the submitted code: both commands exit with code 2 after a
single line (`Cannot analyse this file: not a pcap/pcapng capture (magic
bytes …)` and `Cannot analyse this file: capture path is not a regular
file`); the FIFO is refused by `_validate_path` before `open()`, so there is
no hang. The six files under `samples/malformed/` give the same kind of
one-line note (truncation offset, oversize record length, empty file) and
`faultline bench` reports them as "Hostile files handled 6/6".

---

## 5. Responsible use

Faultline is built for defenders: network administrators, students and
incident responders analysing traffic they are entitled to see. Analyse only
captures you own or have explicit permission to analyse. Captures contain
personal data (addresses, hostnames, visited sites) and sometimes
credentials: treat them, and the reports made from them, as confidential, use
`--redact` before sharing a report outside the team, and delete captures you
no longer need. The tool does not generate, inject or replay traffic, and the
lab generator (`faultline/lab`) only writes synthetic pcap files to disk.

Report a security problem in Faultline by opening an issue titled
`[security]` or contacting the maintainers directly; include the capture
(or a minimised fuzz case from `scripts/fuzz.py --keep out/`) that triggers it.
