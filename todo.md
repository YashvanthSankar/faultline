# Faultline: build log

Deadline: **Sun 01/11/2026 21:00 IST**. Team **Moorthy Gang**: Yashvanth S (CS24I1029).

## Phase 0: Core
- [x] Repo, plan (idea.md / tech.md / todo.md)
- [x] `model.py`: Packet, Finding, Indicator, Variant, Severity, Category, Incident
- [x] `capture/reader.py`: hardened pcap / pcapng / gzip streaming reader
- [x] `capture/decode.py`: own L2 → L7 decoders (~320k packets/s)
- [x] `context.py` host table, `detectors/base.py`, `engine.py`, `cli.py`

## Phase 1: Parallel build
- [x] Scenario lab: byte-level packet crafting, 39 labelled captures (faults, misconfigs, attacks, clean, hostile)
- [x] TCP / latency / MTU detectors (loss localisation, blame split, PMTUD black hole)
- [x] ARP / DHCP / DNS detectors (conflict vs spoofing, rogue vs misplugged DHCP, hijack vs captive portal, tunnelling)
- [x] Scan / flood / ICMP / app detectors (SYN flood vs flash crowd, routing loop vs traceroute, TLS, HTTP, cleartext creds)
- [x] Hypothesis engine ("why not"), correlation (root cause vs symptom), health score, verdict
- [x] HTML report (single file, strict CSP) + Flask dashboard (CSRF, DNS-rebinding guard, upload hardening)
- [x] Security: fuzzer, redaction, secret scanner, SECURITY.md

## Phase 2: Integrate and harden
- [x] Benchmark: 34/34 detected, 34/34 correct verdicts, 0 false alarms, 4/4 clean quiet, 6/6 hostile handled
- [x] Fuzz: 3,000 mutated captures, 0 crashes
- [x] Fresh clone + `pip install -e .` + full test suite on Python 3.10 (369 passed)
- [x] Fixed in verification: IP/MAC redaction leaks at sentence boundaries, 413 on real-size web uploads, `--no-color` position, non-regular-file message, deterministic gzip sample

## Phase 3: Ship
- [x] README with real outputs, screenshots, benchmark table
- [x] Docs: THINKING.md, DETECTORS.md, demo-script.md (fact-checked against the code)
- [x] Real-world validation on 22 public Wireshark sample captures: 22/22 correct, 0 false alarms, 0 crashes
- [x] Demo video (3:50) in docs/demo, linked in README
- [x] Repository set to public
- [ ] Google Form submitted by the team leader before 21:00
