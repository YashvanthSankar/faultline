# Faultline: TODO

Deadline: **Sun 01/11/2026 21:00 IST** (hard; commits after this are ignored). Target: push the final version by 20:30.

## Phase 0: Core (lead) · 13:10 → 14:00
- [x] Repo, venv, idea.md / tech.md / todo.md
- [ ] `model.py`: Packet, Finding, Indicator, Severity, Category, Incident
- [ ] `capture/reader.py`: hardened pcap / pcapng / gzip streaming reader
- [ ] `capture/decode.py`: L2 → L7 decoders (ARP, IPv4/6, TCP opts, UDP, ICMP/v6 with inner header, DNS, DHCP, TLS, HTTP, creds)
- [ ] `capture/writer.py` + `lab/craft.py`: byte-level packet builders
- [ ] `context.py` HostTable, `detectors/base.py`, `engine.py`, a minimal `cli.py analyze`

## Phase 1: Parallel build · 14:00 → 16:30
- [ ] **Agent A, scenario lab**: `lab/scenarios.py` with 20+ labelled captures in `samples/` (faults, attacks, clean, mixed, malformed)
- [ ] **Agent B, TCP / latency / MTU**: TCP tracker; retrans (+ upstream/downstream localization), dup-ACK, lost segment, RST, refused, zero window, SYN timeout; RTT and server-time blame split; PMTUD black hole, frag-needed, MSS mismatch
- [ ] **Agent C, L2 / infra**: ARP (conflict vs. spoofing, scan, unanswered, storm), DHCP (rogue, no server, NAK, starvation), DNS (timeouts, rcodes, slow, hijack, tunneling)
- [ ] **Agent D, attacks / app**: scans (SYN / FIN / NULL / Xmas / UDP / sweep), floods, ICMP (unreachable, TTL / loop, redirect), TLS alerts / old TLS, HTTP errors, cleartext creds
- [ ] **Agent E, presentation**: HTML report (single file, CSP, timeline, findings, incidents, hosts, evidence downloads) + Flask web dashboard (upload, samples gallery, redact toggle)
- [ ] **Lead**: verdict engine, correlation / incidents / health score, terminal UI, redact, diff, bench, evidence export

## Phase 2: Integrate and harden · 16:30 → 18:00
- [ ] Run every sample; tune thresholds; zero false alarms on clean / busy captures
- [ ] Fuzz test + malicious inputs (truncated, giant lengths, pcapng loops, gzip bomb, DNS pointer loops)
- [ ] Benchmark table (precision / recall per scenario)
- [ ] Python 3.10 compatibility check; fresh-clone install test following the README exactly

## Phase 3: Ship · 18:00 → 20:30
- [ ] README: problem, solution, features, screenshots, setup, usage, detector catalog, security, benchmark, libraries used, team
- [ ] Demo video (2 to 5 min): script → real screen recording of the CLI + dashboard → voiceover → link in README
- [ ] Final push before 20:30; submit the Google Form (team leader)
