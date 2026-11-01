# Faultline: idea

> **"Is my network broken, or is someone breaking it?"**
> Faultline reads a packet capture and answers that question in plain language. It shows the exact packets behind every answer, the likely cause and the fix.

## The problem (from the brief)

Small offices, labs and campus departments have no network engineer. When the network is slow, drops connections or acts strangely, the only real way to find out why is to open a packet capture in Wireshark and read it line by line. That takes deep protocol knowledge. Worse, **an outage and an attack look the same to a user** ("the internet is broken"). So people restart the router and wait while the real problem, which may be an attacker, carries on.

## Our answer

Faultline is an offline diagnostic engine with a **CLI** and a **local web dashboard**. You give it a `.pcap`, `.pcapng` or `.pcap.gz` file and it returns:

1. **A verdict at the top**: *Healthy*, *Faulty* or *Under attack*, with a 0 to 100 health score.
2. **Findings**, each with:
   - a plain-language explanation a beginner can follow, plus an expert view;
   - **Fault, Misconfiguration or Attack**, with the reasoning *for* and *against* each one ("why we think this is ARP spoofing and **not** an IP conflict");
   - the likely cause and practical fix steps;
   - **the exact packet numbers** as evidence, which you can export as a tiny `.pcap` to open in Wireshark;
   - a MITRE ATT&CK technique for attacks.
3. **Incidents**: related findings chained into one story, with root cause separated from symptoms. For example, "a rogue DHCP server handed out a fake DNS server, so DNS answers were hijacked. Fix the DHCP server first."
4. **A timeline** of what happened, readable by a human.

## What makes it different (novelty)

| Existing tools (Wireshark, Zeek, Snort, tcpdump) | Faultline |
|---|---|
| Show packets or raise alerts; *you* interpret them | Explains *what it means* for a beginner and *what to do* |
| Either fault-focused (Wireshark expert info) or attack-focused (IDS) | **Fault vs. attack reasoning engine**: weighs competing hypotheses and explains "why not the other one" |
| Alert per event, so you get floods of symptoms | **Root cause vs. symptom correlation**: "fix this one thing first" |
| Need expertise to see *where* loss happens | **Loss localization**: upstream or downstream of the capture point |
| "It's slow" stays vague | **Blame split** for slow connections: network vs. server vs. client vs. receive-window |
| Reports may leak IPs and credentials when shared | **Privacy by design**: `--redact` pseudonymizes hosts, and credentials are detected but never shown |
| Hard to prove a fix worked | **`faultline diff before.pcap after.pcap`** shows what got fixed and what got worse |
| Unknown accuracy | **Built-in scenario lab and benchmark**: labelled captures, precision and recall, plus a false-alarm rate measured on clean captures |

## Covered by design (every challenge point in the brief)

- **Reading captures safely**: our own hardened pcap/pcapng parser with strict bounds checks, size and record limits, and decompression-bomb guards. It never crashes on bad input and is fuzz-tested with malformed files. Packet contents are always treated as hostile, including XSS-proof reports.
- **Finding faults**: TCP retransmissions, resets, refused connections, zero windows, lost segments, DNS failures and timeouts, duplicate IPs, ARP conflicts, MTU mismatches and PMTUD black holes, unusual delays, routing loops and unreachable hosts.
- **Finding attacks**: port scans (SYN, FIN, NULL and Xmas, UDP, sweeps), ARP spoofing, DNS hijacking and spoofing, rogue DHCP servers, DHCP starvation, SYN floods, ICMP redirects, cleartext credentials and DNS tunneling.
- **Telling an outage from an attack**: the hypothesis engine plus correlation, tuned on clean captures to keep false alarms low.
- **Explaining clearly**: a beginner view, an analogy and an expert view for every finding.
- **Recommending fixes**: cause and next steps for every finding.
- **Showing the evidence**: packet numbers, conversations, a timeline and per-finding evidence pcaps.

## Demo story (video)

1. "The Wi-Fi works, but every website is wrong." We load `mitm_rogue_dhcp.pcap`, and Faultline says **Under attack**: a rogue DHCP server led to DNS hijacking, with the evidence packets and the fix.
2. "Video calls keep freezing." We load `lossy_link.pcap`, and Faultline says **Fault, not attack**: 6% loss downstream of the capture point, with the blame split and the fix.
3. The side-by-side ARP case: *IP conflict* versus *ARP spoofing* look identical to a user, and Faultline tells them apart and explains why.
4. Security: we feed it a malicious or corrupt capture and it handles it gracefully. Then the `--redact` report.
5. The benchmark table: accuracy across all scenarios and zero false alarms on clean traffic.
