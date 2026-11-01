# Faultline demo video: shot-by-shot script

Team **Moorthy Gang** · Yashvanth S (CS24I1029). Target length: **3:30 to 4:30**. One take per segment is fine; cut them together. Speak a touch slower than feels natural; judges may not be native English speakers. Everything shown must be real output of the current code (the brief disqualifies faked demos), so rehearse every command on the day of recording and never paste pre-made output. Every command and every number quoted below was run against the submitted code; where output varies run to run (timings), read the number from the screen.

## Pre-recording checklist

**Environment**

- [ ] Fresh terminal, `cd ~/Dev/faultline && source .venv/bin/activate`, `pip install -e .` already done, `faultline --version` prints `faultline 1.0.0`.
- [ ] `ls samples/` shows the 30 scenario captures, `labels.json` and `malformed/` (6 hostile files). If anything is missing, `faultline lab samples/` regenerates them.
- [ ] `faultline bench` passes: `Detection 30/30 (100%) · Correct fault/attack verdict 30/30 (100%) · False alarms 0 · Clean captures quiet 4/4 · Hostile files handled 6/6`.
- [ ] `faultline web --no-browser` is running on `http://127.0.0.1:8765`; a browser tab is open on it and zoomed to ~125 % so text is legible at 1080p. The sample gallery on the front page lists every capture as a tile.
- [ ] Wireshark installed and opened once (so no first-run dialog appears on camera).
- [ ] Pre-run every command once so Python byte-code is compiled and nothing lags.
- [ ] Clear the terminal (`clear`) before each segment; macOS Focus / Do Not Disturb on.
- [ ] Hide the Dock and menu bar clutter; close other apps; remove personal files from the Desktop if it will be visible.

**Terminal**

- [ ] Window 1920×1080 (or 1280×720, same ratio). Terminal/iTerm2 profile with font size 18–20 (Menlo or JetBrains Mono), dark background, no transparency, ~120 columns × 34 rows at 1080p (the report panels are laid out for ~120 columns).
- [ ] Prompt shortened to something like `faultline $` (`export PS1="faultline $ "`) so paths don't eat the screen.
- [ ] `--no-color` is **not** used; the colours are part of the story.

**Files to have ready** (all exist in `samples/`)

- [ ] `mitm_chain.pcap`, `lossy_link.pcap`, `ip_conflict.pcap`, `arp_spoofing.pcap`, `outage_vs_attack_mixed.pcap`, `dns_failure.pcap`, `clean_office.pcap`, `xss_payload.pcap`, `malformed/huge_caplen.pcap`, `malformed/bad_magic.pcap`.

**Recording**

- macOS: QuickTime Player → File → New Screen Recording → select the window region; microphone: built-in or headset. Or `Cmd+Shift+5`.
- Record the voice **while** doing the actions; it sounds natural and saves editing. Re-record a segment rather than fixing it in post.
- Compress to under 100 MB when done:

  ```bash
  ffmpeg -i in.mov -vcodec libx264 -crf 28 -preset slow -acodec aac -b:a 128k demo.mp4
  ```

- Upload (unlisted YouTube or Google Drive with link access), paste the link into README.md.

---

## The script

Timecodes are targets; total ≈ 4:10.

### 0:00–0:20 · Hook

**On screen:** Title card (a plain slide or the README header in a browser): "**Faultline** – Is my network broken, or is someone breaking it?" with "Moorthy Gang · Yashvanth S". Then cut to the terminal.

**Voiceover:**

> Monday morning in a small office. The Wi-Fi is up, but every website is wrong, video calls freeze, and the printer has vanished. The office manager does the one thing everyone knows: restart the router. Here's the problem. To the person suffering it, an outage and an attack look exactly the same. "The internet is broken." And while the router reboots, the attacker who's sitting on the LAN keeps reading the traffic.

### 0:20–0:40 · The problem and the promise

**On screen:** Terminal. Type slowly: `faultline analyze samples/mitm_chain.pcap` but don't press Enter yet.

**Voiceover:**

> The only honest way to know what's happening is a packet capture, and reading one takes years of protocol knowledge. Faultline reads it for you. Give it a pcap and it answers three questions in plain language: what's wrong, is it a fault or an attack, and what do I fix first. With the exact packets as proof. And it's all our own code: our own capture reader, our own protocol decoders, our own detection logic. No Wireshark, no tshark, no Scapy.

### 0:40–1:40 · Demo 1: rogue DHCP → DNS hijack → stolen password (web dashboard)

**On screen:**

1. Press Enter. The red **UNDER ATTACK** panel appears: "Rogue DHCP server on the network (192.168.1.66)", health 52/100, "2 attacks · 0 faults · 1 misconfiguration", then the **FIX THIS FIRST** block "I1 Man-in-the-middle attack" with root cause F1 and two consequences. Pause one second.
2. Switch to the browser on `http://127.0.0.1:8765`. Click the **mitm_chain.pcap** tile in the sample gallery.
3. Point at the verdict banner, the health score, and the **Fix this first** card "Man-in-the-middle attack": root cause "Rogue DHCP server on the network (192.168.1.66)" → consequences "DNS answers are being forged" and "Passwords are being sent unencrypted (HTTP Basic to 192.168.1.66:80)".
4. Open the root finding. Scroll to **Fault or attack? Why we think so**: "It names itself (192.168.1.66) as the router instead of 192.168.1.1", "It points clients' DNS at a local device (192.168.1.66)", "hands out addresses in the same subnet as the real server, so its leases look normal". Then the line **Why not "A second router is handing out addresses (192.168.1.66)"?**.
5. Open the consequence "DNS answers are being forged": the evidence lines show lookups for `login.example-bank.com` answered with 192.168.1.66.
6. Click **Download evidence .pcap (open in Wireshark)** on that finding; open the file in Wireshark; the DNS responses for the bank's names all point at 192.168.1.66. (Or click **Copy filter** and paste the `frame.number in {…}` filter into Wireshark on the full capture.)

**Voiceover:**

> Let's load the capture from that office. Verdict: under attack. Not "something is slow", not forty red alerts. One incident, and a sentence a manager can act on: a device on your network put itself between your users and the internet.
>
> Faultline found three things and understood that they're one story. A second DHCP server appeared and told laptops to use it as their router and their DNS server. Then it answered name lookups for the bank's website with its own address. And then a password went to it over plain HTTP. The dashboard says: fix the DHCP server first; the rest are consequences.
>
> Here's the part that matters. Two DHCP servers is also what you see when someone plugs a home router into the office. So why does Faultline call this an attack and not a misconfiguration? Because it tells you. The second server hands out addresses in the real subnet, so its leases look normal, but it names itself as the router and points DNS at itself, a laptop on the LAN. A home router doesn't do that. The alternative reading, and why it lost, is right here.
>
> Every finding comes with the frames. One click gives me a tiny pcap with only the evidence, or a Wireshark filter, and you can see it with your own eyes: the bank's login site, resolved to the attacker.

### 1:40–2:20 · Demo 2: lossy Wi-Fi in the CLI (fault, not attack)

**On screen:** Terminal. Run:

```bash
faultline analyze samples/lossy_link.pcap
```

The yellow **FAULTY** panel: "Packets are getting lost on the way to or from 203.0.113.10", "no sign of an attack", health 92/100. Point at "5.0% of TCP data packets (56 of 1,122) had to be sent again", the sentence "Losses are spread over both sides of the capture point (53.6% near the local devices, 46.4% towards 203.0.113.10)", the fix steps (move closer to the access point or try a cable; interface error counters; `mtr`), and the **Why we think it's a fault** bullets. Then run:

```bash
faultline diff samples/dns_failure.pcap samples/clean_office.pcap
```

It prints `BEFORE → AFTER`, `dns_failure.pcap: faulty (86/100) → clean_office.pcap: healthy (100/100)`, the conclusion "Everything that was wrong before is gone. The fix worked." and three `(done) fixed` lines (DNS lookups timing out, SERVFAIL errors, slow lookups).

**Voiceover:**

> Second office, different complaint: downloads crawl and video calls keep freezing. Faultline says faulty, and explicitly: no sign of an attack. Five percent of packets are being lost, and because we know where the capture was taken, it can say on which side: here the loss is spread over both sides, so it's congestion rather than one bad cable, and the fix steps say exactly what to check first. That's the difference between "it's slow" and a diagnosis.
>
> After a fix, you take another capture and run diff. Here a DNS outage, then a clean capture: Faultline tells you what got fixed, what persists, and whether anything new appeared. That's how you prove to your boss that the problem is actually gone.

### 2:20–2:55 · Demo 3: IP conflict vs ARP spoofing, side by side

**On screen:** Split the terminal in two panes (or run one after the other). Left:

```bash
faultline analyze samples/ip_conflict.pcap
```

Right:

```bash
faultline analyze samples/arp_spoofing.pcap
```

Highlight: both findings have the same kind `arp.duplicate_ip` (visible in the `--json` output and the dashboard). Left is **FAULTY / MISCONFIG "Two devices are using the same IP address"** (192.168.1.23, two MACs; indicators: "A device probed 192.168.1.23 before using it (RFC 5227 duplicate-address check)", "Both MACs send their own normal traffic", "not the router's"). Right is **UNDER ATTACK / CRITICAL "Someone is impersonating 192.168.1.1 (ARP spoofing / man-in-the-middle)"** with indicators "answered ARP for 2 different IPs that belong to other devices", "belongs to the router (default gateway)", "149 ARP replies nobody asked for", and **MITRE ATT&CK T1557.002 ARP Cache Poisoning**. Each side ends with a **Why not …?** line for the other reading.

**Voiceover:**

> This is the heart of Faultline. These two captures look identical to a user: two devices answering for the same IP. On the left, a printer and a hand-configured laptop both ended up on dot twenty-three. The newcomer probed the address first, like an honest device does, and both keep sending their own traffic. Misconfiguration. Fix: give one of them a different address. On the right, a laptop is claiming the router's address, a hundred and forty-nine unsolicited replies, and it's impersonating a second host too. That's ARP spoofing, and it gets the MITRE technique.
>
> Our detectors don't decide "attack". They list evidence for each hypothesis with a weight, and one engine scores them, so every finding shows what pointed each way and why one reading won. If the evidence is balanced, the confidence says so and both readings are shown. We'd rather say "probably a conflict, check for spoofing" than cry wolf.

### 2:55–3:15 · Demo 4: a fault and an attack in the same capture

**On screen:**

```bash
faultline analyze samples/outage_vs_attack_mixed.pcap
```

The **UNDER ATTACK** panel reads "Port scan: 192.168.1.66 is checking which services are open on 192.168.1.20" and, in the summary, "Separately, 1 genuine fault or misconfiguration also need attention"; the counter shows "1 attack · 1 fault". Scroll: F1 is the port scan (300 ports in 1.4 s, T1046), the second finding is the DNS server timing out, reported as its own fault, not blamed on the scan.

**Voiceover:**

> Real networks don't fail one thing at a time. Here the DNS server really is down, and at the same time an unknown device is scanning the file server. Faultline keeps them apart: one attack, one genuine fault, and it does not blame the outage on the attacker or hide the attack behind the outage.

### 3:15–3:50 · Security segment

**On screen:** Terminal. Run in quick succession:

```bash
faultline analyze samples/malformed/huge_caplen.pcap
faultline analyze samples/malformed/bad_magic.pcap; echo "exit $?"
python scripts/fuzz.py -n 1000
```

`huge_caplen.pcap` ends with the note "record at byte 82 claims 2,147,483,647 bytes (limit 262,144); file is corrupt or hostile, stopped reading here". `bad_magic.pcap` prints one line, "Cannot analyse this file: not a pcap/pcapng capture (magic bytes …)", and `exit 2`. The fuzzer prints a summary table ending in `RESULT: PASS - no crash, bounded time` (about a millisecond per case; read the number).

Then in the browser click the **xss_payload.pcap** tile. The page says HEALTHY; scroll to **Who was talking**: one device's hostname is literally `"><img src=x onerror=alert(1)>`, shown as text, nothing fires. Then:

```bash
faultline analyze samples/mitm_chain.pcap --redact
python scripts/check_secrets.py
```

Point at the `addresses redacted` tag in the banner and the `lan-host-…` / `mac-…` pseudonyms; the secret scan prints `scanned N text files, 0 potential secret(s) found: PASS`.

**Voiceover:**

> A capture file is untrusted input, and a malicious one is a cheap way to attack the analyst. So we wrote the reader ourselves. A record header claiming two gigabytes: refused before a single byte is allocated, and the rest of the file is still analysed. Random bytes with a pcap name: one clear line and a clean exit code. And our fuzzer mutates real captures a thousand times through the whole pipeline: no crash, bounded time.
>
> Reports are hardened too. This capture has an HTML injection payload as a device name. In the dashboard it's just text: strict content security policy, no external resources, everything rendered as text, never as HTML.
>
> And privacy. Payloads are never kept in memory. Passwords sent in the clear are reported by protocol only, never shown. With redact, every address becomes a consistent pseudonym under a random key that is never written down, so you can share the report with a vendor. And the repository itself is scanned for secrets.

### 3:50–4:05 · Benchmark

**On screen:**

```bash
faultline bench
```

Let the table render. Point at the summary line: `Detection 30/30 (100%) · Correct fault/attack verdict 30/30 (100%) · False alarms 0 · Clean captures quiet 4/4 · Hostile files handled 6/6 · 50,791 packets in …s`.

**Voiceover:**

> How do we know it works? Every sample is generated by our own scenario lab, byte by byte, with labels. The benchmark runs all thirty scenarios plus six hostile files: every expected finding detected, every fault-or-attack verdict correct, zero false alarms, all four clean captures silent, fifty thousand packets in about a second. Clean captures stay quiet, because a tool that cries wolf gets uninstalled.

### 4:05–4:15 · Close

**On screen:** README quick-start section in the browser, then the title card.

**Voiceover:**

> Try it yourself: clone, pip install, faultline analyze. Python standard library for the engine, rich and Flask for the screens, nothing else. Faultline: is my network broken, or is someone breaking it? Now you can tell.

---

## Backup cuts if running long

- Drop the Wireshark open in Demo 1 (saves ~15 s); say "and this opens in Wireshark" while hovering the download button.
- Drop the `diff` shot (saves ~15 s) and mention it in the close.
- Drop Demo 4 (saves ~20 s) and mention "it separates a fault from an attack in the same capture" in Demo 3.
- Shorten the security segment to `bad_magic` + XSS + redact (saves ~15 s).

## Things judges listen for (make sure they are said out loud)

- "Our own reader, decoders and detection logic; no tshark or Scapy."
- "Fault **or** attack, and *why not* the other one."
- "Root cause first; the rest are symptoms."
- "Exact packets as evidence; opens in Wireshark."
- "Hostile input handled; no payloads kept; redaction."
- "Clean captures stay quiet; benchmark numbers on screen."
- "Clone, install, one command."
