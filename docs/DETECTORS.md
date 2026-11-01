# Detector catalogue

Every finding Faultline can raise, what it means in plain words, the signals and thresholds behind it, how the fault / misconfiguration / attack reading is decided, the MITRE ATT&CK technique for attacks, and the sample capture that demonstrates it.

<!-- VERIFY: CRITICAL. Attack samples named in this file (arp_spoofing, arp_scan, dns_hijack, dns_tunneling, mitm_rogue_dhcp, dhcp_starvation, port_scan_*, host_sweep, syn_flood, icmp_redirect, cleartext_creds, tls_deprecated) are NOT in samples/labels.json yet -->

Conventions:

- **Kind** is the stable identifier in JSON output (`finding.kind`).
- **Default reading** is the detector's own hint; the verdict engine (`faultline/verdict.py`) can overrule it using the indicators listed under *Discriminators*. Weights are 0.5 (weak hint) to 3 (near conclusive).
- Count thresholds are multiplied by the sensitivity scale (`low` ×1.6, `normal` ×1.0, `high` ×0.6; `faultline/context.py`, `Config.scale`).
- Evidence per finding: up to 200 frame numbers plus a total count (`Evidence.CAP`), evidence lines for the first 40 frames, and an evidence pcap of up to 150 frames (`faultline/engine.py`).
- Severity: 0 info, 1 low, 2 medium, 3 high, 4 critical. Only severity ≥ 2 affects the overall verdict and `--fail-on`.

<!-- VERIFY: sections for tcp, arp, scan, flood reflect the landed code; latency, mtu, dhcp, dns, icmp, app sections are from the design and must be checked against their modules when they land -->

---

## TCP (`faultline/detectors/tcp.py`)

A per-flow state tracker keyed on the 4-tuple (bounded to 200,000 flows, 32 sequence holes per flow, 50,000 services). It follows sequence numbers, ACKs, SACK blocks and window sizes to tell apart loss, refusal, dead peers and stuck receivers.

### `tcp.retransmissions`: packets are being lost and resent

- **Plain words**: data had to be sent twice because the first copy never arrived. A little is normal; a lot means a bad link.
- **Signals**: a segment whose sequence range was already seen (retransmission); three duplicate ACKs for the same sequence (fast retransmit); a receiver ACK/SACK referring to data the capture never saw (lost before the capture point).
- **Threshold**: rate-based: retransmitted data segments / all data segments, per direction and for the whole capture, with a minimum absolute count so tiny flows stay quiet; severity rises with the rate. <!-- VERIFY: exact rate cut-offs in TcpDetector.finalize -->
- **Loss localisation**: original *and* retransmission seen → lost **after the capture point** (`loss_server_side`). A retransmission that fills a sequence hole late, i.e. the original never passed us → lost **before the capture point** (`loss_client_side`). The finding states which side, and the fix steps differ (`mtr` beyond the capture point vs. check the local link/Wi-Fi).
- **Indicators**: loss rate across N connections; duplicate ACK count; "loss affects many unrelated servers: a shared link problem"; "no sign of deliberate interference" (fault).
- **Discriminators**: fault by default. Attack indicators only when the losses coincide with a flood finding (handled by correlation, not here).
- **Sample**: `samples/lossy_link.pcap` (downstream loss, ≈ 6 %).

### `tcp.resets`: connections are being torn down abruptly

- **Plain words**: one side slammed the door mid-conversation.
- **Signals**: RST after data has flowed (not a refused handshake), grouped by the host that sent them.
- **Threshold**: share of *established* connections that were aborted by RST. <!-- VERIFY: cut-off -->
- **Discriminators**: fault (server/middlebox dropping sessions; "reset after being idle 5+ minutes: firewall/NAT timeout") by default. **Forged-reset indicators (attack)**: the RST's IP TTL differs by 5+ from every other packet of that endpoint; the supposed sender keeps sending normally after "its" reset; the RST sequence number is inside the window but not the expected one. When attack wins: severity high, MITRE T1499 Endpoint Denial of Service.
- **Sample**: part of `samples/connection_refused.pcap`, `samples/port_scan_syn.pcap` (as a symptom). <!-- VERIFY -->

### `tcp.refused`: a service is down or closed

- **Plain words**: clients knock, the server says "nobody here" (RST in reply to SYN).
- **Signals**: SYN → RST/ACK with no SYN/ACK in between, grouped by server IP:port.
- **Threshold**: per service (server:port) once several distinct normal clients are refused. <!-- VERIFY: count -->
- **Discriminators**: **fault** when *many clients* hit *one port*; indicators distinguish "every attempt refused, never accepted" (service down/closed), "accepted earlier, then started refusing" (crashed), "alternates between accepting and refusing" (restarting/overloaded), and refusals arriving with a different IP TTL than the server's own replies (a middlebox/firewall is answering, misconfig). Weak attack indicator (0.5) when many different sources hit a closed port. When *one client* hits *many ports*, this is not reported here; the scan detector owns it and the refusals become symptoms of `scan.port`.
- **Sample**: `samples/connection_refused.pcap`.

### `tcp.syn_timeout`: connection attempts get no answer

- **Plain words**: the phone rings and rings. The host or the path to it is dead, or a firewall drops silently.
- **Signals**: SYN retransmitted (same seq) with no SYN/ACK or RST ever seen; exponential back-off pattern (1 s, 2 s, 4 s).
- **Threshold**: per service, connection attempts that retried the SYN 2+ times with no SYN/ACK or RST. <!-- VERIFY: count -->
- **Discriminators**: fault by default; indicators tell apart "host is up (sent other traffic) but the port never answered" (filtered), "host never sent a single packet" (down/unreachable), "stale address", and "the same service accepted other connections" (overloaded). **Attack variant** when many different sources each send a single never-retried SYN (SYN-flood signature; T1499). If the gateway's ARP is unanswered, becomes a symptom of `arp.unanswered`; if a flood is present, becomes a symptom of `flood.syn`.
- **Sample**: `samples/server_down_timeouts.pcap`.

### `tcp.zero_window`: the receiver can't keep up

- **Plain words**: the receiving program told the sender to stop because its buffer is full. The network is fine; the application is the bottleneck.
- **Signals**: advertised window = 0 (after scaling) outside of RST/FIN; window probes; duration of the stall.
- **Threshold**: per receiver: zero-window events, total stall time and longest stall. <!-- VERIFY: cut-offs -->
- **Discriminators**: fault, blamed on the **client/receiver** side.
- **Sample**: `samples/zero_window.pcap`.

## Latency (`faultline/detectors/latency.py`) <!-- VERIFY: module landed after this section was written; check the thresholds below against its constants -->

### `latency.high_rtt`: the network round trip is slow

- **Plain words**: every request waits a long time just to travel there and back.
- **Signals**: SYN → SYN/ACK time (far side), SYN/ACK → ACK time (near side), TCP timestamp echo RTT samples; median and p95 per destination.
- **Threshold**: median handshake RTT ≥ 200 ms (medium), ≥ 500 ms (high), over ≥ 5 handshakes to the same destination. <!-- VERIFY -->
- **Blame split**: near-side vs far-side share of the RTT tells whether the slow half is the local link (Wi-Fi) or the WAN.
- **Discriminators**: fault. Becomes a symptom under `flood.*`, `arp.unanswered` (gateway), `icmp.routing_loop`, `flood.broadcast`.
- **Sample**: `samples/high_latency.pcap`.

### `latency.slow_server`: the application is slow, not the network

- **Plain words**: the network delivers quickly; the server takes ages to think.
- **Signals**: time from the last byte of a client request to the first byte of the server response, minus the measured RTT; per server:port medians.
- **Threshold**: median server time ≥ 1 s over ≥ 5 exchanges, with RTT < 25 % of that time (otherwise the finding is `latency.high_rtt`). <!-- VERIFY -->
- **Discriminators**: fault (server overload, slow backend). Symptom under `flood.syn` / `flood.icmp` / `mtu.*`.
- **Sample**: `samples/slow_server.pcap`.

## MTU (`faultline/detectors/mtu.py`) <!-- VERIFY: module landed after this section was written; check the thresholds below against its constants -->

### `mtu.frag_needed`: a link on the path can't take large packets

- **Plain words**: a router said "too big" and asked the sender to use smaller packets. Normally harmless if the sender listens.
- **Signals**: ICMP type 3 code 4 (IPv4) / ICMPv6 type 2 (Packet Too Big), with the advertised next-hop MTU and the quoted inner header.
- **Threshold**: ≥ 3 such messages; severity low unless the sender keeps sending the same large size afterwards (then medium). <!-- VERIFY -->
- **Discriminators**: misconfig (tunnel/VPN MTU, PPPoE). Attack indicators: none by default.
- **Sample**: `samples/mtu_frag_needed.pcap`.

### `mtu.blackhole`: large packets vanish silently (PMTUD black hole)

- **Plain words**: big packets disappear and nobody says why, so connections hang right after the handshake. Classic VPN symptom.
- **Signals**: segments ≥ ~1400 bytes with DF set are retransmitted repeatedly while small segments in the same flow get ACKed; no ICMP frag-needed is seen; MSS in the SYN larger than the path tolerates.
- **Threshold**: ≥ 2 flows showing ≥ 3 large-segment retransmissions with small segments succeeding. <!-- VERIFY -->
- **Discriminators**: fault/misconfig (ICMP blocked by a firewall, tunnel MTU). Root of `tcp.retransmissions`, `tcp.resets`, `tls.failure`, `latency.slow_server` in correlation.
- **Sample**: `samples/mtu_blackhole.pcap`.

## ARP (`faultline/detectors/arp.py`)

Constants: `SOLICIT_WINDOW` 5 s (a reply within 5 s of a matching request counts as solicited), `SCAN_WINDOW` 60 s, `SCAN_MIN` 30, `UNANSWERED_MIN` 3, `UNANSWERED_SPAN` 2 s, `STORM_RATE` 200 frames/s, `STORM_SECONDS` 3. All per-key tables are `BoundedDict`s (≤ 65,536 IPs/MACs).

### `arp.duplicate_ip`: two devices claim one IP address (conflict **or** spoofing)

This is the showcase finding for the hypothesis engine. The same observation ("IP X is announced by MAC A and MAC B") carries two variants.

- **Plain words (fault variant, "Duplicate IP address")**: two devices were given the same address, like two houses with the same street number. Both lose mail.
- **Plain words (attack variant, "ARP spoofing")**: a device is lying about who owns the router's address so that your traffic goes through it first.
- **Signals**: ARP sender fields (`spa`, `sha`) per IP from `HostTable.arp_claims`; gratuitous ARP; RFC 5227 probes; reply rate; whether replies were solicited; how many IPs each MAC claims; whether the IP is the inferred gateway; whether both MACs stay active.
- **Threshold**: two or more MACs claiming the same IP in ARP (or sourcing L3 traffic from it), excluding the zero/broadcast MAC and VRRP/HSRP/GLBP virtual MAC prefixes.
- **Discriminators** (indicator texts paraphrased from the code; attack = A, misconfig = M):

  | Indicator | Supports | Weight |
  |---|---|---|
  | The disputed address belongs to the router (default gateway) | A | 2.0 |
  | The disputed address is a server on this network (DNS/DHCP) | A | 1.0 |
  | The suspicious MAC sent N ARP replies nobody asked for | A | scaled by count |
  | Those replies repeat like clockwork every ~x s (poisoning tool keep-alive) | A | — |
  | The suspicious MAC answered ARP for several IPs that belong to other devices | A | — |
  | The suspicious MAC also uses its own, different address (two identities) | A | — |
  | The owner of the IP flipped between the two MACs N times while the original stayed alive | A | — |
  | Packets meant for internet addresses were sent to the suspicious MAC / it is relaying internet traffic | A | — |
  | The disputed address is not the router's | M | 1.0 |
  | The suspicious MAC only answered when asked (no unsolicited replies) | M | 1.0 |
  | The suspicious MAC claims only this one address | M | 1.0 |
  | Both MACs were stable; the owner changed only rarely | M | 0.5 |
  | A device probed the address first (RFC 5227 duplicate-address check) | M | — |
  | The newcomer announced itself once with a gratuitous ARP, like a device joining | M | — |
  | Both MACs send their own normal traffic from the IP: two real devices think it is theirs | M | — |
  | Both MACs answered the same ARP question | M | — |
  | Low ARP rate from the newcomer | M | 0.5 |
  | The two MACs are consecutive addresses from the same manufacturer | M | — |
  | A router-redundancy virtual MAC (VRRP/HSRP/GLBP) is involved | M | — |

  <!-- VERIFY: fill the "—" weights from detectors/arp.py lines ~676–730 -->

- **MITRE**: T1557.002 (Adversary-in-the-Middle: ARP Cache Poisoning).
- **Samples**: `samples/ip_conflict.pcap` (fault), `samples/arp_spoofing.pcap` (attack).

### `arp.scan`: one device is asking for every address

- **Plain words**: someone is knocking on every door in the building to see who is home.
- **Signals**: distinct target IPs in ARP requests per sender MAC within a sliding window; sequential targets.
- **Threshold**: ≥ `max(8, 30 × scale)` distinct target IPs within 60 s from one sender.
- **Discriminators**: attack indicators: N different addresses within x s (weight 2.0, 2.5 when ≥ 2× threshold); addresses tried in order like a sweep (1.0); most asked addresses don't exist (probing); very fast (0.5). Misconfig indicators: the sender is network infrastructure (router/DHCP server) which ARPs many hosts (1.5); slow and mostly aimed at existing devices, like an inventory tool (1.5).
- **MITRE**: T1018 (Remote System Discovery) / T1046.
- **Sample**: `samples/arp_scan.pcap`.

### `arp.unanswered`: a device (often the router) never answers

- **Plain words**: everyone is asking "where is the router?" and nobody replies. The router is off, unplugged or on the wrong VLAN.
- **Signals**: requests for an IP with no reply from that IP within the capture, from ≥ N distinct requesters; extra weight if the IP is the gateway.
- **Threshold**: ≥ 3 unanswered requests for one IP spanning ≥ 2 s.
- **Discriminators**: fault indicators: N requests over x s got no answer (1.5); the IP was answering until a time and then went silent (2.0); several devices are trying to reach it (1.0). Softer reading when the IP never answered and only one device asks (probably a stale/wrong address). Root cause for `dns.timeout`, `tcp.syn_timeout`, `icmp.unreachable`, `latency.high_rtt` (rule `gateway-down`).
- **Sample**: `samples/server_down_timeouts.pcap`.

### `arp.storm`: abnormal ARP flood

- **Plain words**: the network is being swamped with ARP frames, usually a switching loop, sometimes a crafted flood.
- **Signals**: ARP frames per second above `200 × scale` for 3 consecutive seconds; share of exact-repeat frames; number of sending MACs.
- **Discriminators**: fault when most frames are exact repeats (switching loop, 2.0) and come from many devices (1.0); attack when most of the flood comes from one MAC (1.5) and the frames are all different, i.e. crafted (1.0). MITRE (attack): T1498 Network Denial of Service.
- **Sample**: none dedicated. <!-- VERIFY: add samples/arp_storm.pcap or remove -->

## DHCP (`faultline/detectors/dhcp.py`) <!-- VERIFY: module landed after this section was written; check the thresholds below against its constants -->

### `dhcp.multiple_servers`: more than one DHCP server is answering (rogue **or** misconfigured)

- **Plain words (misconfig variant)**: a second router someone plugged in is also handing out addresses; devices get inconsistent settings.
- **Plain words (attack variant, "Rogue DHCP server")**: an unauthorised server is handing out settings that route your traffic through an attacker.
- **Signals**: distinct `server_id`s sending OFFER/ACK; the router and DNS options each offers; lease times; who appeared first; whether the advertised DNS/router is a regular LAN host; whether the subsequent DNS traffic is hijacked.
- **Threshold**: ≥ 2 server IDs each with ≥ 1 OFFER/ACK. <!-- VERIFY -->
- **Discriminators**:

  | Indicator | Supports | Weight |
  |---|---|---|
  | Second server offers a **different** router or DNS | attack | 2 |
  | The offered router/DNS is a LAN host that is not the inferred gateway | attack | 3 |
  | Second server appeared mid-capture / shorter lease to win renewals | attack | 1 |
  | Hijacked DNS answers come from the offered DNS | attack | 2 (and chain) |
  | Both servers offer the same router and DNS | misconfig | 2 |
  | Second server offers itself as router and public DNS (home router) | misconfig | 1 |

- **MITRE**: T1557 (Adversary-in-the-Middle) / T1565.002.
- **Samples**: `samples/dhcp_misconfig_two_routers.pcap` (misconfig), `samples/mitm_rogue_dhcp.pcap` (attack, chained to `dns.hijack`).

### `dhcp.no_server`: nobody is handing out addresses

- **Plain words**: devices ask for an address and nothing answers, so they fall back to 169.254.x.x and can't reach anything.
- **Signals**: DISCOVER / REQUEST with no OFFER / ACK for the same `xid` or client MAC; repeated DISCOVERs; link-local addresses appearing afterwards.
- **Threshold**: ≥ 3 clients or ≥ 6 DISCOVERs unanswered. <!-- VERIFY -->
- **Discriminators**: fault. Root cause rule `no-dhcp`.
- **Sample**: `samples/dhcp_no_server.pcap`.

### `dhcp.nak`: the server keeps rejecting devices

- **Plain words**: devices ask to keep their address and the server says no, over and over.
- **Signals**: NAK count per server and per client; NAKs following REQUESTs for addresses outside the server's pool.
- **Threshold**: ≥ 5 NAKs, or ≥ 3 for one client. <!-- VERIFY -->
- **Discriminators**: misconfig (pool/subnet mismatch, stale leases, two servers). Symptom of `dhcp.multiple_servers` when that is misconfig.
- **Sample**: `samples/dhcp_misconfig_two_routers.pcap`.

### `dhcp.starvation`: someone is grabbing every address

- **Plain words**: a flood of fake devices requests addresses until the pool is empty, so real devices get nothing. Usually a prelude to a rogue DHCP server.
- **Signals**: DISCOVER/REQUEST from a very large number of distinct client MACs in a short window, often with random vendor prefixes and sequential `xid`s.
- **Threshold**: ≥ 50 distinct client MACs within 60 s (scaled). <!-- VERIFY -->
- **Discriminators**: attack.
- **MITRE**: T1498 (Network Denial of Service) / T1557.
- **Sample**: `samples/dhcp_starvation.pcap`.

## DNS (`faultline/detectors/dns.py`) <!-- VERIFY: module landed after this section was written; check the thresholds below against its constants -->

Queries and responses are matched by (client, server, transaction ID, qname).

### `dns.timeout`: name lookups get no answer

- **Plain words**: the device asks "what is the address of example.com?" and nobody answers, so every website looks down.
- **Signals**: queries with no response within 2 s; retries of the same query; which resolver is affected.
- **Threshold**: ≥ 5 unanswered queries and ≥ 30 % of queries to that resolver unanswered. <!-- VERIFY -->
- **Discriminators**: fault. Root of `dns.slow`, `dns.errors` (rule `dns-down`); symptom of `arp.unanswered` / `dhcp.no_server` / `dhcp.multiple_servers` (misconfig) / `icmp.routing_loop` / `flood.broadcast`.
- **Sample**: `samples/dns_failure.pcap`.

### `dns.errors`: the resolver is answering with failures

- **Plain words**: the name server answers, but with "I can't help you" (SERVFAIL / REFUSED).
- **Signals**: rcode 2 (SERVFAIL) and 5 (REFUSED) per resolver.
- **Threshold**: ≥ 5 errors and ≥ 20 % of that resolver's responses. <!-- VERIFY -->
- **Discriminators**: fault (upstream failure) / misconfig (REFUSED from an ACL-restricted resolver).
- **Sample**: `samples/dns_failure.pcap`.

### `dns.nxdomain`: many names don't exist

- **Plain words**: lots of lookups for names that don't exist. A few are normal (typos, browser probes); a burst from one host suggests malware probing or a misconfigured search domain.
- **Signals**: rcode 3 per client; fraction of that client's queries; randomness of the labels.
- **Threshold**: ≥ 20 NXDOMAINs from one client and ≥ 50 % of its queries. <!-- VERIFY -->
- **Discriminators**: misconfig (search domain, stale config) by default; attack indicator when names look random (DGA-like) and query rate is high.
- **MITRE** (attack reading): T1568.002 (Domain Generation Algorithms).
- **Sample**: none dedicated; appears in `busy_office.pcap` at a level below threshold (false-alarm guard). <!-- VERIFY -->

### `dns.slow`: lookups are slow

- **Plain words**: names resolve, but every lookup takes a long time, which makes everything feel slow.
- **Signals**: query → response time per resolver, median and p95.
- **Threshold**: median ≥ 300 ms or p95 ≥ 1 s over ≥ 10 lookups. <!-- VERIFY -->
- **Discriminators**: fault. Symptom of `dns.timeout`.
- **Sample**: part of `samples/dns_failure.pcap`. <!-- VERIFY -->

### `dns.hijack`: someone is answering DNS queries with wrong addresses

- **Plain words**: when a device asks for a website's address, an impostor answers first with the wrong one, sending the device to a fake site.
- **Signals**: two responses to one transaction ID with different answers (race); a response from a server IP the client never queried; a public name resolving to a private or LAN address; the fake answer's TTL far from the real one; answers whose source MAC differs from the resolver's usual MAC; the answering server being the DNS advertised by a rogue DHCP offer.
- **Threshold**: ≥ 2 hijacked transactions, or 1 with ≥ 2 attack indicators. <!-- VERIFY -->
- **Discriminators**:

  | Indicator | Supports | Weight |
  |---|---|---|
  | Two different answers for one query ID | attack | 3 |
  | Answer from a server never queried | attack | 3 |
  | Public name → private/LAN address | attack | 2 |
  | Answer's source MAC ≠ the resolver's MAC | attack | 2 |
  | Answers arrive consistently from the configured resolver, single answer, consistent TTLs | fault | 2 |
  | Split-horizon / captive-portal pattern: *every* name resolves to the same LAN IP from the legitimate resolver | misconfig | 2 |

- **MITRE**: T1557 (Adversary-in-the-Middle) / T1584.002 (DNS Server compromise) / T1565.002.
- **Samples**: `samples/dns_hijack.pcap`, `samples/mitm_rogue_dhcp.pcap`.

### `dns.tunneling`: DNS is being used to smuggle data

- **Plain words**: DNS is meant for small lookups. Here one host is sending hundreds of long, random-looking names, which is how malware hides data transfer inside DNS.
- **Signals**: per client: query rate, mean qname length, label entropy, fraction of TXT/NULL/CNAME queries, number of distinct subdomains under one parent domain, response sizes.
- **Threshold**: ≥ 50 queries to one parent domain with mean label length ≥ 30 and entropy ≥ 3.5 bits/char, or ≥ 20 TXT queries with long labels. <!-- VERIFY -->
- **Discriminators**: attack; misconfig indicator when the domain is a known CDN/anti-spam pattern (long but low-entropy labels). <!-- VERIFY -->
- **MITRE**: T1071.004 (Application Layer Protocol: DNS) / T1048.
- **Sample**: `samples/dns_tunneling.pcap`.

## Scans (`faultline/detectors/scan.py`)

Constants: `WINDOW` 60 s, `PORT_THRESHOLD` 25 distinct ports on one host, `STEALTH_THRESHOLD` 5 FIN/NULL/Xmas probes, `SWEEP_THRESHOLD` 20 distinct hosts on one service. UDP ports are tracked separately from TCP; ICMP echo is tracked as its own "service" for sweeps.

### `scan.port`: one host is probing many ports

- **Plain words**: someone is trying every door on one building to find the unlocked ones.
- **Signals**: distinct destination ports per (source, destination) in a window; SYN-only probes; FIN/NULL/Xmas flag combinations (no legitimate stack sends them); UDP probes answered by ICMP port-unreachable; ratio of answered to unanswered; timing regularity.
- **Threshold**: ≥ 25 distinct ports on one host within 60 s (scaled), or ≥ 5 FIN/NULL/Xmas probes.
- **Discriminators**: attack indicators include probe rate far faster than a person or application, share of probed ports that never answered (filtered/closed), open ports discovered, and "no connection was used to exchange data: nothing here looks like a working application". Benign indicator: an FTP control connection exists between the hosts (passive FTP legitimately opens many ports). Refusals and resets it triggers become symptoms (rule `scan-noise`).
- **MITRE**: T1046 (Network Service Discovery).
- **Samples**: `samples/port_scan_syn.pcap`, `samples/port_scan_xmas.pcap`.

### `scan.host_sweep`: one host is probing many hosts

- **Plain words**: someone is checking every address in the building to see who's home.
- **Signals**: distinct destination IPs from one source via ICMP echo, SYN to a fixed port, or ARP (see `arp.scan`); sequential addresses; low reply ratio.
- **Threshold**: ≥ 20 distinct hosts on one service (or ICMP echo) within 60 s (scaled).
- **Discriminators**: attack indicators: addresses walked in order; most contacted addresses never answered; none of the addresses came from a DNS lookup (no user or app asked for them). Misconfig indicators: most addresses were looked up in DNS first (normal browsing); the source is the router/DHCP server; most hosts answered (inventory/monitoring tool); scattered internet web addresses (also what a browser does). MITRE adds T1046 when more than ping is involved.
- **MITRE**: T1018 (Remote System Discovery).
- **Sample**: `samples/host_sweep.pcap`.

## Floods (`faultline/detectors/flood.py`)

Constants: `SYN_WINDOW` 10 s, `SYN_THRESHOLD` 200 SYNs per window to one service, `LOW_COMPLETION` 0.2, `ICMP_RATE` 100 echo requests/s, `ICMP_SUSTAIN` 3 s, `SMURF_THRESHOLD` 10 broadcast pings in 10 s, `BCAST_RATE` 500 frames/s, `BCAST_FRACTION` 0.30, `LOOP_COPIES` 20, `LOOP_GAP` 0.02 s.

### `flood.syn`: a server is being flooded with connection attempts

- **Plain words**: thousands of half-open connections from fake addresses swamp the server so real users can't connect.
- **Signals**: SYN rate to one destination; fraction of handshakes never completed; number of distinct sources; SYN/ACK retransmissions by the server; absence of SYN retries from the "clients" (real stacks retry).
- **Threshold**: ≥ 200 SYNs to one service within 10 s (scaled); attack-like when the completion ratio is below 0.2.
- **Discriminators**: **attack**: only x % of attempts completed; thousands of distinct sources each sending one SYN and never retrying; all "different" senders share the same TTL (one spoofing machine) or TTLs spread randomly; SYNs from impossible (bogon/LAND) addresses; one source sending most SYNs. **Fault (overload / flash crowd)**: a high share of connections completed and carried requests; SYN retries (real clients wait and retry); varied TTLs and reconnects; the server answered only x % of SYNs (overwhelmed). The fault reading has severity medium and no MITRE technique.
- **MITRE**: T1499.001 (Endpoint DoS: OS Exhaustion Flood).
- **Sample**: `samples/syn_flood.pcap`.

### `flood.icmp`: a host is being flooded with pings

- **Signals**: echo request rate to one destination; distinct sources; reply ratio; oversized echo payloads.
- **Threshold**: ≥ 100 echo requests/s to one target for 3 consecutive seconds (scaled). Two more shapes share the kind: **smurf** (≥ 10 pings to a broadcast address in 10 s; T1498.002 Reflection Amplification) and **ping of death** (ICMP fragments reassembling beyond 65,535 bytes; T1499.004).
- **Discriminators**: attack indicators: distributed sources; oversized pings (≥ 1000 bytes); target answered only x % (overwhelmed). Benign: a single local machine sending normal-sized pings in one or two sessions (same identifier).
- **MITRE**: T1498.001 (Direct Network Flood).
- **Sample**: none dedicated. <!-- VERIFY: add samples/icmp_flood.pcap or remove -->

### `flood.broadcast`: broadcast storm / network loop

- **Plain words**: the network is drowning in broadcast traffic, usually because two switch ports were looped together.
- **Signals**: broadcast/multicast frame rate; the same frame (same source, same IP ID or ARP) seen many times in a short time; TTL/hop count unchanged.
- **Threshold**: broadcast/multicast ≥ 500 frames/s and ≥ 30 % of traffic, or the same broadcast frame seen ≥ 20 times with ~20 ms gaps (loop).
- **Discriminators**: fault (switching loop: looping copies from several devices; or a single broken NIC/driver). Attack variant when most broadcasts come from one device and are crafted (T1498.001). Root of retransmissions, DNS timeouts, high RTT, unanswered ARP, DHCP failure (rule `broadcast-storm`).
- **Sample**: none dedicated. <!-- VERIFY: add samples/broadcast_storm.pcap or remove -->

## ICMP (`faultline/detectors/icmp.py`) <!-- VERIFY: module landed after this section was written; check the thresholds below against its constants -->

### `icmp.unreachable`: routers or hosts report destinations as unreachable

- **Signals**: type 3 codes 0/1 (net/host unreachable), 3 (port), 9/10/13 (administratively filtered); the quoted inner header tells which conversation failed.
- **Threshold**: ≥ 10 messages, grouped by code and by reporting router. <!-- VERIFY -->
- **Discriminators**: fault (routing) / misconfig (firewall filtering) by code. Symptom of scans, routing loops, gateway down, no DHCP.
- **Sample**: appears in `samples/port_scan_syn.pcap` (UDP ports) and `samples/routing_loop.pcap`. <!-- VERIFY -->

### `icmp.routing_loop`: packets are circling between routers

- **Plain words**: packets go round in a circle until they expire, so the destination is never reached.
- **Signals**: ICMP Time Exceeded (type 11 / ICMPv6 type 3) for the same inner destination from the same router(s), repeatedly, outside of a traceroute pattern (traceroute has increasing inner TTLs from one source).
- **Threshold**: ≥ 5 time-exceeded messages for the same destination from ≤ 2 routers. <!-- VERIFY -->
- **Discriminators**: fault (misconfigured static routes).
- **Sample**: `samples/routing_loop.pcap`.

### `icmp.redirect`: a device is telling hosts to use a different router

- **Plain words**: "use this other router instead" messages. Legitimate ones are rare; an attacker uses them to divert traffic.
- **Signals**: ICMP Redirect (type 5 / ICMPv6 type 137); whether the sender is the inferred gateway; the redirect target; the number of hosts targeted.
- **Threshold**: ≥ 2 redirects, or 1 from a non-gateway. <!-- VERIFY -->
- **Discriminators**: attack when the sender is not the gateway or the new gateway is a regular LAN host; misconfig when the real gateway redirects to another known router.
- **MITRE**: T1557 (Adversary-in-the-Middle).
- **Sample**: `samples/icmp_redirect.pcap`.

## Application layer (`faultline/detectors/app.py`) <!-- VERIFY: module NOT landed at time of writing; cred.cleartext / tls.failure / tls.deprecated / http.errors are not emitted by any detector yet. Remove this section and the kinds from README if it does not ship -->

### `cred.cleartext`: passwords are crossing the network unencrypted

- **Plain words**: someone logged in over a protocol that sends the password in plain text. Anyone on the network path can read it. **Faultline reports the protocol and the hosts only; it never stores or shows the credential.**
- **Signals**: `Packet.cred` set by the decoder (`capture/decode.py`) to one of `FTP`, `POP3`, `IMAP`, `SMTP AUTH`, `Telnet`, `HTTP Basic`; the decoder never copies the secret.
- **Threshold**: 1 occurrence.
- **Discriminators**: misconfig (legacy service) by default; the finding is a symptom of a MITM incident when one exists (rule `mitm`).
- **MITRE**: T1040 (Network Sniffing) as the exposure; T1552 (Unsecured Credentials).
- **Sample**: `samples/cleartext_creds.pcap`.

### `tls.failure`: secure connections are failing

- **Signals**: cleartext TLS alerts (handshake_failure, bad_certificate, unknown_ca, protocol_version); handshakes that end in RST right after ClientHello.
- **Threshold**: ≥ 3 failed handshakes to one server, or any `unknown_ca`/`bad_certificate` alert cluster. <!-- VERIFY -->
- **Discriminators**: fault/misconfig (expired certificate, version mismatch, SNI/vhost) by default; attack indicator when `bad_certificate`/`unknown_ca` alerts coincide with ARP spoofing or DNS hijack (interception with a fake certificate), handled via rule `mitm`.
- **Sample**: `samples/tls_deprecated.pcap`. <!-- VERIFY -->

### `tls.deprecated`: outdated encryption is in use

- **Signals**: ClientHello/ServerHello negotiating SSL 3.0, TLS 1.0 or TLS 1.1 (via `supported_versions` or record/handshake version).
- **Threshold**: 1 handshake (low), ≥ 5 (medium). <!-- VERIFY -->
- **Discriminators**: misconfig.
- **Sample**: `samples/tls_deprecated.pcap`.

### `http.errors`: web servers are returning errors

- **Signals**: HTTP/1.x status 5xx (server) and 4xx bursts per server; the path (query string stripped) and method.
- **Threshold**: ≥ 5 5xx or ≥ 20 4xx from one server, and ≥ 10 % of its responses. <!-- VERIFY -->
- **Discriminators**: fault (5xx) / misconfig (4xx, e.g. broken links, auth). Symptom of `flood.syn`.
- **Sample**: none dedicated. <!-- VERIFY: add samples/http_errors.pcap or remove -->

---

## Correlation rules (`faultline/correlate.py`)

How findings are chained into incidents. A root explains its consequences; consequences are shown as symptoms with "fixing that should fix this too". `overlap` means the consequence must share a host with the root.

| Rule | Root kinds (category) | Consequence kinds | Incident title | Overlap |
|---|---|---|---|---|
| `mitm` | `dhcp.multiple_servers`, `arp.duplicate_ip`, `icmp.redirect` (attack) | `dns.hijack`, `cred.cleartext`, `tls.failure`, `dns.timeout`, `tcp.resets`, `arp.duplicate_ip` | Man-in-the-middle attack | no |
| `rogue-router` | `dhcp.multiple_servers` (misconfig) | `dns.timeout`, `dns.errors`, `tcp.syn_timeout`, `arp.unanswered`, `icmp.unreachable`, `dhcp.nak` | A second router is breaking connectivity | no |
| `no-dhcp` | `dhcp.no_server` | `dns.timeout`, `tcp.syn_timeout`, `arp.unanswered`, `icmp.unreachable` | Devices can't get a network address | no |
| `gateway-down` | `arp.unanswered` | `dns.timeout`, `tcp.syn_timeout`, `icmp.unreachable`, `latency.high_rtt` | The router stopped responding | yes |
| `scan-noise` | `scan.port`, `scan.host_sweep`, `arp.scan` (attack) | `tcp.refused`, `tcp.resets`, `icmp.unreachable`, `arp.unanswered`, `tcp.syn_timeout` | Reconnaissance scan | yes |
| `flood` | `flood.syn`, `flood.icmp` | `tcp.syn_timeout`, `latency.slow_server`, `latency.high_rtt`, `tcp.retransmissions`, `tcp.resets`, `http.errors` | Denial-of-service attack | yes |
| `mtu` | `mtu.blackhole`, `mtu.frag_needed` | `tcp.retransmissions`, `tcp.resets`, `tls.failure`, `latency.slow_server` | Packet-size (MTU) problem | yes |
| `routing-loop` | `icmp.routing_loop` | `icmp.unreachable`, `tcp.syn_timeout`, `dns.timeout`, `latency.high_rtt` | Routing loop | yes |
| `dns-down` | `dns.timeout` | `dns.slow`, `dns.errors` | DNS outage | no |
| `broadcast-storm` | `flood.broadcast` | `tcp.retransmissions`, `dns.timeout`, `latency.high_rtt`, `arp.unanswered`, `dhcp.no_server` | Network loop / broadcast storm | no |

Incident category is *attack* if any member is an attack, otherwise the root's category. The incident's "fix this first" is the root finding's first three fix steps.

## Verdict and score (`faultline/verdict.py`, `faultline/correlate.py`)

- Hypothesis score = 0.5 prior for the detector's default + Σ indicator weights (each clamped to 3). Winner = highest; ties go to the default. Confidence = softmax over the candidate hypotheses, clamped to [0.5, 0.99]. An attack reading with confidence < 0.6 is shown one severity step softer.
- Health score = 100 − Σ penalty(severity) × max(0.5, confidence), with penalty 0 / 3 / 9 / 18 / 30 for info / low / medium / high / critical, and symptoms counted at 40 %. Clamped to 0..100.
- Overall status: **under_attack** if any attack finding has severity ≥ medium and confidence ≥ 0.6; else **faulty** if any fault/misconfig has severity ≥ medium; else **minor_issues** if anything has severity ≥ low; else **healthy**.
