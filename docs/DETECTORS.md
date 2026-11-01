# Detector catalogue

Every finding Faultline can raise, what it means in plain words, the signals and thresholds behind it, how the fault / misconfiguration / attack reading is decided, the MITRE ATT&CK technique for attacks, and the sample capture that demonstrates it. Everything below was checked against the code as shipped; sample names are those in `samples/labels.json`. Detectors without a dedicated sample are exercised by the unit tests named.

Conventions:

- **Kind** is the stable identifier in JSON output (`finding.kind`).
- **Default reading** is the detector's own hint; the verdict engine (`faultline/verdict.py`) can overrule it using the indicators listed under *Discriminators*. Weights are 0.5 (weak hint) to 3 (near conclusive).
- Count thresholds are multiplied by the sensitivity scale (`low` ×1.6, `normal` ×1.0, `high` ×0.6; `faultline/context.py`, `Config.scale`). Most detectors also apply a floor so `high` never drops a threshold below a sane minimum. Thresholds below are quoted at `normal`.
- Evidence per finding: up to 200 frame numbers plus a total count (`Evidence.CAP`), evidence lines for the first 40 frames (`MAX_EVIDENCE_LINES`), and an evidence pcap of up to 150 frames (`MAX_EVIDENCE_PCAP_PACKETS`), with all evidence pcaps capped at 8 MiB in total (`faultline/engine.py`).
- Severity: 0 info, 1 low, 2 medium, 3 high, 4 critical. Only severity ≥ 2 affects the overall verdict and `--fail-on`.

---

## TCP (`faultline/detectors/tcp.py`)

A per-flow state tracker keyed on the 4-tuple (bounded to 200,000 flows, 32 sequence holes per flow, 50,000 services). It follows sequence numbers, ACKs, SACK blocks and window sizes to tell apart loss, refusal, dead peers and stuck receivers.

### `tcp.retransmissions`: packets are being lost and resent

- **Plain words**: data had to be sent twice because the first copy never arrived. A little is normal; a lot means a bad link.
- **Signals**: a segment whose sequence range was already seen (retransmission); three duplicate ACKs for the same sequence (fast retransmit); a receiver ACK/SACK referring to data the capture never saw (lost before the capture point).
- **Threshold**: rate-based. Fires when retransmitted data segments are ≥ 2 % of all data segments *and* at least 10 (scaled) in number, or when one connection alone has ≥ 8 (scaled) retransmissions at a rate ≥ 5 %. Severity: medium below 5 %, high at ≥ 5 %, critical at ≥ 15 % (capped at high when confined to one connection).
- **Loss localisation**: original *and* retransmission seen → lost **after the capture point** (`loss_server_side`). A retransmission that fills a sequence hole late, i.e. the original never passed us → lost **before the capture point** (`loss_client_side`). When ≥ 3 losses could be located and ≥ 70 % fall on one side, the finding names that side and the fix steps differ (`mtr` beyond the capture point vs. check the local link/Wi-Fi); otherwise it says "both sides of this capture point".
- **Indicators** (all fault): loss rate across N connections (2.0 at ≥ 5 %, else 1.5); normal fast/timeout recovery behaviour (1.0); duplicate ACK count (0.5); "loss affects connections to many unrelated servers: a shared link problem" (1.0, when ≥ 3 servers); "no sign of deliberate interference" (0.5).
- **Discriminators**: fault only. Becomes a symptom of `flood.*`, `mtu.*` or `flood.broadcast` through correlation, not here.
- **Sample**: `samples/lossy_link.pcap` (5.0 % loss, spread over both sides of the capture point).

### `tcp.resets`: connections are being torn down abruptly

- **Plain words**: one side slammed the door mid-conversation.
- **Signals**: RST after data has flowed (not a refused handshake), grouped by the host that sent them; RSTs after a FIN or after a long idle close are ignored.
- **Threshold**: ≥ 5 (scaled) aborted established connections, or ≥ 3 (scaled, minimum 2) when that is ≥ 10 % of established connections. Independently, ≥ 2 forged-looking resets, or one with two agreeing forgery signs, trigger the finding.
- **Discriminators**: fault (server/middlebox dropping sessions; "reset after being idle 5+ minutes: firewall/NAT timeout") by default. **Forged-reset indicators (attack)**: the RST's IP TTL differs by 5+ from every other packet of that endpoint; the supposed sender keeps sending normally after "its" reset; the RST sequence number is inside the window but not the expected one. When attack wins: severity high, MITRE T1499 Endpoint Denial of Service.
- **Sample**: none dedicated; covered by unit tests (`tests/test_tcp.py`).

### `tcp.refused`: a service is down or closed

- **Plain words**: clients knock, the server says "nobody here" (RST in reply to SYN).
- **Signals**: SYN → RST/ACK with no SYN/ACK in between, grouped by server IP:port. Sources that the scan tracker flags as scanners are excluded, so a port scan does not produce hundreds of refusals.
- **Threshold**: ≥ 3 (scaled) refused attempts to one server:port from normal clients. Severity medium when ≥ 5 attempts or ≥ 2 clients, else low.
- **Discriminators**: **misconfig** when the service never accepted a connection in the capture ("every attempt refused", 2.0); **fault** when it accepted earlier and then started refusing (crashed, 2.5; severity high) or alternates (restarting/overloaded, 2.0). Refusals arriving with a different IP TTL than the server's own replies mean a middlebox/firewall is answering (misconfig, 1.5). Weak attack indicator (0.5) when ≥ 20 different sources hit the closed port. When *one client* hits *many ports*, this is not reported here; the scan detector owns it and the refusals become symptoms of `scan.port`.
- **Sample**: `samples/connection_refused.pcap` (misconfig: service never listening).

### `tcp.syn_timeout`: connection attempts get no answer

- **Plain words**: the phone rings and rings. The host or the path to it is dead, or a firewall drops silently.
- **Signals**: SYN retransmitted (same seq) with no SYN/ACK or RST ever seen; exponential back-off pattern (1 s, 2 s, 4 s).
- **Threshold**: per service, ≥ 2 (scaled) connection attempts that retried the SYN 2+ times, or ≥ 5 (scaled) unanswered SYNs. Scanner sources are excluded.
- **Discriminators**: fault by default; indicators tell apart "host is up (sent other traffic) but the port never answered" (filtered), "host never sent a single packet" (down/unreachable), "stale address", and "the same service accepted other connections" (overloaded). **Attack variant** when ≥ 20 different sources each send a single never-retried SYN (SYN-flood signature; T1499). If the gateway's ARP is unanswered, becomes a symptom of `arp.unanswered`; if a flood is present, becomes a symptom of `flood.syn`.
- **Sample**: `samples/server_down_timeouts.pcap`.

### `tcp.zero_window`: the receiver can't keep up

- **Plain words**: the receiving program told the sender to stop because its buffer is full. The network is fine; the application is the bottleneck.
- **Signals**: advertised window = 0 (after scaling) outside of RST/FIN; window probes; duration of the stall.
- **Threshold**: ≥ 3 (scaled) zero-window events or ≥ 1 s of total stall. Severity low below 1 s of stall, medium at ≥ 1 s, high at ≥ 5 s.
- **Discriminators**: fault, blamed on the **client/receiver** side ("the receiver itself advertised a zero window N times: it is the bottleneck"; "ordinary flow control from a legitimate endpoint; no attack pattern").
- **Sample**: `samples/zero_window.pcap`.

## Latency (`faultline/detectors/latency.py`)

### `latency.high_rtt`: the network round trip is slow

- **Plain words**: every request waits a long time just to travel there and back.
- **Signals**: SYN → SYN/ACK time (far side) and SYN/ACK → ACK time (near side) per handshake; median, p10 and p90 per destination (up to 2,000 samples each).
- **Threshold**: ≥ 3 (scaled) handshakes to a destination, and then: median ≥ 300 ms; or p90 ≥ 500 ms with at least two and ≥ 20 % of handshakes above 500 ms; or (≥ 5 handshakes) a jittery path with p90 ≥ 200 ms and p90/p10 ≥ 5. Severity: low for a single public server with a steady RTT below 500 ms (distance only); medium when the median is ≥ 500 ms, ≥ 3 servers are affected, the slow half is the client side, or the path is jittery; high when the median is ≥ 1.5 s.
- **Blame split**: the leg that carries ≥ 60 % of the RTT is blamed (server side = WAN/far end, client side = local link/Wi-Fi); otherwise "both".
- **Discriminators**: fault. Becomes a symptom under `flood.*`, `arp.unanswered` (gateway), `icmp.routing_loop`, `flood.broadcast`.
- **Sample**: `samples/high_latency.pcap`.

### `latency.slow_server`: the application is slow, not the network

- **Plain words**: the network delivers quickly; the server takes ages to think.
- **Signals**: time from the client's request to the first byte of the server's response ("think time", capped at 60 s), per server:port, compared with the measured handshake RTT on the same connections.
- **Threshold**: responses are "slow" at ≥ 1 s of think time. A server is reported when it has ≥ 2 slow responses over ≥ 2 connections and either ≥ 3 (scaled) slow responses or ≥ 30 % of its responses slow (non-HTTP ports need ≥ 3). Severity high when the median slow response is ≥ 5 s, or ≥ 50 % are slow with a median ≥ 3 s; else medium.
- **Blame**: "server" when the network RTT is under 300 ms or the think time is more than 3× the RTT; otherwise "server+network". Responses clustering at 5/10/15/20/30 s are called out as back-end timeouts.
- **Discriminators**: fault (server overload, slow backend). Symptom under `flood.syn` / `flood.icmp` / `mtu.*`.
- **Sample**: `samples/slow_server.pcap`.

## MTU (`faultline/detectors/mtu.py`)

### `mtu.frag_needed`: a link on the path can't take large packets

- **Plain words**: a router said "too big" and asked the sender to use smaller packets. Normally harmless if the sender listens.
- **Signals**: ICMP type 3 code 4 (IPv4) / ICMPv6 type 2 (Packet Too Big), with the advertised next-hop MTU and the quoted inner header; whether each quoted flow then adapted its segment size.
- **Threshold**: any router that sent at least one such message is reported (up to five routers). Severity high if a sender kept sending ≥ 2 oversized packets after the warning; low if every flow adapted and there were ≤ 2 messages; else medium.
- **Discriminators**: misconfig only (tunnel/VPN MTU, PPPoE). Indicators: path MTU below 1500 (1.5); the value matches a known tunnel MTU (e.g. 1400 for IPsec/GRE, 1492 for PPPoE); senders that kept sending oversized packets vs. flows that adapted; the reporting router is this network's gateway (0.5); implausibly small MTUs; messages quoting traffic never seen in the capture.
- **Sample**: `samples/mtu_frag_needed.pcap`.

### `mtu.blackhole`: large packets vanish silently (PMTUD black hole)

- **Plain words**: big packets disappear and nobody says why, so connections hang right after the handshake. Classic VPN symptom.
- **Signals**: a DF segment with ≥ 1,200 bytes of payload (`BIG`) is sent ≥ 4 times and never acknowledged, nothing that large was ever acknowledged on that flow direction, and no ICMP "fragmentation needed" arrived for it; whether the sender later re-sent the same data in smaller segments that got through; whether small segments on the same connection were acknowledged; whether the receiver is still alive.
- **Threshold**: one flow direction is enough when the evidence is conclusive (smaller re-segmentation got through, or small data was acknowledged while the receiver stayed active); otherwise ≥ 3 (scaled) weaker flow directions, or 2 with a receiver proven alive.
- **Discriminators**: misconfig (ICMP blocked by a firewall, tunnel MTU). Root of `tcp.retransmissions`, `tcp.resets`, `tls.failure`, `latency.slow_server` in correlation.
- **Sample**: `samples/mtu_blackhole.pcap`.

## ARP (`faultline/detectors/arp.py`)

Constants: `SOLICIT_WINDOW` 5 s (a reply within 5 s of a matching request counts as solicited), `SCAN_WINDOW` 60 s, `SCAN_MIN` 30, `UNANSWERED_MIN` 3, `UNANSWERED_SPAN` 2 s, `STORM_RATE` 200 frames/s, `STORM_SECONDS` 3. All per-key tables are `BoundedDict`s (65,536 entries for the IP, MAC-claim and L3 tables; 2,048 to 100,000 for the others).

### `arp.duplicate_ip`: two devices claim one IP address (conflict **or** spoofing)

This is the showcase finding for the hypothesis engine. The same observation ("IP X is announced by MAC A and MAC B") carries two variants.

- **Plain words (misconfig variant, "Two devices are using the same IP address")**: two devices were given the same address, like two houses with the same street number. Both lose mail.
- **Plain words (attack variant, "Someone is impersonating X (ARP spoofing / man-in-the-middle)")**: a device is lying about who owns the router's address so that your traffic goes through it first.
- **Signals**: ARP sender fields (`spa`, `sha`) per IP from `HostTable.arp_claims`; gratuitous ARP; RFC 5227 probes; reply rate; whether replies were solicited; how many IPs each MAC claims; whether the IP is the inferred gateway; whether both MACs stay active; whether internet-bound frames are sent to the suspicious MAC.
- **Threshold**: two or more MACs claiming the same IP in ARP (or sourcing L3 traffic from it), excluding the zero/broadcast MAC and VRRP/HSRP/GLBP virtual MAC prefixes.
- **Discriminators** (indicator texts paraphrased from the code; attack = A, misconfig = M):

  | Indicator | Supports | Weight |
  |---|---|---|
  | The disputed address belongs to the router (default gateway) | A | 2.0 |
  | The disputed address is a server on this network (DNS/DHCP) | A | 1.0 |
  | The suspicious MAC sent N (≥ 3) ARP replies nobody asked for | A | 1.5 (2.0 when ≥ 10) |
  | Those replies repeat like clockwork every ~x s (poisoning tool keep-alive) | A | 1.0 |
  | The suspicious MAC answered ARP for several IPs that belong to other devices | A | 2.5 |
  | The suspicious MAC also uses its own, different address (two identities) | A | 1.0 |
  | The owner of the IP flipped between the two MACs ≥ 4 times while the original stayed alive | A | 1.0 |
  | ≥ 5 packets meant for internet addresses were sent to the suspicious MAC instead of the router | A | 2.0 |
  | The suspicious device is relaying internet traffic (≥ 5 frames) | A | 1.0 |
  | The disputed address is not the router's | M | 1.0 |
  | The suspicious MAC only answered when asked (no unsolicited replies) | M | 1.0 |
  | The suspicious MAC claims only this one address | M | 1.0 |
  | Both MACs were stable; the owner changed only rarely (≤ 2 transitions) | M | 0.5 |
  | A device probed the address first (RFC 5227 duplicate-address check) | M | 1.5 |
  | The newcomer announced itself once with a gratuitous ARP, like a device joining | M | 0.5 |
  | Both MACs send their own normal traffic from the IP: two real devices think it is theirs | M | 1.5 |
  | Both MACs answered the same ARP question | M | 1.0 |
  | Low ARP rate from the newcomer (≤ 6 per minute) | M | 0.5 |
  | The two MACs are consecutive addresses from the same manufacturer | M | 2.0 |
  | A router-redundancy virtual MAC (VRRP/HSRP/GLBP) is involved | M | 2.0 |

- **MITRE**: T1557.002 (Adversary-in-the-Middle: ARP Cache Poisoning).
- **Samples**: `samples/ip_conflict.pcap` (misconfig), `samples/arp_spoofing.pcap` (attack).

### `arp.scan`: one device is asking for every address

- **Plain words**: someone is knocking on every door in the building to see who is home.
- **Signals**: distinct target IPs in ARP requests per sender MAC within a sliding window; sequential targets; share of targets that answered.
- **Threshold**: ≥ `max(8, 30 × scale)` distinct target IPs within 60 s from one sender.
- **Discriminators**: attack indicators: N different addresses within x s (2.0, 2.5 when ≥ 2× threshold); addresses tried in order like a sweep (1.0); most asked addresses don't exist (probing); very fast (0.5). Misconfig indicators: the sender is network infrastructure (router/DHCP server) which ARPs many hosts (1.5); slow and mostly aimed at existing devices, like an inventory tool (1.5).
- **MITRE**: T1018 (Remote System Discovery).
- **Sample**: `samples/host_sweep.pcap` (an ARP sweep of .1–.254 followed by pings and port-445 checks; the label expects `arp.scan`).

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
- **Sample**: none dedicated; covered by unit tests (`tests/test_arp.py`).

## DHCP (`faultline/detectors/dhcp.py`)

### `dhcp.multiple_servers`: more than one DHCP server is answering (rogue **or** misconfigured)

- **Plain words (misconfig variant, "A second router is handing out addresses")**: a second router someone plugged in is also handing out addresses; devices get inconsistent settings.
- **Plain words (attack variant, "Rogue DHCP server on the network")**: an unauthorised server is handing out settings that route your traffic through an attacker.
- **Signals**: distinct server IDs sending OFFER/ACK; the subnet, router and DNS options each offers; who answered first in contested races; which clients accepted which leases; whether clients then used the offered DNS; whether internet-bound frames were then sent to the second server's MAC.
- **Threshold**: ≥ 2 servers each with ≥ 1 OFFER/ACK. The "legitimate" server is the one whose MAC forwards internet traffic, whose router option is owned by such a MAC, with the most ACKs and seen first. Pairs that hand out identical settings on the same subnet (failover) or share a MAC are ignored. Up to three extra servers are reported.
- **Discriminators**:

  | Indicator | Supports | Weight |
  |---|---|---|
  | Hands out addresses in the same subnet as the real server, so its leases look normal | attack | 1.5 |
  | Names **itself** as the router instead of the real gateway | attack | 2.5 |
  | Names another local device as the router instead of the real gateway | attack | 2.0 |
  | Points clients' DNS at a local device instead of the normal resolver | attack | 2.0 |
  | Answered first in most races with the real server | attack | 1.5 |
  | Clients accepted its leases | attack | 0.5 |
  | Clients then used it as their DNS server | attack | 1.5 |
  | Packets for the internet were then sent to its MAC as if it were the router | attack | 1.5 |
  | Offers a **different subnet**, like a second home router plugged in by mistake | misconfig | 2.0 |
  | Names itself as the router, as a home router does for its own network | misconfig | 1.0 |
  | Also acts as its own DNS server, normal for a consumer router | misconfig | 0.5 |
  | Hands out public DNS (8.8.8.8, 1.1.1.1 …), typical of a factory-default router | misconfig | 1.0 |
  | (different subnet) points DNS at another local device | attack | 1.0 |

- **MITRE**: T1557.003 (Adversary-in-the-Middle: DHCP Spoofing).
- **Samples**: `samples/dhcp_misconfig_two_routers.pcap` (misconfig), `samples/rogue_dhcp.pcap` (attack), `samples/mitm_chain.pcap` (attack, chained to `dns.hijack` and `cred.cleartext`).

### `dhcp.no_server`: nobody is handing out addresses

- **Plain words**: devices ask for an address and nothing answers, so they fall back to 169.254.x.x and can't reach anything.
- **Signals**: DISCOVER / REQUEST with no OFFER / ACK for the client; repeated DISCOVERs with back-off; 169.254.x.x (APIPA) addresses appearing afterwards.
- **Threshold**: ≥ 3 unanswered requests spanning ≥ 4 s, with at least one client that asked 3+ times or waited ≥ 4 s. Severity high when ≥ 2 devices are stuck or ≥ 10 requests went unanswered, else medium.
- **Discriminators**: fault ("no DHCP server answered anyone during the whole capture", 2.0; "a server did answer others but not these devices"; "N devices gave up and used a 169.254.x.x emergency address", 1.5). An attack variant (T1557.003) exists for the case where a DHCP starvation flood was seen at the same time (1.5). Root cause rule `no-dhcp`.
- **Sample**: `samples/dhcp_no_server.pcap`.

### `dhcp.nak`: the server keeps rejecting devices

- **Plain words**: devices ask to keep their address and the server says no, over and over.
- **Signals**: NAK count per server and per client; NAKs following REQUESTs for addresses from another subnet; one server NAKing leases another server handed out; a server that only ever sends NAKs; whether each rejected client got a new address right after.
- **Threshold**: ≥ 2 NAKs. Severity low when every client recovered, there were ≤ 3 NAKs and no two servers are fighting; else medium.
- **Discriminators**: misconfig (pool/subnet mismatch, stale leases, two servers) by default; an attack variant (forged NAKs from a device that never hands out addresses, T1557.003) exists. Symptom of `dhcp.multiple_servers` when that is misconfig.
- **Sample**: none dedicated; covered by unit tests (`tests/test_dhcp.py`).

### `dhcp.starvation`: someone is grabbing every address

- **Plain words**: a flood of fake devices requests addresses until the pool is empty, so real devices get nothing. Usually a prelude to a rogue DHCP server.
- **Signals**: DISCOVER/REQUEST from a very large number of distinct client MACs in a 60 s window; client-MAC field differing from the Ethernet source; impossible (multicast-bit) MACs; requests without hostnames that never complete; request rate.
- **Threshold**: ≥ `max(10, 30 × scale)` distinct client MACs within 60 s, plus at least two of: ≥ 50 % of requests claim a MAC different from the sending Ethernet address, ≥ 10 % impossible MACs, ≥ 80 % without hostname and ≥ 80 % never completing, ≥ 5 new MACs per second, peak ≥ 100 × scale MACs.
- **Discriminators**: attack by default (2.0 for the burst itself plus the signals above); fault indicator when most requests carry normal device names, like many real devices booting at once (1.5).
- **MITRE**: T1557.003 (DHCP Spoofing).
- **Sample**: none dedicated; covered by unit tests (`tests/test_dhcp.py`).

## DNS (`faultline/detectors/dns.py`)

Queries and responses are matched by (client IP, client port, server IP, transaction ID). A query is unanswered after `TIMEOUT` = 3 s; answered queries are kept 10 s longer to catch racing duplicate answers.

### `dns.timeout`: name lookups get no answer

- **Plain words**: the device asks "what is the address of example.com?" and nobody answers, so every website looks down.
- **Signals**: queries with no response within 3 s; retries of the same query; which resolver is affected; whether that resolver ever answered.
- **Threshold**: ≥ 3 unanswered queries and either ≥ 5 (scaled) unanswered or ≥ 20 % of all queries unanswered. Severity high at ≥ 50 % unanswered, medium at ≥ 20 %, else low.
- **Discriminators**: fault by default ("N lookups out of M got no answer within 3 s", 1.5; "the server answered normally until hh:mm:ss and then stopped", 2.0; "devices retried N lookups", 0.5). Misconfig indicators when the configured server never sent a packet or never answered while other servers did (wrong DNS setting). Root of `dns.slow`, `dns.errors` (rule `dns-down`); symptom of `arp.unanswered` / `dhcp.no_server` / `dhcp.multiple_servers` (misconfig) / `icmp.routing_loop` / `flood.broadcast`.
- **Sample**: `samples/dns_failure.pcap`.

### `dns.errors`: the resolver is answering with failures

- **Plain words**: the name server answers, but with "I can't help you" (SERVFAIL / REFUSED).
- **Signals**: rcode 1 (FORMERR), 2 (SERVFAIL), 4 (NOTIMP) and 5 (REFUSED) per resolver and per domain.
- **Threshold**: ≥ 3 errors and ≥ 5 % of all responses. Severity low when ≥ 80 % of the errors concern one or two domains (that domain's own DNS is broken), otherwise high at ≥ 50 % of responses, medium at ≥ 20 %, else low.
- **Discriminators**: fault (SERVFAIL: resolver can't reach upstream, 2.0; FORMERR: something mangles DNS packets, 1.0) / misconfig (≥ 50 % REFUSED: the server won't serve these devices, ACL).
- **Sample**: `samples/dns_failure.pcap`.

### `dns.nxdomain`: many names don't exist

- **Plain words**: lots of lookups for names that don't exist. A few are normal (typos, browser probes); a burst of random-looking names suggests malware probing; a repeating suffix suggests a misconfigured search domain.
- **Signals**: rcode 3 per client; fraction of all responses; randomness of the labels (entropy, vowel ratio, digit mix); shared suffixes; single-word names.
- **Threshold**: ≥ 20 (scaled) NXDOMAIN responses and ≥ 30 % of all responses. Severity low below 60 %, medium above.
- **Discriminators**: misconfig by default (search-domain suffix, a device repeating the same few stale names, single-word names leaking to DNS, "names look human-made"); attack indicators when ≥ 5 random-looking domains fail (1.0, stronger at ≥ 10 and ≥ 50 %) and most come from one device (0.5).
- **MITRE** (attack reading): T1568.002 (Dynamic Resolution: Domain Generation Algorithms).
- **Sample**: none dedicated; covered by unit tests (`tests/test_dns.py`). `samples/busy_but_healthy.pcap` contains a typo'd domain below threshold as a false-alarm guard.

### `dns.slow`: lookups are slow

- **Plain words**: names resolve, but every lookup takes a long time, which makes everything feel slow.
- **Signals**: query → response time per resolver; median; answers over 1 s; answers arriving after the 3 s timeout.
- **Threshold**: per resolver, ≥ 5 answers with a median ≥ 300 ms, or ≥ 3 answers slower than 1 s. Severity medium when the median is ≥ 500 ms or ≥ 10 answers were slow, else low.
- **Discriminators**: fault (plus "another DNS server on this network answers in x ms" when one exists). Symptom of `dns.timeout`.
- **Sample**: part of `samples/dns_failure.pcap` (reported as a symptom of the timeout).

### `dns.hijack`: someone is answering DNS queries with wrong addresses

- **Plain words**: when a device asks for a website's address, an impostor answers first with the wrong one, sending the device to a fake site.
- **Signals**: two responses to one transaction with different answers (race); a response from a server IP the client never queried; a public name resolving to a private/LAN address; the answer's source MAC differing from the resolver's usual MAC; sub-millisecond "answers"; odd fixed TTLs; the fake address belonging to the very device that delivered the answer, or to the DNS server advertised by a second (rogue) DHCP server.
- **Threshold** (attack reading): any race; or ≥ 3 answers from a server never queried; or a private answer whose address is linked to the answering device / a rogue DHCP server; or ≥ 3 public domains resolving to a private address with no captive-portal explanation. Misconfig reading (captive portal / DNS filtering) when ≥ 5 names all resolve to the resolver itself or the gateway.
- **Discriminators**:

  | Indicator | Supports | Weight |
  |---|---|---|
  | N lookups got two different answers to the same question | attack | 3.0 |
  | Fake answers arrived in under 1 ms, far faster than the real server | attack | 1.5 |
  | The fake answers came from a different MAC than the server's normal answers | attack | 1.5 |
  | Answers came from a server the device never asked | attack | 2.0 (1.5 if fewer than 3) |
  | The fake address is the DNS server handed out by a rogue DHCP server / the very device that delivered the answers | attack | 2.0 |
  | Public websites resolved to a local address | attack | 1.0 |
  | The suspicious answers claim to be authoritative, unlike the server's normal answers | attack | 1.0 |
  | The suspicious answers carry an odd, fixed TTL | attack | 0.5 |
  | Many websites all resolve to the DNS server / router itself: captive portal or DNS filtering | misconfig | 2.5 |
  | No lookup received two conflicting answers | misconfig | 0.5 (1.0 when nothing else points to an attack) |

- **MITRE**: T1557 (Adversary-in-the-Middle).
- **Samples**: `samples/dns_hijack.pcap`, `samples/mitm_chain.pcap`.

### `dns.tunneling`: DNS is being used to smuggle data

- **Plain words**: DNS is meant for small lookups. Here one host is sending hundreds of long, random-looking names, which is how malware hides data transfer inside DNS.
- **Signals**: per registered domain: number of distinct sub-names, mean label length, mean label entropy, fraction of TXT/NULL queries, inter-arrival regularity, number of clients.
- **Threshold**: at least `max(10, 30 × scale)` distinct sub-names under one domain, and then either the classic shape (≥ `max(10, 50 × scale)` sub-names with mean length ≥ 20 and entropy ≥ 3.5 bits/char) or the TXT shape (≥ 50 % TXT/NULL queries, ≥ 50 × scale queries, mean length ≥ 12, entropy ≥ 3.0).
- **Discriminators**: attack only (single variant, severity high): many sub-names (2.0); long random-looking labels; TXT/NULL share; steady rhythm like a beacon; all from one device (0.5).
- **MITRE**: T1071.004 (Application Layer Protocol: DNS).
- **Sample**: `samples/dns_tunnel.pcap`.

## Scans (`faultline/detectors/scan.py`)

Constants: `WINDOW` 60 s, `PORT_THRESHOLD` 25 distinct ports on one host, `STEALTH_THRESHOLD` 5 FIN/NULL/Xmas probes, `SWEEP_THRESHOLD` 20 distinct hosts on one service; scaled with floors of 5, 3 and 5. UDP ports are tracked separately from TCP; ICMP echo is tracked as its own "service" for sweeps. Sources that cross a threshold are published to other detectors through `scanner_sources(ctx)`, so refusals, resets and ICMP errors they cause are not reported as faults.

### `scan.port`: one host is probing many ports

- **Plain words**: someone is trying every door on one building to find the unlocked ones.
- **Signals**: distinct destination ports per (source, destination) in a window; SYN-only probes; FIN/NULL/Xmas flag combinations (no legitimate stack sends them); UDP probes answered by ICMP port-unreachable; ratio of answered to unanswered; timing regularity.
- **Threshold**: ≥ 25 distinct ports on one host within 60 s (scaled), or ≥ 5 FIN/NULL/Xmas probes.
- **Discriminators**: attack indicators include probe rate far faster than a person or application, share of probed ports that never answered (filtered/closed), open ports discovered, and "no connection was used to exchange data: nothing here looks like a working application". Benign indicator: an FTP control connection exists between the hosts (passive FTP legitimately opens many ports). Refusals and resets it triggers become symptoms (rule `scan-noise`).
- **MITRE**: T1046 (Network Service Discovery).
- **Samples**: `samples/port_scan.pcap` (SYN, FIN/NULL/Xmas and UDP probes), `samples/outage_vs_attack_mixed.pcap` (alongside a genuine DNS outage).

### `scan.host_sweep`: one host is probing many hosts

- **Plain words**: someone is checking every address in the building to see who's home.
- **Signals**: distinct destination IPs from one source via ICMP echo or SYN to a fixed port (ARP sweeps are `arp.scan`); sequential addresses; low reply ratio.
- **Threshold**: ≥ 20 distinct hosts on one service (or ICMP echo) within 60 s (scaled).
- **Discriminators**: attack indicators: addresses walked in order; most contacted addresses never answered; none of the addresses came from a DNS lookup (no user or app asked for them). Misconfig indicators: most addresses were looked up in DNS first (normal browsing); the source is the router/DHCP server; most hosts answered (inventory/monitoring tool); scattered internet web addresses (also what a browser does). MITRE adds T1046 when more than ping is involved.
- **MITRE**: T1018 (Remote System Discovery).
- **Sample**: none dedicated (`samples/host_sweep.pcap` is an ARP sweep and reports `arp.scan`); covered by unit tests (`tests/test_scan.py`).

## Floods (`faultline/detectors/flood.py`)

Constants: `SYN_WINDOW` 10 s, `SYN_THRESHOLD` 200 SYNs per window to one service, `LOW_COMPLETION` 0.2, `ICMP_RATE` 100 echo requests/s, `ICMP_SUSTAIN` 3 s, `SMURF_THRESHOLD` 10 broadcast pings in 10 s, `BCAST_RATE` 500 frames/s, `BCAST_FRACTION` 0.30, `LOOP_COPIES` 20, `LOOP_GAP` 0.02 s. Count thresholds are scaled with floors (20 SYNs, 10 pings/s, 3 smurf pings, 50 broadcast frames/s, 5 loop copies).

### `flood.syn`: a server is being flooded with connection attempts

- **Plain words**: thousands of half-open connections from fake addresses swamp the server so real users can't connect.
- **Signals**: SYN rate to one destination; fraction of handshakes never completed; number of distinct sources; SYN/ACK retransmissions by the server; absence of SYN retries from the "clients" (real stacks retry); TTL spread; bogon/LAND source addresses.
- **Threshold**: ≥ 200 SYNs to one service within 10 s (scaled); attack-like when the completion ratio is below 0.2.
- **Discriminators**: **attack**: only x % of attempts completed; thousands of distinct sources each sending one SYN and never retrying; all "different" senders share the same TTL (one spoofing machine) or TTLs spread randomly; SYNs from impossible (bogon/LAND) addresses; one source sending most SYNs. **Fault (overload / flash crowd)**: a high share of connections completed and carried requests; SYN retries (real clients wait and retry); varied TTLs and reconnects; the server answered only x % of SYNs (overwhelmed). The fault reading has severity medium and no MITRE technique.
- **MITRE**: T1499.001 (Endpoint DoS: OS Exhaustion Flood).
- **Sample**: `samples/syn_flood.pcap`.

### `flood.icmp`: a host is being flooded with pings

- **Signals**: echo request rate to one destination; distinct sources; reply ratio; oversized echo payloads; unsolicited echo replies (reflection).
- **Threshold**: ≥ 100 echo requests/s to one target for 3 consecutive seconds (scaled). Two more shapes share the kind: **smurf** (≥ 10 pings to a broadcast address in 10 s; T1498.002 Reflection Amplification) and **ping of death** (ICMP fragments reassembling beyond 65,535 bytes; T1499.004).
- **Discriminators**: attack indicators: distributed sources; oversized pings (≥ 1000 bytes); target answered only x % (overwhelmed). Benign: a single local machine sending normal-sized pings in one or two sessions (same identifier).
- **MITRE**: T1498.001 (Direct Network Flood).
- **Sample**: none dedicated; covered by unit tests (`tests/test_flood.py`).

### `flood.broadcast`: broadcast storm / network loop

- **Plain words**: the network is drowning in broadcast traffic, usually because two switch ports were looped together.
- **Signals**: broadcast/multicast frame rate; the same frame (same source, same IP ID or ARP) seen many times in a short time; TTL/hop count unchanged.
- **Threshold**: broadcast/multicast ≥ 500 frames/s and ≥ 30 % of traffic, or the same broadcast frame seen ≥ 20 times with ~20 ms gaps (loop).
- **Discriminators**: fault (switching loop: looping copies from several devices; or a single broken NIC/driver). Attack variant when most broadcasts come from one device and are crafted (T1498.001). Root of retransmissions, DNS timeouts, high RTT, unanswered ARP, DHCP failure (rule `broadcast-storm`).
- **Sample**: none dedicated; covered by unit tests (`tests/test_flood.py`).

## ICMP (`faultline/detectors/icmp.py`)

Constants: `UNREACH_THRESHOLD` 3, `TE_THRESHOLD` 3, `REDIRECT_THRESHOLD` 3, each scaled with a floor of 2.

### `icmp.unreachable`: routers or hosts report destinations as unreachable

- **Signals**: ICMPv4 type 3 and ICMPv6 type 1 messages grouped into *route* (net unreachable, no route), *host*, *port* and *admin* (administratively prohibited) classes; the quoted inner header tells which conversation failed and who sent it.
- **Threshold**: ≥ 3 messages in one class. Messages caused by known scanners, by one prober hitting ≥ 10 ports on ≤ 2 hosts (UDP scan), or by one source walking ≥ 20 hosts of one subnet (sweep) are excluded. Late replies to DNS/NTP/QUIC/STUN flows are ignored. Severity medium when ≥ 10 messages, ≥ 3 targets or ≥ 3 senders are involved, else low.
- **Discriminators**: fault for route/host unreachable (the gateway has no route; a host is down), misconfig for port unreachable (a client configured with the wrong port; "few ports and few senders, unlike a scan") and for administratively-prohibited (a firewall rejecting as configured). Symptom of scans, routing loops, gateway down, no DHCP, rogue router.
- **Sample**: none dedicated; covered by unit tests (`tests/test_icmp.py`).

### `icmp.routing_loop`: packets are circling between routers

- **Plain words**: packets go round in a circle until they expire, so the destination is never reached.
- **Signals**: ICMP Time Exceeded (type 11 / ICMPv6 type 3) for the same destination prefix, mostly from the same one or two routers; the same packet passing the capture point several times with a decreasing TTL and alternating MACs; traceroute patterns (increasing inner TTLs, UDP high ports) are recognised and excluded.
- **Threshold**: ≥ 3 time-exceeded messages for one destination with the top two routers accounting for ≥ 70 % of them; or the same packet seen ≥ 4 times (for ≥ 2 packets, or ≥ 6 copies of one). Severity high when looping copies were seen or ≥ 20 messages, else medium.
- **Discriminators**: fault (two static routes pointing at each other, or a host sending with a tiny TTL).
- **Sample**: `samples/routing_loop.pcap`.

### `icmp.redirect`: a device is telling hosts to use a different router

- **Plain words**: "use this other router instead" messages. Legitimate ones are rare; an attacker uses them to divert traffic.
- **Signals**: ICMP Redirect (type 5 / ICMPv6 type 137); whether the sender is the inferred gateway (by IP, role, MAC or because its MAC forwards traffic for many internet addresses); the suggested router; whether that router forwards any traffic; the number of hosts targeted; rate.
- **Threshold**: ≥ 3 redirects from one sender, or fewer when any attack indicator weighs ≥ 2 (e.g. the sender is not the gateway, or it is an internet address).
- **Discriminators**: attack when the attack weights exceed the misconfig weights: sender is not the gateway; the redirect names the sender itself or a device sharing its MAC as the "better router"; the suggested router never forwarded anything; ≥ 5 hosts targeted (1.5); ≥ 20 redirects at ≥ 5/s. Misconfig when the real gateway redirects to another known router that really forwards traffic (two routers on one subnet). Severity high for the attack reading; medium for misconfig when ≥ 10 redirects or ≥ 5 hosts, else low.
- **MITRE**: T1557 (Adversary-in-the-Middle).
- **Sample**: none dedicated; covered by unit tests (`tests/test_icmp.py`).

## Application layer (`faultline/detectors/app.py`)

### `cred.cleartext`: passwords are crossing the network unencrypted

- **Plain words**: someone logged in over a protocol that sends the password in plain text. Anyone on the network path can read it. **Faultline reports the protocol and the hosts only; it never stores or shows the credential.**
- **Signals**: `Packet.cred` set by the decoder (`capture/decode.py`) to one of `FTP`, `POP3`, `IMAP`, `SMTP AUTH`, `Telnet`, `HTTP Basic`; the decoder never copies the secret.
- **Threshold**: 1 occurrence (one finding per server and protocol, up to 50). Severity high for login protocols, medium otherwise.
- **Discriminators**: misconfig (legacy service) by default; indicator "the server is on the internet, so the password crossed networks you don't control". **Attack variant (password guessing, T1110 Brute Force)** when one client makes ≥ `max(5, 15 × scale)` separate cleartext logins, or sends ≥ `max(10, 30 × scale)` credential messages, to one server within 60 s. The finding is a symptom of a MITM incident when one exists (rules `mitm`, `dns-spoofing`).
- **MITRE**: T1110 (Brute Force) for the attack reading only; the misconfig reading carries no technique.
- **Samples**: `samples/cleartext_creds.pcap` (FTP, Telnet, HTTP Basic), `samples/mitm_chain.pcap` (HTTP Basic to the attacker, as a consequence).

### `tls.failure`: secure connections are failing

- **Signals**: cleartext TLS alerts (handshake_failure, bad_certificate, unknown_ca, certificate_expired, protocol_version, inappropriate_fallback, …) per server, with who sent them (client or server) and the SNI.
- **Threshold**: ≥ 2 fatal alerts to one server, or any certificate-related alert. Severity medium when ≥ 3 alerts or ≥ 2 clients are affected, else low.
- **Discriminators**: the default category comes from the alert type (fault for handshake/protocol errors, misconfig for certificate problems such as an expired certificate). Attack indicator when clients reject the certificate they were shown (bad_certificate / unknown_ca / certificate_unknown), stronger when ≥ 3 unrelated servers fail the check at once: interception with a fake certificate (variant T1557, severity high). Also chained under `mitm` / `dns-spoofing` incidents.
- **Sample**: `samples/tls_failures.pcap` (misconfig: expired certificate).

### `tls.deprecated`: outdated encryption is in use

- **Signals**: ClientHello / ServerHello versions below TLS 1.2 (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1), negotiated or merely offered.
- **Threshold**: 1 handshake. Severity high when SSL 3.0 or older was negotiated, medium when TLS 1.0/1.1 was negotiated, low when clients only *offered* old versions.
- **Discriminators**: misconfig only ("the server agreed to use TLS 1.0 in N connections", 2.5; "N clients offered at most TLS 1.1: outdated software", 1.5).
- **Sample**: none dedicated; covered by unit tests (`tests/test_app.py`).

### `http.errors`: web servers are returning errors (or being hammered)

One kind, four shapes:

- **Server errors (5xx)**: ≥ 3 responses with status 5xx and ≥ 10 % of that server's responses. Fault; severity high when ≥ 50 % and ≥ 20 errors, else medium. Indicators: share of failed requests (2.5 / 2.0), several clients affected, 502/504 means a proxy lost its backend.
- **Client errors (4xx)**: ≥ 20 responses 4xx and ≥ 50 % of the server's responses. Fault, severity low (broken links, wrong configuration). Suppressed when a brute-force or wordlist finding already explains the server's errors.
- **Password guessing (401/403)**: ≥ `max(5, 20 × scale)` 401/403 answers from one server to one client within 60 s. Attack (T1110 Brute Force, severity high) when attempts are fast, mostly for the same login page and rarely succeed; misconfig (an app retrying a stale saved password, severity low) when the same request repeats at a steady interval.
- **Wordlist content scan (404)**: ≥ `max(10, 50 × scale)` 404 answers to one client within 60 s, for mostly distinct paths spread over ≥ 20 unrelated top-level names (`/admin`, `/backup`, `/.git` …), with ≥ 70 % of the client's requests failing. Attack, T1595.003 (Active Scanning: Wordlist Scanning), severity medium.
- **Correlation**: symptom of `flood.syn` / `flood.icmp`.
- **Sample**: `samples/web_bruteforce.pcap` (attack: 45 refused logins in a row).

---

## Correlation rules (`faultline/correlate.py`)

How findings are chained into incidents. A root explains its consequences; consequences are shown as symptoms with "fixing that should fix this too". `overlap` means the consequence must share a host with the root. Where a root category is given, the rule only applies when the verdict engine judged the root that way.

| Rule | Root kinds (category) | Consequence kinds | Incident title | Overlap |
|---|---|---|---|---|
| `mitm` | `dhcp.multiple_servers`, `arp.duplicate_ip`, `icmp.redirect` (attack) | `dns.hijack`, `cred.cleartext`, `tls.failure`, `dns.timeout`, `tcp.resets`, `arp.duplicate_ip` | Man-in-the-middle attack | no |
| `dns-spoofing` | `dns.hijack` (attack) | `arp.duplicate_ip`, `tls.failure`, `cred.cleartext` | DNS spoofing attack | yes |
| `rogue-router` | `dhcp.multiple_servers` (misconfig) | `dns.timeout`, `dns.errors`, `tcp.syn_timeout`, `arp.unanswered`, `icmp.unreachable`, `dhcp.nak` | A second router is breaking connectivity | no |
| `no-dhcp` | `dhcp.no_server` | `dns.timeout`, `tcp.syn_timeout`, `arp.unanswered`, `icmp.unreachable` | Devices can't get a network address | no |
| `gateway-down` | `arp.unanswered` | `dns.timeout`, `tcp.syn_timeout`, `icmp.unreachable`, `latency.high_rtt` | The router stopped responding | yes |
| `scan-noise` | `scan.port`, `scan.host_sweep`, `arp.scan` (attack) | `tcp.refused`, `tcp.resets`, `icmp.unreachable`, `arp.unanswered`, `tcp.syn_timeout` | Reconnaissance scan | yes |
| `flood` | `flood.syn`, `flood.icmp` | `tcp.syn_timeout`, `latency.slow_server`, `latency.high_rtt`, `tcp.retransmissions`, `tcp.resets`, `http.errors` | Denial-of-service attack | yes |
| `mtu` | `mtu.blackhole`, `mtu.frag_needed` | `tcp.retransmissions`, `tcp.resets`, `tls.failure`, `latency.slow_server` | Packet-size (MTU) problem | yes |
| `routing-loop` | `icmp.routing_loop` | `icmp.unreachable`, `tcp.syn_timeout`, `dns.timeout`, `latency.high_rtt` | Routing loop | yes |
| `dns-down` | `dns.timeout` | `dns.slow`, `dns.errors` | DNS outage | no |
| `broadcast-storm` | `flood.broadcast` | `tcp.retransmissions`, `dns.timeout`, `latency.high_rtt`, `arp.unanswered`, `dhcp.no_server` | Network loop / broadcast storm | no |

Rules are tried in this order; a finding used as a root or consequence once is not reused. Incident category is *attack* if any member is an attack, otherwise the root's category. The incident's "fix this first" is the root finding's first three fix steps.

## Verdict and score (`faultline/verdict.py`, `faultline/correlate.py`)

- Hypothesis score = 0.5 prior for the detector's default + Σ indicator weights (each clamped to 3). Candidates are the default reading plus every category the detector supplied a variant for. Winner = highest; ties go to the default. Confidence = softmax over the candidate scores (temperature 1), or `1 − 0.5·e^(−score/2)` when there is only one candidate, clamped to [0.5, 0.99]. An attack reading with confidence < 0.6 is shown one severity step softer (never below low). The losing hypotheses are kept with their indicators and rendered as "Why not …?".
- Health score = 100 − Σ penalty(severity) × max(0.5, confidence), with penalty 0 / 3 / 9 / 18 / 30 for info / low / medium / high / critical, and symptoms counted at 40 %. Clamped to 0..100.
- Overall status: **under_attack** if any attack finding has severity ≥ medium and confidence ≥ 0.6; else **faulty** if any fault/misconfig has severity ≥ medium; else **minor_issues** if anything has severity ≥ low; else **healthy**.

---

## Protocol anomalies (`detectors/protocol.py`)

Added after testing on public real-world captures (see the README, *Real-world validation*).

### `dns.non_dns_traffic`: something other than DNS on port 53

- **What it means:** port 53 is open on almost every firewall, so backdoors and tunnels hide there. Real DNS messages are binary. Readable text on port 53 is not DNS.
- **Signal:** the decoder flags TCP/UDP port-53 payloads that fail DNS parsing and are ≥ 90% printable text (first 128 bytes). If the text contains shell markers ("Microsoft Windows", `C:\`, `uid=`, `/bin/sh`, `root@`, "Volume in drive"), the packet is marked `shell on DNS port`. Only marker matching is done; the payload is never stored.
- **Fires when:** ≥ 3 such packets, or any shell-like packet.
- **Attack indicators:** readable text on port 53 (1.5), command-shell text (3.0), text in both directions (1.0), the "server" never answered a real DNS query (1.0).
- **Misconfiguration indicators:** the server also answers real DNS (1.0), text in one direction only (0.5).
- **MITRE:** T1571 Non-Standard Port. Severity CRITICAL with a shell, otherwise HIGH.
- **Sample:** `samples/dns_backdoor.pcap`; public: `dns-remoteshell.pcap`.

### `ip.fragment_attack`: overlapping or tiny IP fragments

- **Overlap (Teardrop):** per (src, dst, protocol, IP ID), a fragment whose byte range partially overlaps an earlier fragment. Exact duplicates are ignored, since they are harmless network duplication. Indicator: attack 3.0, MITRE T1499. A single overlap with nothing else adds a fault indicator (1.0, buggy stack).
- **Tiny first fragment (evasion):** a first TCP fragment shorter than 16 bytes, so the TCP header is split, as with `nmap -f`. Indicator: attack 2.0.
- **Samples:** `samples/teardrop.pcap` (next to a legitimately fragmented ping that must stay quiet); public: `teardrop.cap`, `nmap_ACK_scan_on_port_80_2`.
- **Tests:** `tests/test_protocol.py`.
