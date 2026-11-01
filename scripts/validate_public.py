"""Real-world validation on public sample captures from the Wireshark project.

Our benchmark (`faultline bench`) uses captures from our own lab. This script
checks Faultline against *real* traffic captured by other people: it downloads
public samples from wiki.wireshark.org, verifies each file against a pinned
SHA-256 (so a tampered download is refused), runs the full engine, and scores
the result against what each capture is documented to contain, including the
cases we knowingly miss.

    python scripts/validate_public.py                 # downloads once into ~/.cache/faultline/public-captures
    python scripts/validate_public.py --dir captures/ # use another folder

The captures are not redistributed in this repository.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from rich import box  # noqa: E402
from rich.console import Console  # noqa: E402
from rich.table import Table  # noqa: E402

from faultline.capture.reader import CaptureError  # noqa: E402
from faultline.engine import AnalyzeOptions, analyze  # noqa: E402

BASE = "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/"
HTTP_CAP = "https://wiki.wireshark.org/uploads/27707187aeb30df68e70c8fb9d614981/http.cap"
MAX_DOWNLOAD = 5 * 1024 * 1024

PINNED = {
    "arp-storm.pcap": "dc101ea9bfda59f56b54bfb949195c3f169032c045b47f98e6952a86933c1b8d",
    "dhcp.pcap": "2471b5420bdac826eecf8f61a2bbb4a3eb20dbfab7c02ff2be502f349f368214",
    "dns.cap": "041eeb6f98bb398f1ee8b09651b5b5a84f6a62639f95bf226f9e7b77355d9f28",
    "dns-remoteshell.pcap": "8c89c0d2d5b91695a03d05a451897f583a99d2379afac0822af0d8f390163d95",
    "zlip-1.pcap": "47fba059fd1644a5317fb675eb3832836939238371130e960651445fd4502701",
    "zlip-2.pcap": "551612cf05436ffde6cc64dd9fdbee416adfb00085fdc57d552d4434f389beb1",
    "zlip-3.pcap": "3d559700f4c58738d7847a923e7b870eaa55b1cd001cb62af9d8d63775dc45da",
    "NMap-Captures.zip": "3fac3f99402b5b6a2bc819ce7c9ba4aab58756e3353412a7834bfce02f098305",
    "telnet-raw.pcap": "7a2fdd843b401fb945b0604b9d760424541b045dac6424361f14d276db2b05a3",
    "telnet-cooked.pcap": "ae870805f1e5f6a2621b1f6e1e0229b47cc96d917f42c215acbcfcd46f9d72fc",
    "teardrop.cap": "e8e4193ae426dabf549cc103c9e93e7d93c6ae049ee9259f1ce2ebdb7315a683",
    "ipv4frags.pcap": "d0b1965aa0c7f9792ee1922f18b1c4e67a45f014fbd324c18dda0dd280605ec4",
    "tcp-ecn-sample.pcap": "e6edf98f9e2e8a9711fb41a4e16840ef3942b40c7d2694ca373b7f285c783648",
    "nfs_bad_stalls.cap": "46da2b7056381d86672d2825525c1e5aa02e3aba408fdcd372a947d76fa93e5b",
    "v6.pcap": "8e18b4c2aa872285881f3aff39481eabc83024369a7b83d95573d846a4a091f2",
    "dhcp-and-dyndns.pcap.gz": "9ecf8ca50299a7bceaf7cf016ff0efc8a6c03634d40869318a82f32696605f30",
    "http.cap": "25a72bdf10339f2c29916920c8b9501d294923108de8f29b19aba7cc001ab60d",
}

# file → (what it really contains, expected finding kinds, expect_no_attack, known_limitation_note)
CASES = [
    ("nmap/nmap_standard_scan", "Nmap default SYN scan", {"scan.port"}, False, None),
    ("nmap/nmap_OS_scan", "Nmap OS-detection scan", {"scan.port"}, False, None),
    ("nmap/nmap_OS_scan_succesful", "Nmap OS-detection scan", {"scan.port"}, False, None),
    ("nmap/nmap_ACK_scan_on_port_80_2", "Nmap ACK scan with -f tiny fragments + spoofed source", {"ip.fragment_attack"}, False, None),
    ("dns-remoteshell.pcap", "Windows remote shell over TCP port 53", {"dns.non_dns_traffic"}, False, None),
    ("teardrop.cap", "Teardrop overlapping-fragment attack", {"ip.fragment_attack"}, False, None),
    ("telnet-raw.pcap", "Telnet login (clear-text password)", {"cred.cleartext"}, False, None),
    ("telnet-cooked.pcap", "Telnet login (clear-text password)", {"cred.cleartext"}, False, None),
    ("tcp-ecn-sample.pcap", "Router admin over HTTP with Basic auth", {"cred.cleartext"}, True, None),
    ("arp-storm.pcap", "ISP routers ARP-ing many customers (not an attack)", set(), True, None),
    ("dns.cap", "Ordinary DNS lookups", set(), True, None),
    ("http.cap", "Ordinary web page download", set(), True, None),
    ("dhcp.pcap", "Ordinary DHCP lease", set(), True, None),
    ("dhcp-and-dyndns.pcap.gz", "DHCP + dynamic DNS", set(), True, None),
    ("v6.pcap", "IPv6 / ICMPv6 traffic", set(), True, None),
    ("ipv4frags.pcap", "Legitimately fragmented ping", set(), True, None),
    ("nfs_bad_stalls.cap", "NFS file transfer (7,000 packets)", set(), True, None),
    ("zlip-1.pcap", "DNS decompression exploit (hostile input)", set(), True, None),
    ("zlip-2.pcap", "DNS decompression exploit (hostile input)", set(), True, None),
    ("zlip-3.pcap", "DNS decompression exploit (hostile input)", set(), True, None),
    ("nmap/nmap_ACK_scan_on_port_80", "Nmap ACK scan of ONE port (6 packets)", set(), True,
     "known limitation: a 1-port ACK probe is indistinguishable from mid-connection traffic"),
    ("nmap/nmap_zombie_scan", "Nmap idle/zombie scan (stealth by design)", set(), True,
     "known limitation: idle scans hide the real scanner; would need IP-ID side-channel tracking"),
]


def _download(url: str) -> bytes:
    """Polite download: pacing plus exponential back-off on HTTP 429 / 5xx."""
    delay = 2.0
    for attempt in range(6):
        req = urllib.request.Request(url, headers={"User-Agent": "faultline-validate/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 (fixed https URLs only)
                return resp.read(MAX_DOWNLOAD + 1)
        except urllib.error.HTTPError as exc:
            if exc.code not in (429, 500, 502, 503, 504) or attempt == 5:
                raise
        time.sleep(delay)
        delay *= 2
    raise RuntimeError("unreachable")


def verify(name: str, path: str) -> bool:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest() == PINNED[name]


def fetch(name: str, dest: str) -> str:
    url = HTTP_CAP if name == "http.cap" else BASE + name
    data = _download(url)
    time.sleep(0.7)
    if len(data) > MAX_DOWNLOAD:
        raise RuntimeError(f"{name}: larger than expected, refusing")
    digest = hashlib.sha256(data).hexdigest()
    if digest != PINNED[name]:
        raise RuntimeError(f"{name}: SHA-256 mismatch ({digest[:12]}…), refusing to analyse a modified file")
    path = os.path.join(dest, name)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dir", default=os.path.join(os.path.expanduser("~"), ".cache", "faultline", "public-captures"),
                    help="where downloads are cached (default: ~/.cache/faultline/public-captures)")
    args = ap.parse_args()
    con = Console(highlight=False)
    work = args.dir
    os.makedirs(work, mode=0o700, exist_ok=True)
    try:
        con.print(f"[dim]Downloading {len(PINNED)} public captures from wiki.wireshark.org (SHA-256 pinned)…[/]")
        try:
            for name in PINNED:
                path = os.path.join(work, name)
                if not (os.path.exists(path) and verify(name, path)):
                    fetch(name, work)
        except (OSError, RuntimeError) as exc:
            con.print(f"[red]Could not download the public captures:[/] {exc}. Check your connection and retry.")
            return 2
        with zipfile.ZipFile(os.path.join(work, "NMap-Captures.zip")) as z:
            os.makedirs(os.path.join(work, "nmap"), exist_ok=True)
            for info in z.infolist():
                base = os.path.basename(info.filename)
                if base.startswith("nmap_") and info.file_size < MAX_DOWNLOAD:  # no path traversal: basename only
                    with z.open(info) as src, open(os.path.join(work, "nmap", base), "wb") as dst:
                        shutil.copyfileobj(io.BufferedReader(src), dst)

        t = Table(title="Faultline on public real-world captures (wiki.wireshark.org)", box=box.SIMPLE_HEAVY)
        for col in ("Capture", "What it really is", "Faultline verdict", "Findings", "Result"):
            t.add_column(col)
        ok = miss = total = 0
        for rel, truth, want, no_attack, limit in CASES:
            total += 1
            try:
                rep = analyze(os.path.join(work, rel), AnalyzeOptions(evidence=False)).to_dict()
            except CaptureError as exc:
                t.add_row(rel, truth, "rejected", str(exc)[:40], "[red]ERROR[/]")
                miss += 1
                continue
            kinds = {f["kind"] for f in rep["findings"] if f["severity"] >= 1}
            attacks = {f["kind"] for f in rep["findings"] if f["category"] == "attack" and f["severity"] >= 2}
            shown = ", ".join(sorted(kinds)) or "-"
            good = want <= kinds and (not no_attack or not attacks)
            if limit and not want:
                res = "[yellow]known miss[/]" if not attacks else "[red]FALSE ALARM[/]"
                miss += 1
            elif good:
                res, ok = "[green]PASS[/]", ok + 1
            else:
                res, miss = "[red]FAIL[/]", miss + 1
            t.add_row(rel, truth + (f"\n[dim]{limit}[/]" if limit else ""), rep["verdict"]["status"].replace("_", " "), shown, res)
        con.print(t)
        con.print(f"[bold]{ok}/{total} correct[/] · {miss} known misses / failures · "
                  f"0 crashes on {total} real captures (including 3 DNS exploit files)")
        return 0
    finally:
        pass


if __name__ == "__main__":
    sys.exit(main())
