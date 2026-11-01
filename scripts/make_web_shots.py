"""Screenshots of the web dashboard and HTML report for the README (real pages, real samples).

Starts the dashboard on a free local port, opens it in headless Chromium (Playwright)
and saves screenshots to docs/images/web-*.png.

    pip install playwright && playwright install chromium   # one-time, not a Faultline dependency
    python scripts/make_web_shots.py
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "images")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main() -> None:
    from playwright.sync_api import sync_playwright

    port = free_port()
    py = os.path.join(ROOT, ".venv", "bin", "python")
    srv = subprocess.Popen([py if os.path.exists(py) else sys.executable, "-m", "faultline", "web", "--port", str(port),
                            "--no-browser"], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.2)
        os.makedirs(OUT, exist_ok=True)
        with sync_playwright() as p:
            b = p.chromium.launch()
            pg = b.new_page(viewport={"width": 1440, "height": 900}, device_scale_factor=2)

            def shot(name, url, full=False, selector=None, wait=1800, click=None):
                pg.goto(base + url)
                pg.wait_for_timeout(wait)
                if click:
                    pg.click(click)
                    pg.wait_for_timeout(500)
                path = os.path.join(OUT, name)
                if selector:
                    pg.locator(selector).first.scroll_into_view_if_needed()
                    pg.wait_for_timeout(600)
                    pg.locator(selector).first.screenshot(path=path)
                else:
                    pg.screenshot(path=path, full_page=full)
                print("  wrote", os.path.relpath(path, ROOT))

            # The report is an app shell with hash routes: #overview, #incidents, #findings[/F1[/tab]],
            # #network, #evidence, #capture. Tabs: explain, fix, why, evidence, technical (expert mode).
            shot("web-landing.png", "/")
            shot("web-report-mitm.png", "/sample/mitm_chain.pcap")
            shot("web-findings.png", "/sample/mitm_chain.pcap#findings/F1/explain")
            shot("web-network-map.png", "/sample/mitm_chain.pcap#network", selector=".map-panel")
            shot("web-why-attack.png", "/sample/arp_spoofing.pcap#findings/F1/why", selector=".fl-detail .finding")
            shot("web-compare.png", "/compare?a=ip_conflict.pcap&b=arp_spoofing.pcap")
            shot("web-report-mixed.png", "/sample/outage_vs_attack_mixed.pcap")
            shot("web-report-lossy.png", "/sample/lossy_link.pcap")
            shot("web-report-full-mitm.png", "/sample/mitm_chain.pcap#incidents")
            b.close()
    finally:
        srv.terminate()


if __name__ == "__main__":
    main()
