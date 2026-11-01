"""Scripted, real interactions with the local Faultline dashboard (recorded by Playwright)."""

from __future__ import annotations

import time


def _glide(page, selector: str, seconds: float, offset: int = 90) -> None:
    """Scroll smoothly so that `selector` sits near the top of the viewport."""
    loc = page.locator(selector).first
    try:
        box = loc.bounding_box()
    except Exception:
        box = None
    if not box:
        return
    dy = box["y"] - offset
    steps = max(1, int(seconds * 30))
    page.mouse.move(800, 450)
    for i in range(steps):
        page.mouse.wheel(0, dy / steps)
        page.wait_for_timeout(1000 / 30)


def _hold(page, seconds: float) -> None:
    page.wait_for_timeout(int(seconds * 1000))


def _open(page, url: str) -> float:
    t0 = time.time()
    page.goto(url)
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(400)
    return time.time() - t0


def landing(page, base: str, dur: float) -> float:
    lead = _open(page, base + "/")
    _hold(page, dur * 0.35)
    _glide(page, "text=Start here", 1.5)
    _hold(page, dur * 0.2)
    _glide(page, "text=Try a bundled capture", 1.4)
    try:
        page.get_by_role("button", name="Attacks").first.click(timeout=1500)
    except Exception:
        pass
    return lead


def report_mitm(page, base: str, dur: float) -> float:
    lead = _open(page, base + "/sample/mitm_chain.pcap")
    _hold(page, 3.0)
    _glide(page, "#timeline", 1.2, offset=120)
    _hold(page, 2.0)
    _glide(page, ".map-panel", 1.5, offset=80)
    try:
        page.locator('[role="button"][aria-label*="192.168.1.66"]').first.hover(timeout=1500)
    except Exception:
        pass
    _hold(page, 4.0)
    page.mouse.move(80, 80)
    _glide(page, "#findings", 1.5, offset=70)
    _hold(page, 2.5)
    _glide(page, ".reason", 1.5, offset=80)
    _hold(page, 3.5)
    _glide(page, "text=Evidence: the exact packets", 1.4, offset=80)
    return lead


def compare(page, base: str, dur: float) -> float:
    lead = _open(page, base + "/compare?a=ip_conflict.pcap&b=arp_spoofing.pcap")
    return lead


def report_mixed(page, base: str, dur: float) -> float:
    lead = _open(page, base + "/sample/outage_vs_attack_mixed.pcap")
    _hold(page, dur * 0.45)
    _glide(page, "#findings", 1.6, offset=70)
    return lead


ACTIONS = {"landing": landing, "report_mitm": report_mitm, "compare": compare, "report_mixed": report_mixed}
