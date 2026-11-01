"""Scripted, real interactions with the local Faultline dashboard (recorded by Playwright)."""

from __future__ import annotations

import time


def _hold(page, seconds: float) -> None:
    page.wait_for_timeout(int(seconds * 1000))


def _open(page, url: str) -> float:
    t0 = time.time()
    page.goto(url)
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(500)
    return time.time() - t0


def _click(page, selector: str, timeout: int = 2000) -> bool:
    try:
        loc = page.locator(selector).first
        loc.scroll_into_view_if_needed(timeout=timeout)
        box = loc.bounding_box()
        if box:  # move the pointer visibly before clicking
            page.mouse.move(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2, steps=12)
        loc.click(timeout=timeout)
        return True
    except Exception:
        return False


def _section(page, name: str) -> None:
    if not _click(page, f'a.nav-item[data-section="{name}"]'):
        page.evaluate(f"location.hash = '#{name}'")
    page.wait_for_timeout(400)


def _scroll(page, dy: float, seconds: float) -> None:
    steps = max(1, int(seconds * 30))
    for _ in range(steps):
        page.mouse.wheel(0, dy / steps)
        page.wait_for_timeout(33)


def landing(page, base: str, dur: float) -> float:
    lead = _open(page, base + "/")
    page.mouse.move(700, 500)
    _hold(page, dur * 0.4)
    _click(page, 'a.nav-item:has-text("Sample library")') or _scroll(page, 700, 1.5)
    _hold(page, 1.2)
    _click(page, '#sample-tabs button[data-filter="attack"]')
    return lead


def report_mitm(page, base: str, dur: float) -> float:
    lead = _open(page, base + "/sample/mitm_chain.pcap#overview")
    page.mouse.move(900, 400)
    _hold(page, 4.5)
    _scroll(page, 520, 1.6)
    _hold(page, 2.5)
    _section(page, "network")
    page.wait_for_timeout(600)
    try:
        node = page.locator('[data-ip="192.168.1.66"]').first
        box = node.bounding_box()
        if box:
            page.mouse.move(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2, steps=20)
        node.hover(timeout=1500)
    except Exception:
        pass
    _hold(page, 4.5)
    _section(page, "findings")
    _hold(page, 1.5)
    _click(page, '.tab[data-tab="why"]')
    _hold(page, 4.5)
    _click(page, '.tab[data-tab="evidence"]')
    return lead


def compare(page, base: str, dur: float) -> float:
    lead = _open(page, base + "/compare?a=ip_conflict.pcap&b=arp_spoofing.pcap")
    page.mouse.move(900, 400)
    _hold(page, dur * 0.5)
    _scroll(page, 560, 2.0)
    return lead


def report_mixed(page, base: str, dur: float) -> float:
    lead = _open(page, base + "/sample/outage_vs_attack_mixed.pcap#overview")
    page.mouse.move(900, 400)
    _hold(page, dur * 0.45)
    _section(page, "findings")
    return lead


ACTIONS = {"landing": landing, "report_mitm": report_mitm, "compare": compare, "report_mixed": report_mixed}
