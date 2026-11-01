"""Detector modules. Importing this package registers every detector."""

from __future__ import annotations

import importlib

from .base import REGISTRY, Detector

MODULES = ["tcp", "latency", "mtu", "arp", "dhcp", "dns", "scan", "flood", "icmp", "app"]

for _m in MODULES:
    try:
        importlib.import_module(f"{__name__}.{_m}")
    except ModuleNotFoundError as exc:  # module not written yet / optional
        if exc.name != f"{__name__}.{_m}":
            raise


def all_detectors() -> list[Detector]:
    return [cls() for cls in REGISTRY]
