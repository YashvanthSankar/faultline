"""Report redaction: consistent, irreversible pseudonyms for network identifiers.

``redact_report(report)`` returns a deep copy of a report dict in which every
IPv4 address, IPv6 address and MAC address, wherever it appears (dict keys and
values, list items, free text such as explanations, ``host:port`` forms, MACs
in colon or dash notation) is replaced by a pseudonym such as
``lan-host-3f2a1c`` / ``inet-host-91bc0e`` / ``mac-7c1e22``.

Properties
----------
* **Consistent within one report**: the same address always maps to the same
  pseudonym, so the story of the report ("host A talked to host B") survives.
* **Irreversible and uncorrelatable across reports**: pseudonyms are the first
  bytes of ``HMAC-SHA256(key, canonical_address)`` with a fresh random key per
  call (``secrets.token_bytes(32)``). The key is never stored, logged or
  returned; nothing in the output allows the original address to be recovered
  or two redacted reports to be joined.
* **Meaning-preserving**: the local/internet distinction is kept in the
  label; addresses that carry meaning but no identity (0.0.0.0,
  255.255.255.255, loopback, multicast, broadcast / null MACs) are left as-is.
* **Evidence is dropped**: ``report["evidence"]`` (raw pcap bytes / paths) is
  removed and ``report["redacted"] = True`` is set.
* **Never crashes**: unknown types are copied as-is; a failure inside the
  redaction of one value falls back to the unmodified value only for
  non-string scalars; strings are always processed.

Standard library only.
"""

from __future__ import annotations

import hmac
import hashlib
import ipaddress
import re
import secrets
from typing import Any

__all__ = ["redact_report", "Redactor"]

# --------------------------------------------------------------------------- #
# Patterns (precompiled; word-boundary logic so "TLS 1.2" / "1.0.0" are safe)
# --------------------------------------------------------------------------- #

_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
# Four octets, no digit or dot directly before or after (so "1.0.0" and
# "10.0.0.1.5" do not match, "192.168.1.15:443" and "(10.0.0.1)" do).
IPV4_RE = re.compile(rf"(?<![\d.])(?:{_OCTET}\.){{3}}{_OCTET}(?![\d.])")

# Candidate IPv6 text: hex groups and colons, at least two colons, optionally an
# embedded dotted IPv4 tail. Validated with ipaddress before replacement, so
# clock times like "12:30:45" (no '::', fewer than 8 groups) are rejected.
IPV6_RE = re.compile(
    r"(?<![0-9A-Za-z:.\-])"
    r"(?:[0-9A-Fa-f]{1,4})?"
    r"(?::(?:(?:\d{1,3}\.){3}\d{1,3}(?![\d.])|[0-9A-Fa-f]{0,4})){2,7}"
    r"(?![0-9A-Za-z:])"
)

# 6 hex pairs with a consistent ':' or '-' separator and no hex / separator
# neighbours (so a group inside an expanded IPv6 address is not taken as a MAC).
MAC_RE = re.compile(
    r"(?<![0-9A-Fa-f:\-])"
    r"[0-9A-Fa-f]{2}(?P<sep>[:\-])(?:[0-9A-Fa-f]{2}(?P=sep)){4}[0-9A-Fa-f]{2}"
    r"(?![0-9A-Fa-f:\-])"
)

# Domain-like tokens (only applied to known fields when redact_names=True).
_TLD_LIKE = r"[A-Za-z][A-Za-z0-9\-]{1,62}"
NAME_RE = re.compile(rf"(?<![\w.\-])(?:[A-Za-z0-9_\-]{{1,63}}\.)+{_TLD_LIKE}\.?(?![\w\-])")

_LABEL_HEX = 6  # 24 bits: a few hundred hosts collide with probability < 1%


class Redactor:
    """Stateful pseudonymiser; one instance == one report == one random key."""

    def __init__(self, key: bytes | None = None):
        if key is None:
            key = secrets.token_bytes(32)
        if not isinstance(key, (bytes, bytearray)) or len(key) < 16:
            raise ValueError("redaction key must be at least 16 random bytes")
        self._key = bytes(key)
        self._cache: dict[str, str] = {}

    # -- primitives --------------------------------------------------------
    def _tag(self, kind: str, canonical: str) -> str:
        ck = kind + "|" + canonical
        hit = self._cache.get(ck)
        if hit is None:
            digest = hmac.new(self._key, ck.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()
            hit = digest[:_LABEL_HEX]
            self._cache[ck] = hit
        return hit

    def ip(self, text: str) -> str:
        """Pseudonym for one address string (returned unchanged if special)."""
        try:
            addr = ipaddress.ip_address(text)
        except ValueError:
            return text
        if _ip_is_special(addr):
            return text
        if isinstance(addr, ipaddress.IPv6Address):
            if addr.ipv4_mapped is not None:
                return self.ip(str(addr.ipv4_mapped))
            kind = "lan6-host" if (addr.is_private or addr.is_link_local or addr.is_site_local) else "inet6-host"
        else:
            kind = "lan-host" if (addr.is_private or addr.is_link_local) else "inet-host"
        return f"{kind}-{self._tag('ip', addr.compressed)}"

    def mac(self, text: str) -> str:
        norm = text.replace("-", ":").lower()
        if _mac_is_special(norm):
            return text
        return f"mac-{self._tag('mac', norm)}"

    def name(self, text: str) -> str:
        norm = text.rstrip(".").lower()
        if not norm:
            return text
        return f"name-{self._tag('name', norm)}"

    # -- strings -----------------------------------------------------------
    def text(self, s: str, names: bool = False) -> str:
        """Replace every address inside free text."""
        if not s:
            return s
        # IPv6 first: an expanded IPv6 could otherwise be mistaken for MAC pieces.
        if ":" in s:
            s = IPV6_RE.sub(self._sub_ipv6, s)
            s = MAC_RE.sub(self._sub_mac, s)
        elif "-" in s:
            s = MAC_RE.sub(self._sub_mac, s)
        if "." in s:
            s = IPV4_RE.sub(self._sub_ipv4, s)
            if names:
                s = NAME_RE.sub(self._sub_name, s)
        return s

    def _sub_ipv4(self, m: re.Match) -> str:
        return self.ip(m.group(0))

    def _sub_ipv6(self, m: re.Match) -> str:
        cand = m.group(0)
        try:
            addr = ipaddress.IPv6Address(cand)
        except ValueError:
            return cand
        return self.ip(str(addr)) if not _ip_is_special(addr) else cand

    def _sub_mac(self, m: re.Match) -> str:
        return self.mac(m.group(0))

    def _sub_name(self, m: re.Match) -> str:
        tok = m.group(0)
        # already a pseudonym or a number-only "domain" (left over version strings)?
        if tok.startswith(("lan-host-", "inet-host-", "lan6-host-", "inet6-host-", "mac-", "name-")):
            return tok
        if all(part.isdigit() for part in tok.rstrip(".").split(".")):
            return tok
        return self.name(tok)

    # -- structures --------------------------------------------------------
    def walk(self, obj: Any, names: bool = False) -> Any:
        """Deep-copy ``obj`` while redacting every string in it."""
        if isinstance(obj, str):
            return self.text(obj, names)
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                nk = self.text(k, names) if isinstance(k, str) else k
                out[nk] = self.walk(v, names)
            return out
        if isinstance(obj, list):
            return [self.walk(v, names) for v in obj]
        if isinstance(obj, tuple):
            return tuple(self.walk(v, names) for v in obj)
        if isinstance(obj, (set, frozenset)):
            return type(obj)(self.walk(v, names) for v in obj)
        if isinstance(obj, (bytes, bytearray)):
            # raw bytes never belong in a shareable report
            return f"<{len(obj)} bytes removed>"
        return obj  # int / float / bool / None / unknown objects: copied by reference


# --------------------------------------------------------------------------- #
# Special addresses that carry meaning but no identity
# --------------------------------------------------------------------------- #

def _ip_is_special(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if addr.is_unspecified or addr.is_loopback or addr.is_multicast:
        return True
    if isinstance(addr, ipaddress.IPv4Address):
        if addr == ipaddress.IPv4Address("255.255.255.255"):
            return True
    return False


def _mac_is_special(norm: str) -> bool:
    if norm in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return True
    try:
        first = int(norm[:2], 16)
    except ValueError:
        return True
    return bool(first & 0x01)  # group bit set: multicast (01:00:5e.., 33:33.., 01:80:c2..)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

_NAME_FIELDS_HOSTS = ("names", "hostname", "hostnames", "dns_names")


def redact_report(report: dict, key: bytes | None = None, redact_names: bool = False) -> dict:
    """Return a redacted deep copy of ``report``.

    ``key``: optional 16+ byte HMAC key (tests only; by default a fresh random
    key is generated and discarded). ``redact_names``: also pseudonymise
    hostnames in ``hosts[].names``, ``findings[].evidence_lines[].summary`` and
    ``findings[].metrics`` values.
    """
    r = Redactor(key)
    if not isinstance(report, dict):
        # Be forgiving: redact whatever we were given, wrapped.
        return {"report": r.walk(report), "redacted": True}

    out = r.walk(report)
    out.pop("evidence", None)
    out.pop("evidence_files", None)

    if redact_names:
        _redact_names_in_known_fields(out, r)

    out["redacted"] = True
    return out


def _redact_names_in_known_fields(out: dict, r: Redactor) -> None:
    hosts = out.get("hosts")
    host_iter: list = []
    if isinstance(hosts, list):
        host_iter = hosts
    elif isinstance(hosts, dict):
        host_iter = list(hosts.values())
    for h in host_iter:
        if not isinstance(h, dict):
            continue
        for fld in _NAME_FIELDS_HOSTS:
            v = h.get(fld)
            if isinstance(v, list):
                h[fld] = [r.name(x) if isinstance(x, str) and x else x for x in v]
            elif isinstance(v, str) and v:
                h[fld] = r.name(v)

    findings = out.get("findings")
    if isinstance(findings, list):
        for f in findings:
            if not isinstance(f, dict):
                continue
            lines = f.get("evidence_lines")
            if isinstance(lines, list):
                for ln in lines:
                    if isinstance(ln, dict) and isinstance(ln.get("summary"), str):
                        ln["summary"] = r.text(ln["summary"], names=True)
                    elif isinstance(ln, str):
                        pass  # list of plain strings: handled below
                f["evidence_lines"] = [r.text(ln, names=True) if isinstance(ln, str) else ln for ln in lines]
            metrics = f.get("metrics")
            if isinstance(metrics, dict):
                f["metrics"] = r.walk(metrics, names=True)
