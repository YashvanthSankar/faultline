"""Tests for faultline.report.redact."""

from __future__ import annotations

import copy
import json
import re

import pytest

from faultline.report.redact import IPV4_RE, MAC_RE, Redactor, redact_report

KEY = b"\x01" * 32
LABEL = re.compile(r"^(lan|inet|lan6|inet6)-host-[0-9a-f]{6}$")


def sample_report() -> dict:
    return {
        "capture": {"name": "office.pcap", "packets": 1200, "warnings": []},
        "hosts": [
            {"ip": "192.168.1.15", "mac": "aa:bb:cc:dd:ee:01", "names": ["laptop-yash.lan", "yash.local"], "role": "client"},
            {"ip": "192.168.1.1", "mac": "AA-BB-CC-DD-EE-FF", "names": [], "role": "gateway"},
            {"ip": "8.8.8.8", "mac": None, "names": ["dns.google"], "role": "dns"},
            {"ip": "fe80::1", "mac": "00:11:22:33:44:55", "names": []},
            {"ip": "2001:db8::5", "mac": "00:11:22:33:44:66", "names": []},
        ],
        "findings": [
            {
                "id": "f1",
                "kind": "arp.spoofing",
                "title": "ARP spoofing of the gateway 192.168.1.1",
                "summary": "aa:bb:cc:dd:ee:01 claims 192.168.1.1 (real gateway MAC AA-BB-CC-DD-EE-FF)",
                "explanation": "Host 192.168.1.15 sent 240 unsolicited ARP replies to ff:ff:ff:ff:ff:ff. "
                               "TLS 1.2 and version 1.0.0 were unaffected; timestamps like 12:30:45.123 too.",
                "hosts": ["192.168.1.15", "192.168.1.1"],
                "packets": [1, 2, 3],
                "metrics": {"replies": 240, "victim": "192.168.1.1", "resolver": "dns.google", "rate": 1.5},
                "evidence_lines": [
                    {"no": 1, "summary": "TCP 192.168.1.15:443 → 8.8.8.8:53 [S] seq=1"},
                    {"no": 2, "summary": "DNS query www.example.com (192.168.1.15 → 8.8.8.8)"},
                    {"no": 3, "summary": "ICMPv6 fe80::1 → ff02::1"},
                ],
                "by_host": {"192.168.1.15": 240, "192.168.1.1": 0},
            }
        ],
        "evidence": {"f1": b"\xd4\xc3\xb2\xa1 pcap bytes"},
        "health": 42,
    }


def test_returns_deep_copy_and_flags():
    rep = sample_report()
    before = copy.deepcopy(rep)
    out = redact_report(rep, KEY)
    assert rep == before, "input must not be mutated"
    assert out is not rep
    assert out["redacted"] is True
    assert "evidence" not in out
    assert out["health"] == 42 and out["capture"]["packets"] == 1200


def test_every_address_gone_and_consistent():
    out = redact_report(sample_report(), KEY)
    dump = json.dumps(out, default=str)
    for leaked in ("192.168.1.15", "192.168.1.1", "8.8.8.8", "aa:bb:cc:dd:ee:01", "AA-BB-CC-DD-EE-FF",
                   "aa-bb-cc-dd-ee-ff", "fe80::1", "2001:db8::5", "00:11:22:33:44:55"):
        assert leaked.lower() not in dump.lower(), leaked
    # consistency: the laptop's pseudonym is the same everywhere
    lap = out["hosts"][0]["ip"]
    assert LABEL.match(lap) and lap.startswith("lan-host-")
    assert out["findings"][0]["hosts"][0] == lap
    assert lap in out["findings"][0]["explanation"]
    assert out["findings"][0]["evidence_lines"][0]["summary"].startswith(f"TCP {lap}:443 → ")
    assert lap in out["findings"][0]["by_host"], "dict keys are redacted too"
    assert out["findings"][0]["by_host"][lap] == 240
    # local vs internet distinction and role survive
    assert out["hosts"][2]["ip"].startswith("inet-host-")
    assert out["hosts"][1]["role"] == "gateway"
    # colon and dash MAC forms map to one pseudonym
    gw_mac = out["hosts"][1]["mac"]
    assert gw_mac.startswith("mac-") and gw_mac in out["findings"][0]["summary"]
    # IPv6 forms
    assert out["hosts"][3]["ip"].startswith("lan6-host-")
    assert out["hosts"][4]["ip"].startswith(("lan6-host-", "inet6-host-"))


def test_irreversible_key_never_in_output_and_differs_per_key():
    rep = sample_report()
    a = redact_report(rep, KEY)
    b = redact_report(rep, b"\x02" * 32)
    c = redact_report(rep)  # random key
    assert a["hosts"][0]["ip"] != b["hosts"][0]["ip"] != c["hosts"][0]["ip"]
    dump = json.dumps(a, default=str)
    assert KEY.hex() not in dump and "0101" * 4 not in dump
    # deterministic for the same key (the HMAC is keyed, not random per call)
    assert redact_report(rep, KEY) == a


def test_special_addresses_kept():
    s = ("0.0.0.0 255.255.255.255 127.0.0.1 224.0.0.251 239.255.255.250 ff:ff:ff:ff:ff:ff "
         "00:00:00:00:00:00 01:00:5e:00:00:fb 33:33:00:00:00:01 ::1 :: ff02::1 ff02::fb")
    assert Redactor(KEY).text(s) == s


@pytest.mark.parametrize("text", [
    "TLS 1.2", "version 1.0.0", "v2.4", "1.2.3", "12:30:45", "12:30:45.123456", "2024-01-01T10:00:00",
    "port 443", "seq=1234567890", "1.2.3.4.5", "999.1.1.1", "256.1.1.1", "10.0.0.1.2", "a:b:c",
    "deadbeef", "00:11", "mss=1460 win=65535", "ttl 64", "10.0.0", "x.y.z",
])
def test_no_false_positives(text):
    assert Redactor(KEY).text(text) == text


@pytest.mark.parametrize("text,kind", [
    ("10.0.0.1", "lan-host-"), ("172.16.5.5", "lan-host-"), ("169.254.1.1", "lan-host-"),
    ("1.1.1.1", "inet-host-"), ("93.184.216.34", "inet-host-"),
    ("fe80::1", "lan6-host-"), ("2606:4700::1111", "inet6-host-"),
    ("2001:0db8:0000:0000:0000:0000:0000:0001", "inet6-host-"),
    ("::ffff:8.8.8.8", "inet-host-"),
])
def test_single_addresses(text, kind):
    out = Redactor(KEY).text(text)
    assert out.startswith(kind) and LABEL.match(out), out


def test_embedded_forms():
    r = Redactor(KEY)
    out = r.text("from 192.168.1.15:443 to (8.8.8.8) and [2001:db8::5]:53, mac 7c-1e-22-33-44-55.")
    assert out.startswith("from lan-host-") and ":443 to (inet-host-" in out
    assert "[inet6-host-" in out and "]:53" in out
    assert "mac mac-" in out and out.endswith(".")
    assert not IPV4_RE.search(out) and not MAC_RE.search(out)


def test_nested_structures_and_odd_types():
    rep = {
        "a": [{"b": ("10.0.0.1", 5)}, {"c": {"10.0.0.1", "x"}}, frozenset({"10.0.0.2"})],
        "d": {"10.0.0.1": {"e": [[["8.8.8.8"]]]}},
        "n": None, "f": 1.5, "i": 7, "bool": True,
        "bytes": b"\x00\x01", "obj": object(),
        "evidence": [1, 2, 3],
    }
    out = redact_report(rep, KEY)
    assert isinstance(out["a"][0]["b"], tuple) and out["a"][0]["b"][1] == 5
    assert out["a"][0]["b"][0].startswith("lan-host-")
    assert isinstance(out["a"][1]["c"], set) and "x" in out["a"][1]["c"]
    assert isinstance(out["a"][2], frozenset)
    key = next(iter(out["d"]))
    assert key.startswith("lan-host-") and out["d"][key]["e"][0][0][0].startswith("inet-host-")
    assert out["n"] is None and out["f"] == 1.5 and out["i"] == 7 and out["bool"] is True
    assert out["bytes"] == "<2 bytes removed>"
    assert out["obj"] is rep["obj"]
    assert "evidence" not in out and out["redacted"] is True


def test_non_dict_input_does_not_crash():
    out = redact_report(["10.0.0.1"], KEY)  # type: ignore[arg-type]
    assert out["redacted"] is True and out["report"][0].startswith("lan-host-")
    assert redact_report({}, KEY) == {"redacted": True}


def test_names_not_redacted_by_default_but_optional():
    rep = sample_report()
    out = redact_report(rep, KEY)
    assert out["hosts"][0]["names"] == ["laptop-yash.lan", "yash.local"]
    assert "www.example.com" in out["findings"][0]["evidence_lines"][1]["summary"]
    assert out["findings"][0]["metrics"]["resolver"] == "dns.google"

    out2 = redact_report(rep, KEY, redact_names=True)
    dump = json.dumps(out2)
    for n in ("laptop-yash.lan", "yash.local", "dns.google", "www.example.com"):
        assert n not in dump, n
    assert all(x.startswith("name-") for x in out2["hosts"][0]["names"])
    assert out2["findings"][0]["metrics"]["resolver"].startswith("name-")
    # same name → same pseudonym across fields
    assert out2["hosts"][2]["names"][0] == out2["findings"][0]["metrics"]["resolver"]
    assert out2["findings"][0]["metrics"]["replies"] == 240
    # prose in other fields is not touched by name redaction
    assert "TLS 1.2 and version 1.0.0" in out2["findings"][0]["explanation"]


def test_bad_key_rejected():
    with pytest.raises(ValueError):
        Redactor(b"short")


def test_collision_resistance_on_many_hosts():
    r = Redactor(KEY)
    labels = {r.ip(f"10.{i >> 8}.{i & 255}.7") for i in range(2000)}
    assert len(labels) >= 1990  # 24-bit labels: a handful of collisions at most
