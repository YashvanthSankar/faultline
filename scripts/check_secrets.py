#!/usr/bin/env python3
"""Tiny secret scanner for the Faultline repository (standard library only).

    .venv/bin/python scripts/check_secrets.py            # scan tracked / project text files
    .venv/bin/python scripts/check_secrets.py --all      # include ignored files too

Looks for: AWS access keys, private-key PEM headers, GitHub / Slack / Google /
Stripe style tokens, JWTs, generic ``password = "literal"`` / ``api_key: 'literal'``
assignments, ``user:pass@host`` URLs and high-entropy string literals assigned
to secret-looking names. Exits 1 on any hit.

Allowlist: obviously fake demo credentials used by the lab and the tests
(``hunter2``, ``password``, ``admin``, ``secret``, ``changeme``, ``example`` ...)
and the markers ``# nosecret`` / ``nosec`` on the same line.
"""

from __future__ import annotations

import argparse
import math
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TEXT_EXT = {".py", ".md", ".txt", ".toml", ".cfg", ".ini", ".json", ".yaml", ".yml", ".html", ".js", ".css",
            ".env", ".sh", ".j2", ".jinja", ".csv", ".xml", ".svg", ""}
SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules", "build", "dist", "out", ".mypy_cache"}
SKIP_FILES = {"check_secrets.py"}  # this file contains the patterns themselves
BINARY_EXT = {".pcap", ".pcapng", ".gz", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".pyc", ".zip"}

# (name, regex) -- all case-insensitive where it makes sense
PATTERNS = [
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("AWS secret key assignment", re.compile(r"(?i)aws(?:.{0,20})?secret(?:.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]")),
    ("private key header", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("Slack token", re.compile(r"\bxox[abpors]-[0-9A-Za-z-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Stripe key", re.compile(r"\b[sr]k_(?:live|test)_[0-9a-zA-Z]{20,}\b")),
    ("OpenAI-style key", re.compile(r"\bsk-[A-Za-z0-9]{32,}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("credentials in URL", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/:@'\"]+:[^\s/@'\"]+@[^\s'\"]+", re.I)),
    ("generic secret assignment",
     re.compile(r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?token|"
                r"secret[_-]?key|private[_-]?key|client[_-]?secret)\b\s*[:=]\s*['\"]([^'\"\s]{4,})['\"]")),
]
HIGH_ENTROPY_ASSIGN = re.compile(
    r"(?i)\b(?:key|token|secret|password|passwd|credential|salt|auth)\w*\s*[:=]\s*['\"]([A-Za-z0-9+/=_\-]{20,})['\"]")

FAKE_VALUES = {"hunter2", "password", "passw0rd", "admin", "secret", "changeme", "letmein", "example", "test",
               "redacted", "xxxx", "dummy", "fake", "demo", "placeholder", "s3cret", "qwerty", "123456", "guest",
               "anonymous", "user", "root", "toor", "pass", "none", "null", "true", "false"}
FAKE_PREFIXES = ("hunter", "fake", "dummy", "example", "test", "demo", "lab", "sample", "placeholder", "xxx", "your_", "<", "${", "%(")
ALLOW_MARKERS = ("nosecret", "nosec", "allowlist", "pragma: allowlist")
# demo credentials are expected in these places (they are the thing we detect, never store)
ALLOW_PATH_PARTS = ("/tests/", "/faultline/lab/", "/samples/", "SECURITY.md", "README.md", "tech.md", "idea.md")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def tracked_files(include_all: bool) -> list[str]:
    files: list[str] = []
    if not include_all:
        try:
            out = subprocess.run(["git", "-C", ROOT, "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                                 capture_output=True, check=True, timeout=30).stdout
            files = [os.path.join(ROOT, f.decode()) for f in out.split(b"\0") if f]
        except (OSError, subprocess.SubprocessError):
            files = []
    if not files:
        for dirpath, dirnames, filenames in os.walk(ROOT):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            files.extend(os.path.join(dirpath, f) for f in filenames)
    return sorted(set(files))


def is_text_candidate(path: str) -> bool:
    base = os.path.basename(path)
    ext = os.path.splitext(base)[1].lower()
    if base in SKIP_FILES or ext in BINARY_EXT:
        return False
    if any(f"/{d}/" in path.replace(os.sep, "/") + "/" for d in SKIP_DIRS):
        return False
    return ext in TEXT_EXT or base.startswith(".env")


def looks_fake(value: str, path: str, line: str) -> bool:
    v = value.lower().strip()
    if any(m in line.lower() for m in ALLOW_MARKERS):
        return True
    if v in FAKE_VALUES or v.startswith(FAKE_PREFIXES) or set(v) <= set("x*.-_0") or v.startswith("$"):
        return True
    if v.startswith("{{") or v.startswith("{") or v.startswith("os.environ"):
        return True
    # base64 of a fake credential ("user:s3cr3t", "admin:hunter2") used as a test vector
    try:
        import base64 as _b64
        decoded = _b64.b64decode(value + "=" * (-len(value) % 4), validate=True).decode("ascii").lower()
        if any(w in decoded for w in ("hunter", "s3cr", "secret", "example", "test", "demo", "admin:", "user:")):
            return True
    except Exception:
        pass
    posix = path.replace(os.sep, "/")
    if any(part in posix for part in ALLOW_PATH_PARTS) and (v in FAKE_VALUES or any(w in v for w in ("hunter", "demo", "lab", "test", "example"))):
        return True
    return False


def scan_file(path: str) -> list[tuple[int, str, str]]:
    hits: list[tuple[int, str, str]] = []
    try:
        with open(path, "rb") as fh:
            raw = fh.read(2 * 1024 * 1024)
    except OSError:
        return hits
    if b"\x00" in raw[:4096]:
        return hits  # binary
    text = raw.decode("utf-8", "replace")
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 2000:
            continue  # minified blobs: skip, do not stall
        for name, rx in PATTERNS:
            for m in rx.finditer(line):
                value = m.group(1) if m.groups() else m.group(0)
                if name == "generic secret assignment" and looks_fake(value, path, line):
                    continue
                if name == "credentials in URL" and looks_fake(value.split("://", 1)[-1].split("@")[0].split(":")[-1], path, line):
                    continue
                if any(mk in line.lower() for mk in ALLOW_MARKERS):
                    continue
                hits.append((lineno, name, line.strip()[:160]))
        for m in HIGH_ENTROPY_ASSIGN.finditer(line):
            value = m.group(1)
            if looks_fake(value, path, line):
                continue
            if shannon_entropy(value) >= 4.0 and not value.isalpha():
                hits.append((lineno, "high-entropy literal in secret-looking assignment", line.strip()[:160]))
    return hits


def main() -> int:
    ap = argparse.ArgumentParser(description="Scan the repository for hardcoded secrets.")
    ap.add_argument("--all", action="store_true", help="scan every file under the repo, not only tracked/untracked-unignored ones")
    ap.add_argument("paths", nargs="*", help="limit the scan to these files/directories")
    args = ap.parse_args()

    files = tracked_files(args.all)
    if args.paths:
        wanted = [os.path.abspath(p) for p in args.paths]
        files = [f for f in files if any(f == w or f.startswith(w.rstrip(os.sep) + os.sep) for w in wanted)]
    files = [f for f in files if is_text_candidate(f) and os.path.isfile(f)]

    total_hits = 0
    for f in files:
        for lineno, name, line in scan_file(f):
            total_hits += 1
            print(f"{os.path.relpath(f, ROOT)}:{lineno}: [{name}] {line}")
    print(f"\nscanned {len(files)} text files, {total_hits} potential secret(s) found: "
          + ("FAIL" if total_hits else "PASS"))
    return 1 if total_hits else 0


if __name__ == "__main__":
    sys.exit(main())
