"""Record the real output of every verification command as terminal screenshots (SVG).

Each image in docs/proof/ is the *actual* stdout/stderr of the command shown in
its title bar, captured live by running it in a subprocess (colours preserved).
Nothing is typed or edited by hand: re-run this script and you get the same images.

    python scripts/make_proof.py                       # all proofs
    python scripts/make_proof.py --public-dir DIR      # reuse downloaded public captures
"""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from rich.console import Console  # noqa: E402
from rich.terminal_theme import MONOKAI  # noqa: E402
from rich.text import Text  # noqa: E402

OUT = os.path.join(ROOT, "docs", "proof")
PY = sys.executable
FL = [PY, "-m", "faultline"]


def record(name: str, title: str, commands: list[tuple[str, list[str]]], width: int = 120, tail: int | None = None) -> None:
    """Run each command, capture its real output, and save one terminal-window SVG."""
    env = dict(os.environ, FORCE_COLOR="1", COLUMNS=str(width), TERM="xterm-256color", PYTHONIOENCODING="utf-8")
    env.pop("NO_COLOR", None)
    con = Console(record=True, width=width, force_terminal=True, color_system="truecolor", highlight=False)
    for shown, argv in commands:
        con.print(Text("$ ", style="bold green") + Text(shown, style="bold"))
        t0 = time.perf_counter()
        proc = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True, text=True, timeout=900)
        out = (proc.stdout + proc.stderr).rstrip("\n")
        lines = out.splitlines()
        if tail and len(lines) > tail:
            con.print(Text(f"… ({len(lines) - tail} earlier lines omitted; run the command to see them all)", style="dim"))
            lines = lines[-tail:]
        con.print(Text.from_ansi("\n".join(lines)))
        con.print(Text(f"[exit code {proc.returncode} · {time.perf_counter() - t0:.1f}s]", style="dim"))
        con.print()
    os.makedirs(OUT, exist_ok=True)
    con.save_svg(os.path.join(OUT, name), title=title, theme=MONOKAI)
    print("  wrote", os.path.relpath(os.path.join(OUT, name), ROOT))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--public-dir", help="directory with already-downloaded public captures")
    args = ap.parse_args()

    record("tests.svg", "pytest: full test suite",
           [("python -m pytest -q", [PY, "-m", "pytest", "-q", "--color=yes", "-p", "no:cacheprovider"])], tail=12)
    record("benchmark.svg", "faultline bench: 37 labelled captures",
           [("faultline bench", FL + ["bench"])], width=150)
    record("fuzz.svg", "fuzzing the whole pipeline with 3,000 corrupted captures",
           [("python scripts/fuzz.py -n 3000 --seed 42", [PY, "scripts/fuzz.py", "-n", "3000", "--seed", "42"])])
    pub = ["scripts/validate_public.py"] + (["--dir", args.public_dir] if args.public_dir else [])
    record("public-captures.svg", "real-world validation on public Wireshark sample captures",
           [("python " + " ".join(shlex.quote(p) for p in pub[:1]), [PY] + pub)], width=150)
    record("hostile-files.svg", "hostile and broken input: clean errors, never a traceback",
           [("faultline analyze samples/malformed/bad_magic.pcap", FL + ["analyze", "samples/malformed/bad_magic.pcap"]),
            ("faultline analyze samples/malformed/zero_length.pcap", FL + ["analyze", "samples/malformed/zero_length.pcap"]),
            ("faultline analyze /etc", FL + ["analyze", "/etc"]),
            ("faultline analyze samples/malformed/huge_caplen.pcap  # record claims 2 GiB",
             FL + ["analyze", "samples/malformed/huge_caplen.pcap"])], width=110)
    record("redaction.svg", "--redact: shareable report with every IP and MAC pseudonymised",
           [("faultline analyze samples/arp_spoofing.pcap --redact", FL + ["analyze", "samples/arp_spoofing.pcap", "--redact"])],
           width=110, tail=34)
    record("secrets.svg", "no hardcoded secrets",
           [("python scripts/check_secrets.py", [PY, "scripts/check_secrets.py"]),
            ("grep -rnE 'eval\\(|pickle|os\\.system|subprocess' faultline/ | wc -l",
             ["bash", "-c", "grep -rnE 'eval\\(|pickle|os\\.system|subprocess' faultline/ | wc -l"])])


if __name__ == "__main__":
    main()
