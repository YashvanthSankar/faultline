"""Regenerate every image and example used in the README, straight from the tool.

Nothing in docs/images or docs/examples is hand-made: this script runs the real
CLI / renderer on the bundled samples and records the output.

    python scripts/make_assets.py            # terminal SVGs, example reports, benchmark
    python scripts/make_assets.py --shots    # + browser screenshots (needs Google Chrome)
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from rich.console import Console  # noqa: E402
from rich.terminal_theme import MONOKAI  # noqa: E402

from faultline.cli import build_parser, print_report  # noqa: E402
from faultline.engine import AnalyzeOptions, analyze  # noqa: E402
from faultline.report.html import render_html  # noqa: E402

IMAGES = os.path.join(ROOT, "docs", "images")
EXAMPLES = os.path.join(ROOT, "docs", "examples")
SAMPLES = os.path.join(ROOT, "samples")

TERMINAL = [
    ("mitm_chain.pcap", "terminal-mitm.svg", False),
    ("lossy_link.pcap", "terminal-lossy.svg", False),
    ("arp_spoofing.pcap", "terminal-arp-spoofing.svg", False),
    ("ip_conflict.pcap", "terminal-ip-conflict.svg", False),
    ("clean_office.pcap", "terminal-healthy.svg", False),
]
EXAMPLE_REPORTS = ["mitm_chain.pcap", "lossy_link.pcap", "outage_vs_attack_mixed.pcap", "clean_office.pcap"]
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"


def terminal_svg(sample: str, out: str, expert: bool) -> None:
    rep = analyze(os.path.join(SAMPLES, sample), AnalyzeOptions()).to_dict()
    con = Console(record=True, width=110, force_terminal=True, color_system="truecolor")
    con.print(f"[bold green]$[/] faultline analyze samples/{sample}")
    print_report(con, rep, expert=expert)
    con.save_svg(os.path.join(IMAGES, out), title=f"faultline analyze samples/{sample}", theme=MONOKAI)
    print("  wrote", os.path.join("docs/images", out))


def bench_svg() -> None:
    con = Console(record=True, width=150, force_terminal=True, color_system="truecolor")
    con.print("[bold green]$[/] faultline bench")
    import faultline.cli as cli

    orig = cli._console
    cli._console = lambda no_color=False: con  # record the real command's output
    try:
        args = build_parser().parse_args(["bench", SAMPLES])
        args.func(args)
    finally:
        cli._console = orig
    con.save_svg(os.path.join(IMAGES, "terminal-bench.svg"), title="faultline bench", theme=MONOKAI)
    print("  wrote docs/images/terminal-bench.svg")


def examples() -> None:
    for sample in EXAMPLE_REPORTS:
        rep = analyze(os.path.join(SAMPLES, sample), AnalyzeOptions()).to_dict()
        base = os.path.splitext(sample)[0]
        with open(os.path.join(EXAMPLES, f"{base}.html"), "w", encoding="utf-8") as fh:
            fh.write(render_html(rep))
        print("  wrote", f"docs/examples/{base}.html")
    rep = analyze(os.path.join(SAMPLES, "mitm_chain.pcap"), AnalyzeOptions(redact=True)).to_dict()
    with open(os.path.join(EXAMPLES, "mitm_chain.redacted.json"), "w", encoding="utf-8") as fh:
        json.dump(rep, fh, indent=2, default=str)
    print("  wrote docs/examples/mitm_chain.redacted.json")


def shots() -> None:
    if not os.path.exists(CHROME):
        print("  (skipping screenshots: Google Chrome not found)")
        return
    for name, w, h in (("mitm_chain", 1440, 900), ("lossy_link", 1440, 900), ("outage_vs_attack_mixed", 1440, 900)):
        src = os.path.join(EXAMPLES, f"{name}.html")
        out = os.path.join(IMAGES, f"report-{name}.png")
        subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--virtual-time-budget=5000",
                        f"--window-size={w},{h}", f"--screenshot={out}", "file://" + src],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=60)
        print("  wrote", os.path.relpath(out, ROOT))
    # a long, full-page shot of the attack report for the README "tour"
    out = os.path.join(IMAGES, "report-mitm_chain-full.png")
    subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--virtual-time-budget=5000",
                    "--window-size=1440,2400", f"--screenshot={out}", "file://" + os.path.join(EXAMPLES, "mitm_chain.html")],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=60)
    print("  wrote", os.path.relpath(out, ROOT))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--shots", action="store_true", help="also take browser screenshots (needs Chrome)")
    args = ap.parse_args()
    os.makedirs(IMAGES, exist_ok=True)
    os.makedirs(EXAMPLES, exist_ok=True)
    for sample, out, expert in TERMINAL:
        terminal_svg(sample, out, expert)
    bench_svg()
    examples()
    if args.shots:
        shots()


if __name__ == "__main__":
    main()
