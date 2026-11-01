"""Command-line interface.

    faultline analyze capture.pcap [--html report.html] [--json out.json] [--redact] [--expert]
    faultline web [--port 8765]
    faultline diff before.pcap after.pcap
    faultline lab samples/
    faultline bench [samples/]

Exit codes: 0 success · 1 ``--fail-on`` condition met · 2 unusable input / usage error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime

from . import __version__

CAT_STYLE = {"attack": "bold red", "fault": "bold yellow", "misconfig": "bold cyan", "info": "dim"}
CAT_LABEL = {"attack": "ATTACK", "fault": "FAULT", "misconfig": "MISCONFIG", "info": "INFO"}
STATUS_STYLE = {
    "under_attack": ("white on red", "UNDER ATTACK"),
    "faulty": ("black on yellow", "FAULTY"),
    "minor_issues": ("black on cyan", "MINOR ISSUES"),
    "healthy": ("black on green", "HEALTHY"),
}
SEV_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _console(no_color: bool = False):
    from rich.console import Console

    return Console(highlight=False, no_color=no_color, soft_wrap=False)


def _safe(text) -> str:
    """Capture-derived text must never be interpreted as rich markup or terminal escapes."""
    from rich.markup import escape

    s = str(text)
    s = re.sub(r"[\x00-\x08\x0b-\x1f\x7f\x1b]", "?", s)  # strip control chars / ANSI escapes
    return escape(s)


def _code(text: str) -> str:
    """Render `inline code` spans in fix steps (input is escaped first)."""
    return re.sub(r"`([^`]+)`", r"[bold green]\1[/]", _safe(text))


def _ts(ts) -> str:
    if ts is None:
        return "?"
    try:
        return datetime.fromtimestamp(ts).strftime("%H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return "?"


# --------------------------------------------------------------------------- #
# analyze
# --------------------------------------------------------------------------- #


def cmd_analyze(args) -> int:
    from .capture.reader import CaptureError
    from .engine import AnalyzeOptions, analyze

    con = _console(args.no_color)
    if not os.path.exists(args.capture):
        con.print(f"[red]error:[/] no such file: {_safe(args.capture)}")
        return 2
    opts = AnalyzeOptions(redact=args.redact, sensitivity=args.sensitivity, max_packets=args.max_packets,
                          evidence=not args.no_evidence)
    try:
        if args.quiet or args.json == "-":
            report = analyze(args.capture, opts)
        else:
            with con.status(f"[bold]Analysing[/] {_safe(os.path.basename(args.capture))} …", spinner="dots") as st:
                report = analyze(args.capture, opts, progress=lambda n: st.update(f"[bold]Analysing[/] … {n:,} packets"))
    except CaptureError as exc:
        con.print(f"[red bold]Cannot analyse this file:[/] {_safe(exc)}")
        return 2
    data = report.to_dict()

    if args.json:
        text = json.dumps(data, indent=2, default=str)
        if args.json == "-":
            sys.stdout.write(text + "\n")
        else:
            _write_private(args.json, text)
    if args.html:
        from .report.html import render_html

        _write_private(args.html, render_html(data))
    if args.evidence_dir:
        _write_evidence(data, args.evidence_dir)

    if args.json != "-" and not args.quiet:
        print_report(con, data, expert=args.expert)
        outputs = [p for p in (args.html, args.json if args.json != "-" else None) if p]
        for p in outputs:
            con.print(f"[dim]→ wrote[/] {_safe(p)}")
        if args.evidence_dir:
            con.print(f"[dim]→ evidence pcaps in[/] {_safe(args.evidence_dir)}")

    return _exit_code(data, args.fail_on)


def _write_private(path: str, text: str) -> None:
    """Reports can contain network details: create them readable by the owner only."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)


def _write_evidence(data: dict, outdir: str) -> None:
    import base64

    os.makedirs(outdir, mode=0o700, exist_ok=True)
    for fid, b64 in (data.get("evidence") or {}).items():
        if not re.fullmatch(r"F\d{1,5}", fid):
            continue
        kind = next((f["kind"] for f in data["findings"] if f["id"] == fid), "finding")
        name = re.sub(r"[^a-z0-9_.-]", "_", f"{fid}-{kind}.pcap".lower())
        fd = os.open(os.path.join(outdir, name), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(base64.b64decode(b64))


def _exit_code(data: dict, fail_on: str) -> int:
    if fail_on == "never":
        return 0
    cats = {f["category"] for f in data["findings"] if f["severity"] >= 2}
    if fail_on == "attack" and "attack" in cats:
        return 1
    if fail_on == "fault" and cats & {"fault", "misconfig"}:
        return 1
    if fail_on == "any" and cats:
        return 1
    return 0


def print_report(con, data: dict, expert: bool = False) -> None:
    from rich import box
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    v = data["verdict"]
    cap = data["capture"]
    style, label = STATUS_STYLE.get(v["status"], ("bold", v["status"]))
    score = v["score"]
    bar_len = 30
    filled = round(score / 100 * bar_len)
    score_col = "green" if score >= 80 else "yellow" if score >= 50 else "red"

    head = Text()
    head.append(f" {label} ", style=style)
    head.append("  ")
    head.append(v["headline"], style="bold")
    body = Text()
    body.append(v["summary"] + "\n\n")
    body.append("Health  ")
    body.append("█" * filled, style=score_col)
    body.append("░" * (bar_len - filled), style="dim")
    body.append(f"  {score}/100", style=f"bold {score_col}")
    c = v["counts"]
    body.append("\n")
    body.append(f"Found   {c['attack']} attack{'s' if c['attack'] != 1 else ''}", style="bold red" if c["attack"] else "dim")
    body.append("  ·  ", style="dim")
    body.append(f"{c['fault']} fault{'s' if c['fault'] != 1 else ''}", style="bold yellow" if c["fault"] else "dim")
    body.append("  ·  ", style="dim")
    body.append(f"{c['misconfig']} misconfiguration{'s' if c['misconfig'] != 1 else ''}\n",
                style="bold cyan" if c["misconfig"] else "dim")
    dur = cap.get("duration") or 0
    body.append(
        f"{cap['name']} · {cap['format']} · {cap['packets']:,} packets · {dur:.1f}s · analysed in {data.get('analysis_seconds', 0):.2f}s",
        style="dim",
    )
    if data.get("redacted"):
        body.append("  · addresses redacted", style="dim magenta")
    con.print()
    con.print(Panel(body, title=head, title_align="left", box=box.HEAVY, border_style=style.split()[-1], padding=(1, 2)))

    findings = data["findings"]
    by_id = {f["id"]: f for f in findings}

    if data["incidents"]:
        con.print(Text(" FIX THIS FIRST ", style="bold black on white"))
        for inc in data["incidents"]:
            st = CAT_STYLE.get(inc["category"], "bold")
            t = Text()
            t.append(f"{inc['id']}  ", style="dim")
            t.append(inc["title"], style=st)
            con.print(t)
            con.print(f"    {_safe(inc['story'])}")
            root = by_id.get(inc["root_cause"])
            if root:
                con.print(f"    [dim]root cause[/] {root['id']} {_safe(root['title'])}")
            for fid in inc["findings"][1:]:
                f = by_id.get(fid)
                if f:
                    con.print(f"    [dim]  └─ consequence[/] {f['id']} {_safe(f['title'])}")
            for i, step in enumerate(inc["first_fix"], 1):
                con.print(f"    [bold]{i}.[/] {_code(step)}")
            con.print()

    shown = [f for f in findings if f["severity"] >= 1 or expert]
    if not shown:
        con.print("[green]No problems to report.[/] Use [bold]--expert[/] to see informational notes.\n")
    for f in shown:
        _print_finding(con, f, expert)

    if data.get("warnings"):
        con.print(Text(" NOTES ON THE CAPTURE FILE ", style="bold black on white"))
        for w in data["warnings"][:10]:
            con.print(f"  [yellow]![/] {_safe(w)}")
        con.print()

    if expert and data["hosts"]:
        t = Table(title="Hosts", box=box.SIMPLE_HEAD, show_lines=False)
        for col in ("IP", "MAC", "Roles", "Sent", "Recv"):
            t.add_column(col)
        for h in data["hosts"][:15]:
            t.add_row(_safe(h["ip"]), _safe(", ".join(h["macs"][:2])), _safe(", ".join(h["roles"])),
                      f"{h['packets_sent']:,}", f"{h['packets_recv']:,}")
        con.print(t)
    con.print("[dim]Tip: --html report.html for the full interactive report · faultline web for the dashboard · --expert for details[/]\n")


def _print_finding(con, f: dict, expert: bool) -> None:
    from rich.panel import Panel
    from rich.text import Text

    cat = f["category"]
    st = CAT_STYLE.get(cat, "bold")
    title = Text()
    title.append(f" {CAT_LABEL.get(cat, cat.upper())} ", style=f"reverse {st}")
    title.append(f" {f['confidence'] * 100:.0f}% ", style="dim")
    title.append(f" {f['severity_name'].upper()} ", style=SEV_STYLE.get(f["severity_name"], ""))
    title.append(f" {f['id']}  ", style="dim")
    title.append(f["title"], style="bold")

    lines: list[str] = [f"[bold]{_safe(f['summary'])}[/]"]
    if f.get("symptom_of"):
        lines.append(f"[dim]↳ consequence of {f['symptom_of']}; fixing that should fix this too[/]")
    lines.append("")
    lines.append(f"[bold]What's happening[/]  {_safe(f['explanation'])}")
    if f.get("analogy"):
        lines.append(f"[italic dim]{_safe(f['analogy'])}[/]")
    lines.append(f"[bold]Likely cause[/]  {_safe(f['cause'])}")
    lines.append("[bold]How to fix[/]")
    for i, step in enumerate(f["fix"][:6], 1):
        lines.append(f"  {i}. {_code(step)}")

    if cat in ("attack", "fault", "misconfig") and (f.get("alternatives") or f.get("indicators")):
        word = {"attack": "an attack", "fault": "a fault", "misconfig": "a misconfiguration"}[cat]
        lines.append(f"[bold]Why we think it's {word}[/]")
        pro = sorted((i for i in f["indicators"] if i["supports"] == cat), key=lambda i: -i["weight"])
        for ind in pro[: (6 if expert else 3)]:
            dots = "●" * max(1, min(3, round(ind["weight"])))
            lines.append(f"  [{st.split()[-1]}]{dots:<3}[/] {_safe(ind['text'])}")
        for alt in f.get("alternatives", [])[:2]:
            lines.append(f"  [bold dim]Why not “{_safe(alt['title'] or alt['category'])}”?[/] [dim]{_safe(alt['why_not'])}[/]")
    if f.get("mitre"):
        lines.append(f"[bold]MITRE ATT&CK[/]  {_safe(f['mitre'])}")

    pk = f.get("packets", [])
    if pk:
        shown = ", ".join(f"#{n}" for n in pk[:12])
        more = f" … ({f['packet_total']:,} total)" if f["packet_total"] > len(pk[:12]) else ""
        lines.append(f"[bold]Evidence[/]  frames {shown}{more}")
        for ev in f.get("evidence_lines", [])[: (8 if expert else 3)]:
            lines.append(f"  [dim]#{ev['no']:<6} +{ev['rel']:>9.3f}s[/] {_safe(ev['summary'])}")
        lines.append(f"  [dim]Wireshark filter:[/] frame.number in {{{' '.join(str(n) for n in pk[:30])}}}")
    if f.get("hosts"):
        lines.append(f"[bold]Hosts[/]  {_safe(', '.join(f['hosts'][:8]))}")
    if expert and f.get("technical"):
        lines.append(f"[bold]Technical[/]  {_safe(f['technical'])}")

    border = st.split()[-1] if cat != "info" else "grey50"
    con.print(Panel("\n".join(lines), title=title, title_align="left", border_style=border, padding=(0, 1)))
    con.print()


# --------------------------------------------------------------------------- #
# other commands
# --------------------------------------------------------------------------- #


def cmd_web(args) -> int:
    from .web.app import run

    run(host=args.host, port=args.port, open_browser=not args.no_browser)
    return 0


def cmd_diff(args) -> int:
    from rich.text import Text

    from .capture.reader import CaptureError
    from .diff import diff_reports
    from .engine import AnalyzeOptions, analyze

    con = _console(args.no_color)
    try:
        with con.status("Analysing both captures …"):
            a = analyze(args.before, AnalyzeOptions(evidence=False, sensitivity=args.sensitivity)).to_dict()
            b = analyze(args.after, AnalyzeOptions(evidence=False, sensitivity=args.sensitivity)).to_dict()
    except CaptureError as exc:
        con.print(f"[red bold]Cannot analyse:[/] {_safe(exc)}")
        return 2
    d = diff_reports(a, b)
    if args.json:
        print(json.dumps(d, indent=2, default=str))
        return 0
    con.print()
    con.print(Text(" BEFORE → AFTER ", style="bold black on white"))
    con.print(f"  {_safe(d['before']['name'])}: {d['before']['status']} ({d['before']['score']}/100)  →  "
              f"{_safe(d['after']['name'])}: {d['after']['status']} ({d['after']['score']}/100)")
    con.print(f"\n  [bold]{_safe(d['conclusion'])}[/]\n")
    for f in d["fixed"]:
        con.print(f"  [green]✔ fixed[/]      {_safe(f['title'])}")
    for p in d["persisting"]:
        col = {"better": "cyan", "worse": "red", "same": "yellow"}[p["trend"]]
        con.print(f"  [{col}]● {p['trend']:<10}[/] {_safe(p['after']['title'])}")
    for f in d["new"]:
        con.print(f"  [red]✚ new[/]        {_safe(f['title'])}")
    con.print()
    return 0


def cmd_lab(args) -> int:
    from .lab.scenarios import generate_all

    labels = generate_all(args.outdir)
    print(f"wrote {len(labels)} labelled captures to {args.outdir}")
    return 0


def cmd_bench(args) -> int:
    from rich import box
    from rich.table import Table

    from .bench import run_bench

    con = _console(args.no_color)
    with con.status("Running benchmark …") as st:
        result = run_bench(args.samples, progress=lambda name: st.update(f"Running benchmark … {name}"))
    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return 0
    t = Table(box=box.SIMPLE_HEAVY, title="Faultline scenario benchmark")
    for col in ("Capture", "Expected", "Detected", "Correct verdict", "False alarms", "Result"):
        t.add_column(col)
    for c in result["cases"]:
        exp = ", ".join(f"{e['kind']}/{e['category']}" for e in c["expected"]) or ("(clean)" if c["clean"] else "(hostile input)" if c["malformed"] else "-")
        if c["malformed"]:
            det = "handled" if c["passed"] else "CRASH"
            cls = "-"
        else:
            det = f"{c['detected']}/{len(c['expected'])}"
            cls = f"{c['classified']}/{c['detected']}" if c["detected"] else "-"
        fa = ", ".join(c["false_alarms"]) or "0"
        res = "[green]PASS[/]" if c["passed"] else "[red]FAIL[/]"
        if c.get("error") and not c["malformed"]:
            fa = _safe(c["error"])
        t.add_row(_safe(c["file"]), _safe(exp), det, cls, _safe(fa), res)
    con.print(t)
    s = result["summary"]
    con.print(
        f"[bold]Detection[/] {s['detected']}/{s['expected_findings']} ({s['detection_rate']:.0%}) · "
        f"[bold]Correct fault/attack verdict[/] {s['classified']}/{s['detected']} ({s['classification_accuracy']:.0%}) · "
        f"[bold]False alarms[/] {s['false_alarms']} · [bold]Clean captures quiet[/] {s['clean_cases_without_alarm']}/{s['clean_cases']} · "
        f"[bold]Hostile files handled[/] {s['hostile_handled']}/{s['hostile_cases']} · "
        f"{s['total_packets']:,} packets in {s['total_seconds']:.1f}s"
    )
    return 0 if s["passed"] == s["cases"] else 1


# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="faultline",
        description="Is my network broken, or is someone breaking it? Diagnose faults and attacks in packet captures.",
    )
    p.add_argument("--version", action="version", version=f"faultline {__version__}")
    p.add_argument("--no-color", action="store_true", help="disable colours")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", aliases=["a"], help="analyse a .pcap / .pcapng / .pcap.gz file")
    a.add_argument("capture")
    a.add_argument("--html", metavar="FILE", help="write a self-contained interactive HTML report")
    a.add_argument("--json", metavar="FILE", help="write the full report as JSON ('-' for stdout)")
    a.add_argument("--evidence-dir", metavar="DIR", help="write one small evidence .pcap per finding")
    a.add_argument("--redact", action="store_true", help="pseudonymise IP and MAC addresses (safe to share)")
    a.add_argument("--sensitivity", choices=["low", "normal", "high"], default="normal")
    a.add_argument("--expert", action="store_true", help="show technical details, all indicators and info notes")
    a.add_argument("--quiet", "-q", action="store_true", help="no terminal report (use with --json/--html)")
    a.add_argument("--fail-on", choices=["attack", "fault", "any", "never"], default="never",
                   help="exit with status 1 if findings of this kind (severity >= medium) exist (for CI)")
    a.add_argument("--max-packets", type=int, metavar="N", help="analyse at most N packets")
    a.add_argument("--no-evidence", action="store_true", help="skip the evidence pass (faster)")
    a.set_defaults(func=cmd_analyze)

    w = sub.add_parser("web", help="start the local web dashboard")
    w.add_argument("--host", default="127.0.0.1")
    w.add_argument("--port", type=int, default=8765)
    w.add_argument("--no-browser", action="store_true")
    w.set_defaults(func=cmd_web)

    d = sub.add_parser("diff", help="compare two captures (before / after a fix)")
    d.add_argument("before")
    d.add_argument("after")
    d.add_argument("--json", action="store_true")
    d.add_argument("--sensitivity", choices=["low", "normal", "high"], default="normal")
    d.set_defaults(func=cmd_diff)

    lab = sub.add_parser("lab", help="(re)generate the labelled sample captures")
    lab.add_argument("outdir", nargs="?", default=os.path.join(REPO_ROOT, "samples"))
    lab.set_defaults(func=cmd_lab)

    b = sub.add_parser("bench", help="benchmark detection accuracy on the labelled samples")
    b.add_argument("samples", nargs="?", default=os.path.join(REPO_ROOT, "samples"))
    b.add_argument("--json", action="store_true")
    b.set_defaults(func=cmd_bench)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    # global flags are accepted anywhere: `faultline analyze x.pcap --no-color` works too
    no_color = "--no-color" in argv or bool(os.environ.get("NO_COLOR"))
    argv = [a for a in argv if a != "--no-color"]
    args = parser.parse_args(argv)
    args.no_color = no_color
    try:
        return args.func(args) or 0
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:  # e.g. `faultline analyze x.pcap --json - | head`
        return 0


if __name__ == "__main__":
    sys.exit(main())
