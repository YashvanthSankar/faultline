#!/usr/bin/env python3
"""Mutation fuzzer for the Faultline capture pipeline (reader -> decoder -> engine).

    .venv/bin/python scripts/fuzz.py                # 500 cases
    .venv/bin/python scripts/fuzz.py -n 5000 --seed 7
    .venv/bin/python scripts/fuzz.py --no-engine    # reader + decoder only
    .venv/bin/python scripts/fuzz.py --keep out/    # save crashing inputs

Exit code 0 when no case crashed (only CaptureError is acceptable) and no case
exceeded the per-case time budget; 1 otherwise. Standard library only.
"""

from __future__ import annotations

import argparse
import os
import random
import shutil
import sys
import tempfile
import time
import traceback
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tests import fuzzing  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-n", "--cases", type=int, default=500)
    ap.add_argument("--seed", type=int, default=int(time.time()))
    ap.add_argument("--no-engine", action="store_true", help="stop after the decoder")
    ap.add_argument("--budget", type=float, default=3.0, help="max seconds per case")
    ap.add_argument("--keep", metavar="DIR", help="directory to save crashing / slow inputs")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    stages = fuzzing.stages_available()
    seeds = fuzzing.seed_captures()
    rng = random.Random(args.seed)
    workdir = tempfile.mkdtemp(prefix="faultline-fuzz-")
    if args.keep:
        os.makedirs(args.keep, exist_ok=True)

    print(f"faultline fuzz  seed={args.seed}  cases={args.cases}  seeds={len(seeds)}  "
          f"stages={'+'.join(k for k, v in stages.items() if v and not (k == 'engine' and args.no_engine))}")
    print()

    results = []
    by_mutation: Counter = Counter()
    crashes = []
    slow = []
    t_start = time.perf_counter()
    try:
        for i in range(args.cases):
            seed = seeds[i % len(seeds)]
            kind, data = fuzzing.mutate(seed.data, rng)
            path = os.path.join(workdir, f"case{i}.bin")
            with open(path, "wb") as fh:
                fh.write(data)
            res = fuzzing.run_case(path, seed.name, kind, run_engine=not args.no_engine)
            results.append(res)
            by_mutation[kind.split("(")[0]] += 1
            if not res.ok or res.seconds > args.budget:
                (crashes if not res.ok else slow).append((i, res))
                if args.keep:
                    shutil.copy(path, os.path.join(args.keep, f"{'crash' if not res.ok else 'slow'}-{i}-{seed.name}.bin"))
                if not res.ok and not args.quiet:
                    print(f"CRASH case {i} seed={seed.name} mutation={kind} stage={res.stage}")
                    traceback.print_exception(type(res.crash), res.crash, res.crash.__traceback__, limit=6)
            os.unlink(path)
            if not args.quiet and (i + 1) % 100 == 0:
                print(f"  ... {i + 1}/{args.cases}  crashes={len(crashes)}", flush=True)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    elapsed = time.perf_counter() - t_start
    n = len(results)
    packets = sum(r.packets for r in results)
    decoded = sum(r.decoded for r in results)
    malformed = sum(r.malformed for r in results)
    capture_errors = sum(1 for r in results if r.capture_error)
    slowest = max(results, key=lambda r: r.seconds) if results else None
    total_case_time = sum(r.seconds for r in results)

    rows = [
        ("cases", f"{n}"),
        ("crashes (non-CaptureError exceptions)", f"{len(crashes)}"),
        ("rejected cleanly (CaptureError)", f"{capture_errors}  ({100.0 * capture_errors / max(n, 1):.1f}%)"),
        ("accepted with warnings / truncation", f"{n - capture_errors - len(crashes)}"),
        ("frames read", f"{packets:,}"),
        ("frames decoded", f"{decoded:,}  (malformed layers flagged: {malformed:,})"),
        ("slowest case", f"{(slowest.seconds * 1000 if slowest else 0):.1f} ms  ({slowest.name if slowest else '-'}, {slowest.mutation if slowest else '-'})"),
        ("cases over budget", f"{len(slow)}  (budget {args.budget:.1f}s)"),
        ("mean per case", f"{(1000 * total_case_time / max(n, 1)):.2f} ms"),
        ("throughput", f"{packets / max(total_case_time, 1e-9):,.0f} packets/s   {n / max(elapsed, 1e-9):,.0f} cases/s"),
        ("mutations", ", ".join(f"{k}={v}" for k, v in sorted(by_mutation.items()))),
    ]
    width = max(len(k) for k, _ in rows)
    print()
    print("=" * (width + 44))
    for k, v in rows:
        print(f"{k:<{width}}  {v}")
    print("=" * (width + 44))
    ok = not crashes and not slow
    print("RESULT:", "PASS - no crash, bounded time" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
