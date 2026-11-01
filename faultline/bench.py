"""Benchmark Faultline against the labelled scenario lab (``samples/labels.json``).

For every labelled capture we check:

* **detection**: each expected finding kind is present;
* **classification**: it was judged the expected category (fault / misconfig / attack);
* **false alarms**: findings of severity ≥ medium that were not expected
  (on clean captures, *any* such finding is a false alarm), and any ``must_not`` kind.
* **robustness**: malformed / hostile captures are handled without a crash.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field

from .capture.reader import CaptureError
from .engine import AnalyzeOptions, analyze

MEDIUM = 2


@dataclass
class CaseResult:
    file: str
    title: str
    expected: list[dict]
    detected: int = 0
    classified: int = 0
    missed: list[str] = field(default_factory=list)
    misclassified: list[str] = field(default_factory=list)
    false_alarms: list[str] = field(default_factory=list)
    verdict: str = ""
    error: str | None = None
    seconds: float = 0.0
    packets: int = 0
    malformed: bool = False
    clean: bool = False

    @property
    def passed(self) -> bool:
        if self.malformed:
            return self.error is None or self.error.startswith("CaptureError")
        return not self.missed and not self.misclassified and not self.false_alarms and self.error is None


def run_bench(samples_dir: str, progress=None) -> dict:
    labels_path = os.path.join(samples_dir, "labels.json")
    with open(labels_path, encoding="utf-8") as fh:
        labels = json.load(fh)
    results: list[CaseResult] = []
    for rel, meta in sorted(labels.items()):
        path = os.path.join(samples_dir, rel)
        res = CaseResult(file=rel, title=meta.get("title", rel), expected=meta.get("expected", []),
                         malformed=bool(meta.get("malformed")), clean=bool(meta.get("clean")))
        if progress:
            progress(rel)
        t0 = time.perf_counter()
        try:
            rep = analyze(path, AnalyzeOptions(evidence=False)).to_dict()
        except CaptureError as exc:
            res.error = f"CaptureError: {exc}"
            res.seconds = time.perf_counter() - t0
            results.append(res)
            continue
        except Exception as exc:  # a crash is a failed case, never a crashed benchmark
            res.error = f"CRASH {type(exc).__name__}: {exc}"
            res.seconds = time.perf_counter() - t0
            results.append(res)
            continue
        res.seconds = time.perf_counter() - t0
        res.packets = rep["capture"]["packets"]
        res.verdict = rep["verdict"]["status"]
        found = rep["findings"]
        expected_kinds = {e["kind"] for e in res.expected}
        for exp in res.expected:
            hits = [f for f in found if f["kind"] == exp["kind"]]
            if not hits:
                res.missed.append(exp["kind"])
                continue
            res.detected += 1
            if any(f["category"] == exp["category"] for f in hits):
                res.classified += 1
            else:
                res.misclassified.append(f"{exp['kind']} → {hits[0]['category']} (expected {exp['category']})")
        must_not = set(meta.get("must_not", []))
        for f in found:
            if f["kind"] in must_not:
                res.false_alarms.append(f"{f['kind']} ({f['category']})")
            elif not res.malformed and f["kind"] not in expected_kinds and f["severity"] >= MEDIUM and f["kind"] != "capture.malformed":
                # an unexpected medium+ finding that is explained as a symptom of an expected root is not a false alarm
                if f.get("symptom_of") is None:
                    res.false_alarms.append(f"{f['kind']} ({f['category']}, {f['severity_name']})")
        results.append(res)

    labelled = [r for r in results if not r.malformed]
    exp_total = sum(len(r.expected) for r in labelled)
    detected = sum(r.detected for r in labelled)
    classified = sum(r.classified for r in labelled)
    fa = sum(len(r.false_alarms) for r in labelled)
    clean = [r for r in labelled if r.clean]
    hostile = [r for r in results if r.malformed]
    summary = {
        "cases": len(results),
        "expected_findings": exp_total,
        "detected": detected,
        "classified": classified,
        "detection_rate": round(detected / exp_total, 3) if exp_total else 1.0,
        "classification_accuracy": round(classified / detected, 3) if detected else 1.0,
        "false_alarms": fa,
        "clean_cases": len(clean),
        "clean_cases_without_alarm": sum(1 for r in clean if not r.false_alarms),
        "hostile_cases": len(hostile),
        "hostile_handled": sum(1 for r in hostile if r.passed),
        "passed": sum(1 for r in results if r.passed),
        "total_seconds": round(sum(r.seconds for r in results), 2),
        "total_packets": sum(r.packets for r in results),
    }
    return {"summary": summary, "cases": [r.__dict__ | {"passed": r.passed} for r in results]}
