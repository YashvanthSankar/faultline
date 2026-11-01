"""``faultline diff before.pcap after.pcap``: did the fix work?

Findings are matched across the two reports by (kind, category) and by the
hosts involved, so "DNS timeouts from 192.168.1.1" before and after a change
are recognised as the same problem.
"""

from __future__ import annotations


def _key(f: dict) -> tuple:
    return (f["kind"], f["category"])


def diff_reports(before: dict, after: dict) -> dict:
    def index(rep: dict) -> dict[tuple, dict]:
        out: dict[tuple, dict] = {}
        for f in rep.get("findings", []):
            if f.get("severity", 0) < 1:
                continue
            k = _key(f)
            if k not in out or f["severity"] > out[k]["severity"]:
                out[k] = f
        return out

    a, b = index(before), index(after)
    fixed = [a[k] for k in a if k not in b]
    new = [b[k] for k in b if k not in a]
    persisting = []
    for k in a:
        if k in b:
            fa, fb = a[k], b[k]
            if fb["severity"] < fa["severity"] or fb.get("packet_total", 0) < fa.get("packet_total", 0) * 0.5:
                trend = "better"
            elif fb["severity"] > fa["severity"] or fb.get("packet_total", 0) > fa.get("packet_total", 0) * 1.5:
                trend = "worse"
            else:
                trend = "same"
            persisting.append({"before": fa, "after": fb, "trend": trend})
    sa, sb = before["verdict"]["score"], after["verdict"]["score"]
    if not new and not persisting and fixed:
        conclusion = "Everything that was wrong before is gone. The fix worked."
    elif not new and all(p["trend"] == "better" for p in persisting) and (fixed or persisting):
        conclusion = "Things improved, but some problems are still present."
    elif new and not fixed:
        conclusion = "New problems appeared and nothing was fixed. The change made things worse."
    elif sb > sa:
        conclusion = "Overall healthier than before, but check the remaining and new findings."
    elif sb < sa:
        conclusion = "Overall less healthy than before."
    else:
        conclusion = "No meaningful change."
    return {
        "before": {"name": before["capture"]["name"], "status": before["verdict"]["status"], "score": sa},
        "after": {"name": after["capture"]["name"], "status": after["verdict"]["status"], "score": sb},
        "fixed": fixed,
        "new": new,
        "persisting": persisting,
        "conclusion": conclusion,
    }
