"""Fault vs. misconfiguration vs. attack: the hypothesis engine.

Detectors report *observations* (e.g. "two MACs claim 192.168.1.1") together
with ``Indicator``s: small pieces of evidence, each supporting one hypothesis
with a weight. They may also supply a ``Variant`` (wording) per hypothesis.

This module decides, uniformly for every finding:

* the winning hypothesis (highest evidence score among the candidates),
* a calibrated confidence (softmax over candidate scores),
* "why not" explanations for each losing hypothesis, built from the
  indicators that supported it and the strongest evidence that beat it.

Keeping the decision here, not in each detector, makes the reasoning
consistent, auditable, and explainable to a beginner.
"""

from __future__ import annotations

import math

from .model import Category, Finding, Severity

HYPOTHESES = (Category.ATTACK, Category.FAULT, Category.MISCONFIG)
PRIOR = 0.5  # small head start for the detector's own default reading
MAX_WEIGHT = 3.0
TEMPERATURE = 1.0

LABEL = {
    Category.ATTACK: "an attack",
    Category.FAULT: "a fault",
    Category.MISCONFIG: "a misconfiguration",
    Category.INFO: "informational",
}


def _clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def score(f: Finding) -> dict[Category, float]:
    scores = {h: 0.0 for h in HYPOTHESES}
    if f.category in scores:
        scores[f.category] += PRIOR
    for ind in f.indicators:
        if ind.supports in scores:
            scores[ind.supports] += _clamp(float(ind.weight or 0.0), 0.0, MAX_WEIGHT)
    return scores


def assess(f: Finding) -> Finding:
    """Decide the category of one finding in place and return it."""
    if f.category == Category.INFO and not f.variants:
        f.confidence = 1.0
        return f

    scores = score(f)
    candidates = [h for h in HYPOTHESES if h == f.category or h in f.variants]
    if not candidates:
        candidates = [f.category] if f.category in scores else [Category.FAULT]

    # deterministic tie-break: the detector's default reading wins ties
    winner = max(candidates, key=lambda h: (round(scores[h], 6), h == f.category))

    if len(candidates) == 1:
        # confidence grows with the amount of evidence for the only reading
        conf = 1.0 - 0.5 * math.exp(-scores[winner] / 2.0)
    else:
        exps = {h: math.exp(scores[h] / TEMPERATURE) for h in candidates}
        conf = exps[winner] / sum(exps.values())
    f.confidence = _clamp(conf, 0.5, 0.99)
    f.scores = {h.value: scores[h] for h in HYPOTHESES if scores[h] > 0 or h in candidates}

    original = f.category
    f.category = winner
    variant = f.variants.get(winner)
    if variant is not None:
        f.title = variant.title or f.title
        f.summary = variant.summary or f.summary
        f.explanation = variant.explanation or f.explanation
        f.cause = variant.cause or f.cause
        f.fix = list(variant.fix) or f.fix
        f.analogy = variant.analogy or f.analogy
        f.mitre = variant.mitre if winner == Category.ATTACK else None
        if variant.severity is not None:
            f.severity = variant.severity
    elif winner != Category.ATTACK:
        f.mitre = None

    # A weakly-supported attack reading is presented one step softer.
    if winner == Category.ATTACK and f.confidence < 0.6 and f.severity > Severity.LOW:
        f.severity = Severity(int(f.severity) - 1)

    f.alternatives = [_why_not(f, h, winner, scores) for h in candidates if h != winner]
    if original != winner:
        f.metrics.setdefault("detector_default", original.value)
    return f


def _why_not(f: Finding, losing: Category, winner: Category, scores: dict[Category, float]) -> dict:
    pro = sorted((i for i in f.indicators if i.supports == losing), key=lambda i: -i.weight)
    win = sorted((i for i in f.indicators if i.supports == winner), key=lambda i: -i.weight)
    variant = f.variants.get(losing)
    title = variant.title if variant else f"Could be {LABEL[losing]}"
    if pro:
        signs = "; ".join(i.text.rstrip(".") for i in pro[:3])
        text = f"Some signs pointed this way ({signs}), but they were outweighed"
    else:
        text = f"Nothing in the traffic pointed to {LABEL[losing]}"
    if win:
        text += f". The stronger evidence: {win[0].text.rstrip('.')}"
        if len(win) > 1:
            text += f"; {win[1].text.rstrip('.')}"
    text += "."
    return {
        "category": losing.value,
        "title": title,
        "score": round(scores[losing], 2),
        "why_not": text,
    }
