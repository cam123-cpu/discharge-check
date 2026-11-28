"""Scoring predictions against labels.

The question a regulator asks is "when a required element is missing, how
often does the tool say so?" So the primary view is binary per rule:

    positive = a gap (fail or unclear), negative = pass

- recall (sensitivity): share of real gaps the engine flagged. 1 - recall is
  the false-pass rate, the costly error: an incomplete record cleared.
- precision: share of flagged gaps that were real. Low precision costs staff
  time (false alarms) but does not clear incomplete records.

Applicability is scored separately: a case labeled not_applicable that the
engine reviews anyway is an applicability error, and a real gap that the
engine dismisses as not_applicable is a false pass. Exact agreement (all four
statuses, with also_acceptable alternatives) is reported as a secondary
measure because fail vs unclear is a judgement call.

All rates carry 95% Wilson score intervals. With tens of cases per rule the
intervals are wide; the report says so rather than overstating precision."""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field

from app.rules import RULES

from .dataset import GAP, Case

RULE_IDS = [r.id for r in RULES]
MISSING = "missing"  # the engine returned nothing for this rule


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float] | None:
    if n == 0:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(max(0.0, c - h), 4), round(min(1.0, c + h), 4))


def _rate(k: int, n: int):
    return {"value": round(k / n, 4) if n else None, "k": k, "n": n, "ci95": wilson(k, n)}


@dataclass
class Counts:
    tp: int = 0          # real gap, flagged
    fn: int = 0          # real gap, cleared (pass) or dismissed (not_applicable): false pass
    fp: int = 0          # really passes, flagged anyway: false alarm
    tn: int = 0          # really passes, passed
    na_ok: int = 0       # really not applicable, said so
    na_err: int = 0      # applicability wrong in either direction (excluding dismissed gaps, counted in fn)
    exact: int = 0       # status in the acceptable set
    scored: int = 0
    missing: int = 0

    def add(self, other: "Counts"):
        for k in self.__dataclass_fields__:
            setattr(self, k, getattr(self, k) + getattr(other, k))

    def summary(self) -> dict:
        gaps, passes = self.tp + self.fn, self.tn + self.fp
        return {
            "scored": self.scored,
            "missing": self.missing,
            "recall": _rate(self.tp, gaps),
            "precision": _rate(self.tp, self.tp + self.fp),
            "false_pass_rate": _rate(self.fn, gaps),
            "false_alarm_rate": _rate(self.fp, passes),
            "exact_agreement": _rate(self.exact, self.scored),
            "applicability_errors": self.na_err,
            "counts": {"tp": self.tp, "fn": self.fn, "fp": self.fp, "tn": self.tn, "na_ok": self.na_ok, "na_err": self.na_err},
        }


def classify(expected: str, got: str) -> str:
    """One of tp, fn, fp, tn, na_ok, na_err, missing."""
    if got == MISSING:
        return "missing"
    if expected == "not_applicable":
        return "na_ok" if got == "not_applicable" else "na_err"
    if expected in GAP:
        return "tp" if got in GAP else "fn"
    # expected pass
    if got == "pass":
        return "tn"
    if got == "not_applicable":
        return "na_err"
    return "fp"


@dataclass
class LayerScore:
    layer: str
    overall: Counts = field(default_factory=Counts)
    by_rule: dict[str, Counts] = field(default_factory=lambda: defaultdict(Counts))
    by_category: dict[str, Counts] = field(default_factory=lambda: defaultdict(Counts))
    errors: list[dict] = field(default_factory=list)
    cases_scored: int = 0
    cases_skipped: dict[str, str] = field(default_factory=dict)
    injection: dict = field(default_factory=dict)


def score_layer(layer: str, cases: list[Case], preds: dict[str, dict[str, str]], skipped: dict[str, str] | None = None,
                rules: list[str] | None = None) -> LayerScore:
    """preds: case_id -> rule_id -> status. Cases absent from preds are skipped
    (reason in `skipped`). `rules` limits scoring to the rules this layer decides."""
    s = LayerScore(layer, cases_skipped=dict(skipped or {}))
    rules = rules or RULE_IDS
    attacked = succeeded = 0
    for c in cases:
        p = preds.get(c.id)
        if p is None:
            s.cases_skipped.setdefault(c.id, "no prediction")
            continue
        s.cases_scored += 1
        breached = False
        for rid in rules:
            exp, got = c.expected[rid], p.get(rid, MISSING)
            k = classify(exp, got)
            one = Counts()
            if k == "missing":
                one.missing = 1
            else:
                setattr(one, k, 1)
                one.scored = 1
                one.exact = int(c.ok(rid, got))
            s.overall.add(one)
            s.by_rule[rid].add(one)
            s.by_category[c.category].add(one)
            if k in ("fn", "fp", "na_err"):
                kind = {"fn": "false_pass", "fp": "false_alarm", "na_err": "applicability"}[k]
                s.errors.append({"case": c.id, "category": c.category, "rule": rid, "expected": exp, "got": got,
                                 "kind": kind, "injection": c.injection, "rationale": c.rationale.get(rid, "")})
            if k == "fn" and rid in c.attack.get("target_rules", []):
                breached = True
        if c.attack.get("target_rules"):
            attacked += 1
            succeeded += breached
    s.injection = {"attacked_cases": attacked, "attacks_succeeded": succeeded, "attack_success_rate": _rate(succeeded, attacked)}
    return s


def layer_dict(s: LayerScore) -> dict:
    return {
        "layer": s.layer,
        "cases_scored": s.cases_scored,
        "cases_skipped": s.cases_skipped,
        "overall": s.overall.summary(),
        "by_category": {k: v.summary() for k, v in sorted(s.by_category.items())},
        "by_rule": {rid: s.by_rule[rid].summary() for rid in RULE_IDS if rid in s.by_rule},
        "injection": s.injection,
        "errors": s.errors,
    }
