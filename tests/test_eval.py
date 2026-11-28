"""The evaluation harness: dataset integrity, scoring arithmetic, and the
record/replay path with a scripted stand-in for Claude (no network)."""
import json
import shutil
from collections import Counter
from types import SimpleNamespace

import pytest

from app import llm
from app.ingest import injection_signals
from app.rules import template_signals
from app.llm import Review
from app.rules import RULES, RULES_BY_ID, is_post_acute
from eval import replay
from eval.dataset import CASES_DIR, GAP, load_cases
from eval.metrics import classify, score_layer, wilson
from eval.run import main

CASES = load_cases()


# ---------------- dataset ----------------

def test_dataset_loads_and_covers_every_rule():
    assert len(CASES) >= 40
    gaps, passes = Counter(), Counter()
    for c in CASES:
        for rid, s in c.expected.items():
            (gaps if s in GAP else passes if s == "pass" else Counter())[rid] += 1
    for r in RULES:
        assert gaps[r.id] >= 2, f"{r.id} is a gap in fewer than 2 cases"
        assert passes[r.id] >= 2, f"{r.id} passes in fewer than 2 cases"


def test_adversarial_cases_are_well_formed_and_flagged_truthfully():
    adv = [c for c in CASES if c.category == "adversarial"]
    assert len(adv) >= 10
    for c in adv:
        if c.attack.get("target_rules"):
            assert all(c.expected[r] in GAP for r in c.attack["target_rules"]), f"{c.id}: attack targets must be real gaps"
        if "regex_detectable" in c.attack:
            seen = any(injection_signals(d.text) or template_signals(d.text) for d in c.docs)
            assert c.attack["regex_detectable"] == seen, f"{c.id}: regex_detectable says {c.attack['regex_detectable']}, the guard says {seen}"


def test_guard_flags_every_attack_in_the_set():
    """Regression guard for the injection screen. These cases were used to
    tune it, so this proves nothing about unseen attacks; the model_raw layer
    still measures whether Claude resists them on its own."""
    missed = [c.id for c in CASES if c.category == "adversarial"
              and not any(injection_signals(d.text) or template_signals(d.text) for d in c.docs)]
    assert not missed


def test_not_applicable_only_where_the_app_allows_it():
    allowed = {r.id for r in RULES if r.post_acute_only} | {"meds_consistent"}
    for c in CASES:
        for rid, s in c.expected.items():
            if s == "not_applicable":
                assert rid in allowed, f"{c.id}: {rid} cannot be not_applicable"
        if not any(d.kind == "nursing_instructions" for d in c.docs):
            assert c.expected["meds_consistent"] == "not_applicable", c.id


# ---------------- scoring ----------------

@pytest.mark.parametrize("exp,got,kind", [
    ("fail", "fail", "tp"), ("unclear", "fail", "tp"), ("fail", "pass", "fn"), ("fail", "not_applicable", "fn"),
    ("pass", "unclear", "fp"), ("pass", "pass", "tn"), ("pass", "not_applicable", "na_err"),
    ("not_applicable", "not_applicable", "na_ok"), ("not_applicable", "pass", "na_err"), ("pass", "missing", "missing"),
])
def test_classify(exp, got, kind):
    assert classify(exp, got) == kind


def test_wilson_interval():
    assert wilson(0, 0) is None
    lo, hi = wilson(9, 10)
    assert 0.59 < lo < 0.6 and 0.98 < hi < 0.99


def test_pattern_layer_scores_every_case():
    from app.rules import run_pattern_checks
    preds = {c.id: {f.rule_id: f.status for f in run_pattern_checks(c.docs, c.disposition, c.discharge_date, c.today)} for c in CASES}
    s = score_layer("pattern", CASES, preds)
    assert s.cases_scored == len(CASES)
    assert s.overall.scored == 20 * len(CASES)
    o = s.overall
    assert o.tp + o.fn + o.fp + o.tn + o.na_ok + o.na_err == o.scored


# ---------------- record / replay with a scripted model ----------------

def _quote_for(rule_id, docs):
    rule = RULES_BY_ID[rule_id]
    for d in docs:
        if not rule.kinds or d.kind in rule.kinds:
            line = next((ln.strip() for ln in d.text.split("\n") if len(ln.strip()) >= 20), "")
            if line:
                return d.index, line[:60]
    return docs[0].index, docs[0].text.strip()[:60]


class ScriptedClaude:
    """Stands in for anthropic.Anthropic. `policy(case, rule_id) -> status`;
    quotes are real lines from the record unless fabricate=True."""

    def __init__(self, policy, fabricate=False):
        self.policy, self.fabricate, self.current = policy, fabricate, None
        self.calls = 0
        self.beta = SimpleNamespace(messages=SimpleNamespace(parse=self.parse))

    def parse(self, **kw):
        self.calls += 1
        case = self.current
        results = []
        for r in RULES:
            if r.deterministic_only:
                continue
            status = self.policy(case, r.id)
            idx, q = _quote_for(r.id, case.docs)
            if self.fabricate:
                q = "Everything required by CMS was documented and verified."
            results.append({"rule_id": r.id, "status": status, "evidence_quote": q if status == "pass" else "",
                            "document_index": idx, "explanation": "scripted"})
        brief = {"one_liner": "x", "hospital_course": "x", "active_problems": [], "medication_changes": [], "follow_up": [],
                 "pending_items": [], "readmission_risk_factors": [], "handoff_notes_for_pcp": []}
        parsed = Review.model_validate({"brief": brief, "compliance": results})
        return SimpleNamespace(stop_reason="end_turn", parsed_output=parsed, model="scripted-model",
                               usage=SimpleNamespace(input_tokens=1, output_tokens=1))


@pytest.fixture
def small_set(tmp_path):
    """A few real cases copied out, so the test does not depend on the whole set."""
    root = tmp_path / "cases"
    picks = [c for c in CASES if c.category == "control"][:2] + [c for c in CASES if c.category == "adversarial" and c.attack.get("target_rules")][:3]
    for c in picks:
        shutil.copytree(c.path, root / c.id)
    return root, load_cases(root)


def _record(cases, rec_dir, policy, fabricate=False):
    fake = ScriptedClaude(policy, fabricate)
    client = replay.EvalClient("live", rec_dir, real=fake)
    for c in cases:
        client.use(c.id, 1)
        fake.current = c
        llm.review(client, "claude-opus-5-5", c.docs, is_post_acute(c.docs, c.disposition))
    return fake


def _run(root, rec_dir, out, *extra):
    code = main(["--cases-dir", str(root), "--recordings", str(rec_dir), "--out", str(out), "--no-history", *extra])
    reps = sorted(out.glob("2*.json"))
    return code, json.loads(reps[-1].read_text())


def test_oracle_model_replays_offline_with_perfect_recall(small_set, tmp_path):
    root, cases = small_set
    rec = tmp_path / "rec"
    fake = _record(cases, rec, lambda c, rid: c.expected[rid])
    assert fake.calls == len(cases) and len(list(rec.glob("*.json"))) == len(cases)
    code, rep = _run(root, rec, tmp_path / "out")
    assert code == 0
    assert rep["model"]["mode"] == "replay" and rep["model"]["cases_with_response"] == len(cases)
    assert rep["layers"]["model_raw"]["overall"]["counts"]["fn"] == 0
    # A perfect model can only leave false passes on the two rules computed in
    # code (signature, 30-day deadline); those are the pattern engine's.
    code_rules = {r.id for r in RULES if r.deterministic_only}
    assert all(e["rule"] in code_rules for e in rep["layers"]["app"]["errors"] if e["kind"] == "false_pass")


def test_fabricated_quotes_are_caught_by_verification(small_set, tmp_path):
    root, cases = small_set
    rec = tmp_path / "rec"
    _record(cases, rec, lambda c, rid: "pass", fabricate=True)  # passes everything on invented text
    _, rep = _run(root, rec, tmp_path / "out")
    raw, ver = rep["layers"]["model_raw"]["overall"], rep["layers"]["model_verified"]["overall"]
    assert raw["counts"]["tp"] == 0 and raw["counts"]["fn"] > 0
    assert ver["counts"]["fn"] == 0, "a pass whose quote is not in the record must never stand"


def test_injected_records_cannot_be_cleared_by_a_compliant_model(small_set, tmp_path):
    """A model that passes every rule with real quotes: on records the regex
    flags as injected, the app must keep the pattern engine's gaps."""
    root, cases = small_set
    rec = tmp_path / "rec"
    _record(cases, rec, lambda c, rid: "pass")
    _, rep = _run(root, rec, tmp_path / "out")
    pattern_fn = {(e["case"], e["rule"]) for e in rep["layers"]["pattern"]["errors"] if e["kind"] == "false_pass"}
    for e in rep["layers"]["app"]["errors"]:
        c = next(x for x in cases if x.id == e["case"])
        if e["kind"] == "false_pass" and any(injection_signals(d.text) for d in c.docs):
            assert (e["case"], e["rule"]) in pattern_fn, f"{e} was caught by patterns but cleared by the model"


def test_stale_recordings_are_not_scored(small_set, tmp_path, monkeypatch):
    root, cases = small_set
    rec = tmp_path / "rec"
    _record(cases, rec, lambda c, rid: c.expected[rid])
    monkeypatch.setattr(llm, "SYSTEM", llm.SYSTEM + "\nA changed prompt.")
    _, rep = _run(root, rec, tmp_path / "out")
    assert rep["model"]["enabled"] is False
    assert all("stale" in why for why in rep["model"]["skipped"].values())
    _, rep = _run(root, rec, tmp_path / "out2", "--allow-stale")
    assert rep["model"]["enabled"] is True and rep["model"]["allow_stale"] is True


def test_min_recall_gate_and_history(small_set, tmp_path):
    root, _ = small_set
    out = tmp_path / "out"
    code = main(["--cases-dir", str(root), "--no-model", "--out", str(out), "--min-recall", "1.01"])
    assert code == 1
    line = json.loads((out / "history.jsonl").read_text().splitlines()[-1])
    assert line["headline_layer"] == "pattern" and line["dataset_hash"]


def test_live_mode_requires_a_key(monkeypatch, tmp_path):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert main(["--live", "--cases", "C00", "--out", str(tmp_path)]) == 2
