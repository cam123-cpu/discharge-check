"""Run the accuracy evaluation.

    python -m eval.run                      # offline: pattern engine + replay any saved Claude responses
    python -m eval.run --live               # call Claude for every case (needs ANTHROPIC_API_KEY), save responses
    python -m eval.run --live --trials 3    # repeat to measure run-to-run stability
    python -m eval.run --cases A D          # only cases whose id starts with A or D
    python -m eval.run --min-recall 0.95    # exit 1 if the app's gap recall falls below this (for CI)

Layers scored:
    pattern         the regex engine alone (always available, no API)
    model_raw       what Claude answered, before any server-side checks
    model_verified  after llm.review() drops passes whose quote is not in the record
    app             what a user sees: analysis.analyze() with the merge, applicability and injection guards

Writes eval/reports/<timestamp>.json and .md, and appends one line to
eval/reports/history.jsonl so results accumulate into a long-run record."""
from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from app import analysis, llm
from app.config import Settings
from app.rules import RULES, RULES_BY_ID, RULES_VERSION, is_post_acute, run_pattern_checks

from . import replay
from .dataset import CASES_DIR, CaseError, dataset_hash, load_cases
from .metrics import layer_dict, score_layer
from .report import render_markdown

HARNESS_VERSION = "1"
DEFAULT_MODEL = Settings.__dataclass_fields__["model"].default
REPORTS_DIR = Path(__file__).resolve().parent / "reports"
MODEL_RULES = [r.id for r in RULES if not r.deterministic_only]
ROOT = Path(__file__).resolve().parent.parent


def _git() -> dict:
    def run(*a):
        try:
            return subprocess.run(["git", *a], cwd=ROOT, capture_output=True, text=True, timeout=10).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return ""
    return {"commit": run("rev-parse", "HEAD"), "dirty": bool(run("status", "--porcelain", "--", "app", "eval/cases"))}


def prompt_fingerprint() -> str:
    import hashlib
    rules = llm._render_rules(False) + "\n" + llm._render_rules(True)
    return hashlib.sha256((llm.SYSTEM + "\n" + rules).encode()).hexdigest()[:16]


def run_model(cases, client: replay.EvalClient, model: str, trial: int):
    raw, verified, app_layer, skipped, meta = {}, {}, {}, {}, {}
    for c in cases:
        client.use(c.id, trial)
        try:
            _, findings = llm.review(client, model, c.docs, is_post_acute(c.docs, c.disposition))
        except replay.MissingRecording:
            skipped[c.id] = "no recording"
            continue
        except replay.StaleRecording:
            skipped[c.id] = "stale recording (prompt or rules changed since it was recorded)"
            continue
        except (llm.LLMUnavailable, replay.RecordedError) as exc:
            skipped[c.id] = f"model unavailable: {exc}"
            meta[c.id] = client.last
            continue
        rec = client.last
        meta[c.id] = {k: rec.get(k) for k in ("served_model", "recorded_at", "request_hash", "seconds", "usage", "source")}
        parsed = rec.get("parsed_output") or {}
        raw[c.id] = {r["rule_id"]: r["status"] for r in parsed.get("compliance", []) if r.get("rule_id") in RULES_BY_ID}
        verified[c.id] = {rid: f.status for rid, f in findings.items()}
        result = analysis.analyze(c.docs, disposition_hint=c.disposition, discharge_hint=c.discharge_date,
                                  client=client, model=model, today=c.today)
        if result["engine"] != "model":  # should not happen: the response is cached
            skipped[c.id] = "app fell back to pattern engine: " + result["message"]
            raw.pop(c.id), verified.pop(c.id)
            continue
        app_layer[c.id] = {f["rule_id"]: f["status"] for f in result["findings"]}
    return raw, verified, app_layer, skipped, meta


def stability(trial_preds: list[dict[str, dict[str, str]]]) -> dict:
    """Share of (case, rule) pairs where every trial gave the same status."""
    if len(trial_preds) < 2:
        return {}
    same = total = 0
    flips = []
    for cid in set.intersection(*(set(p) for p in trial_preds)):
        for rid in RULES_BY_ID:
            vals = [p[cid].get(rid) for p in trial_preds]
            total += 1
            if len(set(vals)) == 1:
                same += 1
            else:
                flips.append({"case": cid, "rule": rid, "statuses": vals})
    return {"pairs": total, "consistent": same, "consistency": round(same / total, 4) if total else None, "flips": flips}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.run", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cases", nargs="*", help="only cases whose id starts with one of these")
    ap.add_argument("--cases-dir", type=Path, default=CASES_DIR, help=argparse.SUPPRESS)
    ap.add_argument("--live", action="store_true", help="call the Anthropic API and save responses (needs ANTHROPIC_API_KEY)")
    ap.add_argument("--no-model", action="store_true", help="score the pattern engine only")
    ap.add_argument("--model", default=None, help="model id (default: the app's configured model)")
    ap.add_argument("--recordings", type=Path, default=None, help="recording folder (default eval/recordings/<model>)")
    ap.add_argument("--trials", type=int, default=1)
    ap.add_argument("--allow-stale", action="store_true", help="replay recordings made with a different prompt (marked in the report)")
    ap.add_argument("--out", type=Path, default=REPORTS_DIR)
    ap.add_argument("--no-history", action="store_true", help="do not append to history.jsonl")
    ap.add_argument("--min-recall", type=float, default=None, help="exit 1 if the headline layer's gap recall is below this")
    ap.add_argument("--label", default="", help="free text stored with the run, e.g. 'after prompt v3'")
    args = ap.parse_args(argv)

    try:
        cases = load_cases(args.cases_dir, args.cases)
    except CaseError as exc:
        print(exc, file=sys.stderr)
        return 2
    if not cases:
        print("No cases matched.", file=sys.stderr)
        return 2

    model = args.model or DEFAULT_MODEL
    rec_dir = args.recordings or (replay.RECORDINGS_DIR / model)

    started = datetime.now(timezone.utc)
    layers: dict[str, dict] = {}
    pattern = {c.id: {f.rule_id: f.status for f in run_pattern_checks(c.docs, c.disposition, c.discharge_date, c.today)} for c in cases}
    layers["pattern"] = layer_dict(score_layer("pattern", cases, pattern))

    model_info: dict = {"enabled": False}
    if not args.no_model:
        if args.live:
            key = os.environ.get("ANTHROPIC_API_KEY")
            if not key:
                print("--live needs ANTHROPIC_API_KEY in the environment.", file=sys.stderr)
                return 2
            import anthropic
            real = anthropic.Anthropic(api_key=key, timeout=300, max_retries=2)
            client = replay.EvalClient("live", rec_dir, real=real)
        else:
            client = replay.EvalClient("replay", rec_dir, allow_stale=args.allow_stale)
        trials = []
        for t in range(1, args.trials + 1):
            if args.live:
                print(f"trial {t}/{args.trials}: reviewing {len(cases)} cases with {model} ...", file=sys.stderr)
            trials.append(run_model(cases, client, model, t))
        raw, verified, app_layer, skipped, meta = trials[0]
        if app_layer:
            layers["model_raw"] = layer_dict(score_layer("model_raw", cases, raw, skipped, MODEL_RULES))
            layers["model_verified"] = layer_dict(score_layer("model_verified", cases, verified, skipped, MODEL_RULES))
            layers["app"] = layer_dict(score_layer("app", cases, app_layer, skipped))
            for t, tr in enumerate(trials[1:], start=2):
                layers[f"app_trial{t}"] = layer_dict(score_layer(f"app_trial{t}", cases, tr[2], tr[3]))
        served = sorted({m.get("served_model") for m in meta.values() if m.get("served_model")})
        model_info = {
            "enabled": bool(app_layer),
            "mode": "live" if args.live else "replay",
            "requested_model": model,
            "served_models": served,
            "recordings": str(rec_dir.relative_to(ROOT)) if rec_dir.is_relative_to(ROOT) else str(rec_dir),
            "allow_stale": args.allow_stale,
            "cases_with_response": len(app_layer),
            "skipped": skipped,
            "stability": stability([tr[2] for tr in trials]),
            "per_case": meta,
        }
        if not app_layer:
            print(f"No usable Claude responses ({len(skipped)} case(s) skipped, e.g. {next(iter(skipped.values()), '')}). "
                  "Scoring the pattern engine only. Run with --live to record responses.", file=sys.stderr)

    headline = "app" if "app" in layers else "pattern"
    report = {
        "harness_version": HARNESS_VERSION,
        "run_at": started.isoformat(timespec="seconds"),
        "label": args.label,
        "headline_layer": headline,
        "provenance": {
            **_git(),
            "rules_version": RULES_VERSION,
            "prompt_fingerprint": prompt_fingerprint(),
            "dataset_hash": dataset_hash(cases),
            "case_filter": args.cases or [],
            "python": platform.python_version(),
        },
        "dataset": {
            "cases": len(cases),
            "by_category": {k: sum(c.category == k for c in cases) for k in sorted({c.category for c in cases})},
            "injection_cases": sum(c.injection for c in cases),
            "labels": {s: sum(v == s for c in cases for v in c.expected.values()) for s in ("pass", "fail", "unclear", "not_applicable")},
        },
        "model": model_info,
        "layers": layers,
    }

    args.out.mkdir(parents=True, exist_ok=True)
    stamp = started.strftime("%Y%m%dT%H%M%SZ")
    jpath, mpath = args.out / f"{stamp}.json", args.out / f"{stamp}.md"
    jpath.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
    md = render_markdown(report)
    mpath.write_text(md, encoding="utf-8")
    (args.out / "latest.md").write_text(md, encoding="utf-8")
    if not args.no_history:
        h = report["layers"][headline]["overall"]
        line = {
            "run_at": report["run_at"], "label": args.label, "headline_layer": headline, "mode": model_info.get("mode", "pattern"),
            "model": model_info.get("served_models") or None, **{k: report["provenance"][k] for k in ("commit", "dirty", "rules_version", "prompt_fingerprint", "dataset_hash")},
            "cases": len(cases), "recall": h["recall"]["value"], "precision": h["precision"]["value"],
            "false_pass": h["counts"]["fn"], "false_alarm": h["counts"]["fp"],
            "pattern_recall": layers["pattern"]["overall"]["recall"]["value"],
            "attack_success": report["layers"][headline]["injection"]["attack_success_rate"]["value"],
            "report": jpath.name,
        }
        with (args.out / "history.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(line) + "\n")

    print(md.split("\n## Per rule")[0])
    print(f"Full report: {mpath}")
    if args.min_recall is not None:
        r = report["layers"][headline]["overall"]["recall"]["value"]
        if r is None or r < args.min_recall:
            print(f"FAIL: {headline} recall {r} is below {args.min_recall}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
