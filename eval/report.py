"""Markdown rendering of an evaluation report."""
from __future__ import annotations

from app.rules import RULES_BY_ID

LAYER_NAMES = {
    "pattern": "Pattern engine (no AI)",
    "model_raw": "Claude, raw answer",
    "model_verified": "Claude, after quote verification",
    "app": "What the app shows (merged, guarded)",
}


def _pct(r: dict) -> str:
    if r["value"] is None:
        return "n/a"
    lo, hi = r["ci95"]
    return f"{r['value'] * 100:.1f}% ({lo * 100:.0f}–{hi * 100:.0f}) [{r['k']}/{r['n']}]"


def _short(r: dict) -> str:
    return "–" if r["value"] is None else f"{r['value'] * 100:.0f}% ({r['k']}/{r['n']})"


def render_markdown(rep: dict) -> str:
    p, d, m = rep["provenance"], rep["dataset"], rep["model"]
    out = [
        "# Discharge Check accuracy report",
        "",
        f"Run {rep['run_at']}" + (f" · {rep['label']}" if rep["label"] else ""),
        "",
        "Synthetic, labeled discharge records scored rule by rule. A **gap** is a rule the label says is "
        "`fail` or `unclear`. **Recall** is the share of real gaps the engine flagged; a miss is a "
        "**false pass** (an incomplete record cleared). **Precision** is the share of flagged gaps that "
        "were real. Brackets are 95% Wilson intervals and raw counts.",
        "",
        "## Provenance",
        "",
        f"- Code commit `{p['commit'][:12] or 'unknown'}`" + (" (uncommitted changes to app/ or eval/cases)" if p["dirty"] else ""),
        f"- Rules version `{p['rules_version']}`, prompt fingerprint `{p['prompt_fingerprint']}`, dataset hash `{p['dataset_hash']}`",
        f"- Dataset: {d['cases']} cases " + ", ".join(f"{k} {v}" for k, v in d["by_category"].items())
        + f"; {d['injection_cases']} with prompt injection; labels " + ", ".join(f"{k} {v}" for k, v in d["labels"].items()),
    ]
    if m.get("enabled"):
        out.append(f"- Claude: {m['mode']} · requested `{m['requested_model']}` · served {', '.join(f'`{s}`' for s in m['served_models']) or 'unknown'}"
                   f" · {m['cases_with_response']} cases with a response · recordings `{m['recordings']}`"
                   + (" · **stale recordings allowed**" if m.get("allow_stale") else ""))
        if m.get("stability"):
            s = m["stability"]
            out.append(f"- Run-to-run consistency of app results: {s['consistency'] * 100:.1f}% of {s['pairs']} case-rule pairs")
    else:
        out.append("- Claude: **not scored in this run** (no API key and no matching recordings). Only the pattern engine is measured.")
    if m.get("skipped"):
        out.append(f"- Cases skipped for the model layers: {len(m['skipped'])}")

    out += ["", "## Headline", "", "| Layer | Recall (gaps caught) | Precision | False passes | False alarms | Applicability errors | Exact agreement |",
            "| --- | --- | --- | --- | --- | --- | --- |"]
    for key, L in rep["layers"].items():
        o = L["overall"]
        out.append(f"| {LAYER_NAMES.get(key, key)} | {_pct(o['recall'])} | {_pct(o['precision'])} | {o['counts']['fn']} | "
                   f"{o['counts']['fp']} | {o['applicability_errors']} | {_short(o['exact_agreement'])} |")
    if "model_raw" in rep["layers"]:
        out.append("")
        out.append("Model layers score the 18 rules Claude reviews; signature and 30-day timeliness are computed in code and appear only in the pattern and app rows.")

    out += ["", "## Prompt injection", "", "| Layer | Attacked cases | Attacks that cleared a targeted gap | False passes on injected records |", "| --- | --- | --- | --- |"]
    for key, L in rep["layers"].items():
        inj = L["injection"]
        fp_inj = sum(1 for e in L["errors"] if e["kind"] == "false_pass" and e["injection"])
        out.append(f"| {LAYER_NAMES.get(key, key)} | {inj['attacked_cases']} | {_short(inj['attack_success_rate'])} | {fp_inj} |")

    out += ["", "## By category (headline layer)", "", "| Category | Recall | Precision | False passes | False alarms |", "| --- | --- | --- | --- | --- |"]
    for cat, o in rep["layers"][rep["headline_layer"]]["by_category"].items():
        out.append(f"| {cat} | {_short(o['recall'])} | {_short(o['precision'])} | {o['counts']['fn']} | {o['counts']['fp']} |")

    layer_keys = list(rep["layers"])
    out += ["", "## Per rule", "", "Recall / precision per layer. With few cases per rule, treat single-rule numbers as indicative.", "",
            "| Rule | " + " | ".join(LAYER_NAMES.get(k, k) for k in layer_keys) + " |",
            "| --- |" + " --- |" * len(layer_keys)]
    for rid, rule in RULES_BY_ID.items():
        cells = []
        for k in layer_keys:
            r = rep["layers"][k]["by_rule"].get(rid)
            cells.append("not reviewed" if r is None else f"{_short(r['recall'])} / {_short(r['precision'])}")
        out.append(f"| `{rid}` {rule.title} | " + " | ".join(cells) + " |")

    head = rep["layers"][rep["headline_layer"]]
    fps = [e for e in head["errors"] if e["kind"] == "false_pass"]
    out += ["", f"## False passes ({LAYER_NAMES.get(rep['headline_layer'])})", ""]
    if not fps:
        out.append("None.")
    else:
        out += ["| Case | Rule | Label | Engine said | Why the label is a gap |", "| --- | --- | --- | --- | --- |"]
        for e in fps:
            out.append(f"| {e['case']}{' (injection)' if e['injection'] else ''} | `{e['rule']}` | {e['expected']} | {e['got']} | {e['rationale'].replace('|', '/')} |")
    others = [e for e in head["errors"] if e["kind"] != "false_pass"]
    if others:
        out += ["", f"## False alarms and applicability errors ({len(others)})", "", "| Case | Rule | Label | Engine said | Kind |", "| --- | --- | --- | --- | --- |"]
        for e in others:
            out.append(f"| {e['case']} | `{e['rule']}` | {e['expected']} | {e['got']} | {e['kind'].replace('_', ' ')} |")
    if m.get("skipped"):
        out += ["", "## Skipped cases (model layers)", ""]
        out += [f"- {cid}: {why}" for cid, why in sorted(m["skipped"].items())]
    out.append("")
    return "\n".join(out)
