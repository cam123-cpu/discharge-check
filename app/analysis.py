"""Runs the checks for one patient and stores the result."""
from __future__ import annotations

import json
from datetime import date

import anthropic

from . import llm
from .brief import build_brief
from .rules import RULES, RULES_VERSION, Doc, Finding, is_post_acute, medication_reconciliation, run_pattern_checks, tally

# Lower is more cautious. A model result may move a rule down this scale.
# It may not move a rule up: a quoted sentence is not enough to clear a miss.
_SEVERITY = {"fail": 0, "unclear": 1, "pass": 2}


def merge(pattern: list[Finding], model: dict[str, Finding]) -> list[Finding]:
    out = []
    for f in pattern:
        m = model.get(f.rule_id)
        if m is None:
            out.append(f)
            continue
        if f.status not in _SEVERITY or m.status not in _SEVERITY:
            if m.status != f.status:
                f.pattern_status = f.status
                f.model_status = m.status
            out.append(f)
            continue
        if m.status == f.status:
            # Agreement. The pattern line stays under the citation.
            out.append(f)
            continue
        if _SEVERITY[m.status] < _SEVERITY[f.status]:
            # A harsher model call with no quote is a doubt, not a miss the
            # queue can count. A quoted harsher call may still lower the status.
            if m.status == "fail" and not (m.evidence or "").strip():
                doubt = Finding(
                    f.rule_id, "unclear", f.evidence, f.source,
                    note=m.note or "Model review added a doubt and did not quote the record.",
                    engine="model",
                )
                doubt.pattern_status = f.status
                doubt.model_status = m.status
                out.append(doubt)
            else:
                m.pattern_status = f.status
                m.model_status = m.status
                out.append(m)
        else:
            f.pattern_status = f.status
            f.model_status = m.status
            out.append(f)
    return out


def analyze(docs: list[Doc], *, disposition_hint: str, discharge_hint: str, client: anthropic.Anthropic | None,
            model: str, today: date | None = None) -> dict:
    pattern = run_pattern_checks(docs, disposition_hint, discharge_hint, today)
    brief = build_brief(docs, discharge_hint)
    engine, message, model_brief = "pattern", "", None
    findings = pattern
    if client is not None and docs:
        try:
            model_brief, model_findings = llm.review(client, model, docs, is_post_acute(docs, disposition_hint))
            findings = merge(pattern, model_findings)
            engine = "model"
        except llm.LLMUnavailable as exc:
            message = f"{exc} Showing pattern-check results only."
    return {
        "engine": engine,
        "message": message,
        "rules_version": RULES_VERSION,
        "brief": brief,
        "model_brief": model_brief,
        "medication_reconciliation": medication_reconciliation(docs),
        "findings": [f.to_dict() for f in findings],
        "tally": tally(findings),
        "document_ids": [d.doc_id for d in docs if d.doc_id],
    }


def store(db, conn, cipher, org_id: int, patient_id: int, user_id: int, result: dict) -> int:
    t = result["tally"]
    cur = conn.execute(
        """INSERT INTO analyses (org_id, patient_id, engine, result_enc, passed, failed, unclear, created_by)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (org_id, patient_id, result["engine"], cipher.encrypt(json.dumps(result)), t["pass"], t["fail"], t["unclear"], user_id),
    )
    # Rule-level status stays inside result_enc. A plaintext findings row would
    # let a copied database show which clinical rules failed, and a tampered
    # row could change the dashboard without breaking the sealed blob.
    return cur.lastrowid


RULE_ORDER = [r.id for r in RULES]
