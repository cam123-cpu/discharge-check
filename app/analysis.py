"""Runs the checks for one patient and stores the result."""
from __future__ import annotations

import json
from datetime import date

import anthropic

from . import llm
from .brief import build_brief
from .ingest import injection_signals
from .rules import RULES, RULES_VERSION, Doc, Finding, is_post_acute, run_pattern_checks, tally


GUARD_NOTE = ("The record contains text aimed at an AI reviewer, so the model cannot mark this complete "
              "on its own. A person needs to confirm it. ")


def merge(pattern: list[Finding], model: dict[str, Finding], guarded: bool = False) -> list[Finding]:
    """Model findings replace pattern findings. When the record looks like it
    is trying to steer the model (guarded), the model may only make a result
    stricter: it can flag a gap the patterns missed, never clear one."""
    out = []
    for f in pattern:
        m = model.get(f.rule_id)
        if m is None:
            out.append(f)
            continue
        if guarded and m.status == "pass" and f.status != "pass":
            m.status, m.note = "unclear", GUARD_NOTE + m.note
        if m.status != f.status:
            m.pattern_status = f.status
        out.append(m)
    return out


def analyze(docs: list[Doc], *, disposition_hint: str, discharge_hint: str, client: anthropic.Anthropic | None,
            model: str, today: date | None = None) -> dict:
    pattern = run_pattern_checks(docs, disposition_hint, discharge_hint, today)
    brief = build_brief(docs, discharge_hint)
    engine, message, model_brief = "pattern", "", None
    findings = pattern
    guarded = any(injection_signals(d.text) for d in docs)
    if client is not None and docs:
        try:
            model_brief, model_findings = llm.review(client, model, docs, is_post_acute(docs, disposition_hint))
            findings = merge(pattern, model_findings, guarded)
            engine = "model"
        except llm.LLMUnavailable as exc:
            message = f"{exc} Showing pattern-check results only."
    return {
        "engine": engine,
        "message": message,
        "guarded": guarded,
        "rules_version": RULES_VERSION,
        "brief": brief,
        "model_brief": model_brief,
        "findings": [f.to_dict() for f in findings],
        "tally": tally(findings),
    }


def store(db, conn, cipher, org_id: int, patient_id: int, user_id: int, result: dict) -> int:
    t = result["tally"]
    cur = conn.execute(
        """INSERT INTO analyses (org_id, patient_id, engine, result_enc, passed, failed, unclear, created_by)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (org_id, patient_id, result["engine"], cipher.encrypt(json.dumps(result)), t["pass"], t["fail"], t["unclear"], user_id),
    )
    aid = cur.lastrowid
    conn.executemany(
        "INSERT INTO findings (org_id, analysis_id, patient_id, rule_id, status) VALUES (?, ?, ?, ?, ?)",
        [(org_id, aid, patient_id, f["rule_id"], f["status"]) for f in result["findings"]],
    )
    return aid


RULE_ORDER = [r.id for r in RULES]
