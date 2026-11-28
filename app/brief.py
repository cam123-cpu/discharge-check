"""Per-patient brief built from the record's own sections (no model needed).
When a model is configured, llm.py produces a richer brief with quotes."""
from __future__ import annotations

import re

from .rules import Doc, discharge_date, parse_date

SECTION_MAP = {
    "reason": ["chief complaint", "reason for admission", "admission diagnosis", "history of present illness"],
    "course": ["brief hospital course", "hospital course", "summary of hospitalization"],
    "diagnoses": ["discharge diagnosis", "discharge diagnoses", "final diagnosis", "principal diagnosis"],
    "medications": ["discharge medications", "medications on discharge", "discharge medication list"],
    "changes": ["medication changes", "medications stopped", "changes to medications"],
    "allergies": ["allergies"],
    "followup": ["followup instructions", "follow-up instructions", "follow up instructions", "follow-up", "follow-up appointments"],
    "pending": ["pending results", "pending labs", "pending tests", "results pending at discharge"],
    "disposition": ["discharge disposition", "disposition"],
    "goals": ["goals of care", "code status", "treatment preferences"],
    "function": ["functional status", "activity", "mobility"],
}


def _lines(text: str, limit: int) -> list[str]:
    out = []
    for ln in text.split("\n"):
        if not ln.strip() and out:
            break  # a blank line ends a list section; trailing prose belongs elsewhere
        ln = re.sub(r"^\s*(?:[-*•]|\d+[.)])\s*", "", ln).strip()
        if ln:
            out.append(ln[:300])
        if len(out) >= limit:
            break
    return out


def _first_sentences(text: str, n: int = 3) -> str:
    flat = " ".join(text.split())
    parts = re.split(r"(?<=[.!?])\s+", flat)
    return " ".join(parts[:n])[:900]


def _find(docs: list[Doc], keys: list[str]) -> str:
    order = {"discharge_summary": 0, "case_management": 1, "nursing_instructions": 2}
    for d in sorted(docs, key=lambda d: order.get(d.kind, 9)):
        for k in keys:
            if d.sections.get(k):
                return d.sections[k]
    return ""


def build_brief(docs: list[Doc], discharge_hint: str = "") -> dict:
    get = {name: _find(docs, keys) for name, keys in SECTION_MAP.items()}
    admit = None
    for d in docs:
        m = re.search(r"\badmission date[ \t]*:[ \t]*(\S{1,40})", d.text, re.I)
        if m:
            admit = parse_date(m.group(1))
            break
    dc = discharge_date(docs, discharge_hint)
    los = (dc - admit).days if admit and dc else None
    return {
        "engine": "pattern",
        "admission_date": admit.isoformat() if admit else "",
        "discharge_date": dc.isoformat() if dc else "",
        "length_of_stay_days": los,
        "reason": _first_sentences(get["reason"], 2),
        "hospital_course": _first_sentences(get["course"], 4),
        "diagnoses": _lines(get["diagnoses"], 8),
        "medications": _lines(get["medications"], 25),
        "medication_changes": _lines(get["changes"], 12),
        "allergies": _lines(get["allergies"], 6),
        "follow_up": _lines(get["followup"], 8),
        "pending": _lines(get["pending"], 8),
        "disposition": _first_sentences(get["disposition"], 1),
        "goals_of_care": _first_sentences(get["goals"], 2),
        "functional_status": _first_sentences(get["function"], 2),
    }
