"""Rule library and the deterministic (pattern) checker.

The rule library is data (rules.json), so a hospital can add rules for its
own policies or its state's deadlines without code changes. The pattern
checker always runs; when an Anthropic key is configured, the model-based
checker in llm.py refines it."""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import date, datetime
from pathlib import Path

from .ingest import split_sections

RULES_PATH = Path(__file__).with_name("rules.json")


@dataclass
class Rule:
    id: str
    group: str
    title: str
    citation: str
    kinds: list[str]
    sections: list[str]
    patterns: list[str]
    question: str
    fix: str
    min_chars: int = 0
    needs_timeframe: bool = False
    post_acute_only: bool = False
    deterministic_only: bool = False
    cross_document: bool = False


@dataclass
class Doc:
    index: int
    kind: str
    filename: str
    text: str
    author: str = ""
    sections: dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        if not self.sections:
            self.sections = split_sections(self.text)


@dataclass
class Finding:
    rule_id: str
    status: str  # pass | fail | unclear | not_applicable
    evidence: str = ""
    source: str = ""
    note: str = ""
    engine: str = "pattern"
    pattern_status: str = ""  # pattern result when it differs from the stored status
    model_status: str = ""  # model result when it differs from the stored status

    def to_dict(self):
        return asdict(self)


def load_rules(path: Path = RULES_PATH) -> tuple[list[Rule], re.Pattern, str]:
    data = json.loads(path.read_text())
    rules = [Rule(**r) for r in data["rules"]]
    return rules, re.compile(data["post_acute_pattern"], re.I), data["version"]


RULES, POST_ACUTE, RULES_VERSION = load_rules()
RULES_BY_ID = {r.id: r for r in RULES}

_NEGATED = re.compile(
    r"\b(not (yet )?(discussed|addressed|documented|done|arranged|scheduled|completed)|none documented|unknown|tbd|to be determined|deferred)\b",
    re.I,
)
_TIMEFRAME = re.compile(
    r"(\b\d{4}-\d{2}-\d{2}\b|\b\d{1,2}/\d{1,2}(/\d{2,4})?\b|\bwithin \d+\s*(days?|weeks?)\b|\bin \d+\s*(-\s*\d+\s*)?(days?|weeks?|months?)\b|"
    r"\b(mon|tues|wednes|thurs|fri|satur|sun)day\b|\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.? \d{1,2}\b)",
    re.I,
)
_DATE = re.compile(r"\b(\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{4})\b")
_TIME = re.compile(r"\b([01]?\d|2[0-3]):[0-5]\d\b")
_SIGNED = re.compile(r"^[^\n]*\b(electronically signed|signed by|e-signed|authenticated by|attestation)\b[^\n]*$", re.I | re.M)
_DISCHARGE_DATE = re.compile(r"\bdischarge date\s*:\s*(\S+)", re.I)


def _clip(s: str, n: int = 240) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 3] + "..."


def _line_at(text: str, pos: int) -> str:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    return text[start : end if end != -1 else len(text)]


def parse_date(s: str) -> date | None:
    s = s.strip().rstrip(".,")
    for fmt in ("%Y-%m-%d", "%m/%d/%Y"):
        try:
            return datetime.strptime(s, fmt).date()
        except ValueError:
            continue
    return None


def is_post_acute(docs: list[Doc], disposition_hint: str = "") -> bool:
    if POST_ACUTE.search(disposition_hint or ""):
        return True
    for d in docs:
        for key in ("discharge disposition", "disposition"):
            if key in d.sections and POST_ACUTE.search(d.sections[key]):
                return True
    return False


RECORD_DEADLINE_DAYS = 30


def days_until_deadline(discharge: str | date | None, today: date | None = None) -> int | None:
    """Days remaining in the 30-day completion window. Negative means past it."""
    today = today or date.today()
    if isinstance(discharge, date):
        dc: date | None = discharge
    elif isinstance(discharge, str) and discharge:
        dc = parse_date(discharge)
    else:
        dc = None
    if dc is None:
        return None
    return RECORD_DEADLINE_DAYS - (today - dc).days


def discharge_date(docs: list[Doc], hint: str = "") -> date | None:
    if hint:
        d = parse_date(hint)
        if d:
            return d
    for doc in docs:
        m = _DISCHARGE_DATE.search(doc.text)
        if m:
            d = parse_date(m.group(1))
            if d:
                return d
    return None


_MED_LINE = re.compile(r"^\s*(?:[-*•]|\d+[.)])\s*([A-Za-z][A-Za-z-]{2,})", re.M)
_MED_STOP = {"take", "the", "and", "new", "continue", "stop", "start", "hold", "resume", "none", "medications", "changed", "increase", "decrease"}


def med_names(section_text: str) -> set[str]:
    names = set()
    for m in _MED_LINE.finditer(section_text):
        w = m.group(1).lower()
        if w not in _MED_STOP:
            names.add(w)
    return names


def _med_section(doc: Doc) -> str:
    for key, val in doc.sections.items():
        if "medication" in key and "stopped" not in key and "allerg" not in key:
            return val
    return ""


# ---------------- individual checks ----------------

def _check_generic(rule: Rule, docs: list[Doc]) -> Finding:
    candidates = [d for d in docs if d.kind in rule.kinds] or []
    if not candidates:
        names = ", ".join(k.replace("_", " ") for k in rule.kinds)
        return Finding(rule.id, "fail", note=f"No {names} uploaded for this patient.")
    weak: Finding | None = None
    for d in candidates:
        for key in rule.sections:
            body = d.sections.get(key)
            if body is None:
                continue
            first = next((ln for ln in body.split("\n") if ln.strip()), "")
            if not body.strip():
                weak = weak or Finding(rule.id, "fail", source=d.filename, note=f"Section '{key}' is empty.")
                continue
            if _NEGATED.search(body[:300]):
                weak = Finding(rule.id, "unclear", _clip(first), d.filename, "Section is present but says it was not done or is unknown.")
                continue
            if rule.min_chars and len(body) < rule.min_chars:
                weak = Finding(rule.id, "unclear", _clip(first), d.filename, "Section is very short; outcome may not be described.")
                continue
            if rule.needs_timeframe and not _TIMEFRAME.search(body):
                weak = Finding(rule.id, "unclear", _clip(first), d.filename, "Follow-up is listed but no date or timeframe was found.")
                continue
            return Finding(rule.id, "pass", _clip(f"{key.title()}: {first}"), d.filename)
        for pat in rule.patterns:
            m = re.search(pat, d.text, re.I)
            if m:
                line = _line_at(d.text, m.start())
                if _NEGATED.search(line):
                    weak = Finding(rule.id, "unclear", _clip(line), d.filename, "Mentioned, but the note says it was not done or is unknown.")
                    continue
                if rule.needs_timeframe and not _TIMEFRAME.search(line):
                    weak = weak or Finding(rule.id, "unclear", _clip(line), d.filename, "No date or timeframe found.")
                    continue
                return Finding(rule.id, "pass", _clip(line), d.filename)
    return weak or Finding(rule.id, "fail", note="Not found in the uploaded documents.")


def _check_authenticated(rule: Rule, docs: list[Doc]) -> Finding:
    summaries = [d for d in docs if d.kind == "discharge_summary"]
    if not summaries:
        return Finding(rule.id, "fail", note="No discharge summary uploaded.")
    for d in summaries:
        m = _SIGNED.search(d.text)
        if m:
            line = m.group(0)
            has_date, has_time = bool(_DATE.search(line)), bool(_TIME.search(line))
            if has_date and has_time:
                return Finding(rule.id, "pass", _clip(line), d.filename)
            missing = " and ".join(x for x, ok in (("date", has_date), ("time", has_time)) if not ok)
            return Finding(rule.id, "fail", _clip(line), d.filename, f"Signature line has no {missing}.")
    return Finding(rule.id, "fail", source=summaries[0].filename, note="No signature line found; the summary looks unsigned.")


def _check_timeliness(rule: Rule, docs: list[Doc], dc_date: date | None, today: date) -> Finding:
    if dc_date is None:
        return Finding(rule.id, "unclear", note="Discharge date not found, so the 30-day deadline cannot be checked.")
    for d in docs:
        if d.kind != "discharge_summary":
            continue
        m = _SIGNED.search(d.text)
        if m:
            dm = _DATE.search(m.group(0))
            signed = parse_date(dm.group(1)) if dm else None
            if signed:
                days = (signed - dc_date).days
                status = "pass" if days <= 30 else "fail"
                return Finding(rule.id, status, _clip(m.group(0)), d.filename, f"Signed {days} days after discharge on {dc_date.isoformat()}.")
    elapsed = (today - dc_date).days
    if elapsed > 30:
        return Finding(rule.id, "fail", note=f"Unsigned {elapsed} days after discharge; the record is delinquent.")
    return Finding(rule.id, "unclear", note=f"Not signed yet. {30 - elapsed} days remain before the 30-day limit.")


def medication_reconciliation(docs: list[Doc]) -> dict:
    """Compare medication names in the summary and the nursing instructions."""
    summary = next((d for d in docs if d.kind == "discharge_summary"), None)
    nursing = next((d for d in docs if d.kind == "nursing_instructions"), None)
    empty = {"only_summary": [], "only_nursing": [], "shared": []}
    if not nursing:
        return {**empty, "status": "not_applicable", "note": "No nursing discharge instructions uploaded."}
    if not summary:
        return {**empty, "status": "unclear", "note": "No discharge summary to compare against."}
    a, b = med_names(_med_section(summary)), med_names(_med_section(nursing))
    if not a or not b:
        return {**empty, "status": "unclear", "note": "Could not find a medication list in both documents."}
    only_a, only_b, shared = sorted(a - b), sorted(b - a), sorted(a & b)
    if not only_a and not only_b:
        return {"status": "pass", "only_summary": [], "only_nursing": [], "shared": shared,
                "note": f"Both documents list the same {len(a)} medications."}
    parts = []
    if only_a:
        parts.append("only in summary: " + ", ".join(only_a))
    if only_b:
        parts.append("only in nursing instructions: " + ", ".join(only_b))
    return {"status": "fail", "only_summary": only_a, "only_nursing": only_b, "shared": shared,
            "note": "Medication lists differ (" + "; ".join(parts) + ")."}


def _check_meds_consistent(rule: Rule, docs: list[Doc]) -> Finding:
    diff = medication_reconciliation(docs)
    summary = next((d for d in docs if d.kind == "discharge_summary"), None)
    nursing = next((d for d in docs if d.kind == "nursing_instructions"), None)
    names = [d.filename for d in (summary, nursing) if d is not None]
    return Finding(rule.id, diff["status"], note=diff["note"], source=", ".join(names))


def run_pattern_checks(docs: list[Doc], disposition_hint: str = "", discharge_hint: str = "", today: date | None = None) -> list[Finding]:
    today = today or date.today()
    post_acute = is_post_acute(docs, disposition_hint)
    dc = discharge_date(docs, discharge_hint)
    out = []
    for rule in RULES:
        if rule.post_acute_only and not post_acute:
            out.append(Finding(rule.id, "not_applicable", note="Applies only to home health, SNF, IRF or LTCH referrals."))
        elif rule.id == "authenticated":
            out.append(_check_authenticated(rule, docs))
        elif rule.id == "timeliness":
            out.append(_check_timeliness(rule, docs, dc, today))
        elif rule.id == "meds_consistent":
            out.append(_check_meds_consistent(rule, docs))
        else:
            out.append(_check_generic(rule, docs))
    return out


def tally(findings: list[Finding]) -> dict[str, int]:
    t = {"pass": 0, "fail": 0, "unclear": 0, "not_applicable": 0}
    for f in findings:
        t[f.status] += 1
    return t
