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

from .ingest import _HEADER, injection_lines, split_sections

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
    pattern_status: str = ""  # what the pattern checker said, when the model overrode it

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
# Wording that says an element was not done, or will only be done later.
# Checked on the sentence that matched (and the one after it), never on a
# whole note, so a "not" elsewhere on the line does not cancel real evidence.
_NOT_DONE = re.compile(
    r"\b(never|nobody|no one|refused to|declined to (discuss|address|go over|review|participate)"
    r"|unable to participate|not able to|would have (preferred|liked|wanted)|rejected|unsuccessful|failed to (send|transmit|reach)"
    r"|not (yet )?(been )?(offered|given|provided|shared|reviewed|assigned|transmitted|sent|faxed|routed|received|established|reached|signed|authenticated)"
    r"|no\b[^.;\n]{0,40}\b(was|were) (given|offered|provided|shared|reviewed|discussed))\b",
    re.I,
)
_HEDGED = re.compile(
    r"\b(will likely|may need|might need|plan to have|planned to have"
    r"|to be (faxed|sent|routed|transmitted|forwarded|completed|reviewed|scheduled|arranged|discussed|done)"
    r"|will be (faxed|sent|routed|transmitted|forwarded|completed|reviewed|discussed|done)"
    r"|once (signed|established|assigned|available|she|he|they|the patient)"
    r"|if (symptoms|palpitations|pain|it) (persist|persists|continue|continues))\b",
    re.I,
)
# A section that only points somewhere else ("See progress note", "Per CM").
_POINTER = re.compile(
    r"^[ \t]*(see|per|refer to|referred to|as per|as documented in|reference|in the)\b[^\n]{0,80}$"
    r"|\b(see|in) (the )?(reconciled |separate |attached )?(medication list in the )?(patient portal|transfer MAR|MAR|EHR|chart)\b",
    re.I,
)
_NONE_VALUE = re.compile(r"^[ \t]*(none|n/?a|unknown|nil|not applicable|-+|_+)[ \t]*([.;,]|$)", re.I)
_TIMEFRAME = re.compile(
    r"(\b\d{4}-\d{2}-\d{2}\b|\b\d{1,2}/\d{1,2}(/\d{2,4})?\b|\bwithin \d+\s*(days?|weeks?)\b|\bin \d+\s*(-\s*\d+\s*)?(days?|weeks?|months?)\b|"
    r"\b(mon|tues|wednes|thurs|fri|satur|sun)day\b|\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.? \d{1,2}\b)",
    re.I,
)
_DATE = re.compile(r"\b(\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{4})\b")
_TIME = re.compile(r"\b([01]?\d|2[0-3]):[0-5]\d\b")
# A signature line starts with the signing phrase; "signed by patient" in the
# middle of a POLST sentence, or a "QA attestation", is not the author signing.
_SIGNED = re.compile(
    r"^[ \t]*(?:(?:attending|physician|provider|author)[ \t]+)?"
    r"(?:electronically signed|e-?signed|digitally signed|signed|authenticated|attested)(?:[ \t]+by)?[ \t]*:?[ \t]*([^\n]*)$",
    re.I | re.M,
)
_SIGNATURE_LINE = re.compile(r"^[ \t]*(?:(?:attending|physician|provider|author)[ \t]+)?signature[ \t]*:[ \t]*([^\n]*)$", re.I | re.M)
_NOT_A_SIGNER = re.compile(r"\b(on file|pending|unsigned|not (yet )?(signed|authenticated)|to follow|QA|compliance|patient|family)\b|_{3,}", re.I)
_SIGNER_NAME = re.compile(r"(?-i:\b(?:Dr\.?\s+)?[A-Z][a-z'-]+(?:[ -][A-Z][a-z'-]+)+)")
_DISCHARGE_DATE = re.compile(r"\bdischarge date[ \t]*:[ \t]*(\S{1,40})", re.I)
_PERIOD_END = re.compile(r"(?<!\bDr)(?<!\bMr)(?<!\bMs)(?<!\bMrs)(?<!\bSt)\.\s+(?=[A-Z(])")
_SENTENCE_END = re.compile(r"(?<!\bDr)(?<!\bMr)(?<!\bMs)(?<!\bMrs)(?<!\bSt)[.;]\s+(?=[A-Z(])")

# ---------------- text the pattern engine must not count as evidence ----------------

_HTML_COMMENT = re.compile(r"<!--.*?(-->|\Z)", re.S)
_TEMPLATE_HEADER = re.compile(r"\b(template|default|boilerplate) (text|phrases?|language)\b[^\n]{0,40}\b(do not use|delete before signing|not for use)\b|\bdo not use\b[^\n]{0,20}:\s*$", re.I)
_COPIED_START = re.compile(r"^[ \t]*-{2,}[ \t]*(copied|carried) forward\b", re.I)
_COPIED_END = re.compile(r"^[ \t]*-{2,}[ \t]*end of (copied|carried)", re.I)
_UNCHECKED = re.compile(r"^[ \t]*\[[ \t]?\]")
_CHECKED = re.compile(r"^([ \t]*)\[[xX✓✔][ \t]?\][ \t]*")
_BLANK_FIELD = re.compile(r":[ \t]*_{3,}[ \t]*$")


_SCREENED = "Screened Out:"


def template_signals(text: str) -> bool:
    """Unused template text kept in a note ("Template Text - Do Not Use")."""
    return any(_TEMPLATE_HEADER.search(ln) for ln in text.split("\n"))


def screen_text(text: str) -> str:
    """The note as the pattern engine reads it. Drops what a surveyor would not
    accept as documentation: HTML comments, unused template blocks, text copied
    forward from another note, unchecked boxes, blank fill-in fields, and any
    line addressed to a reviewer. Removing text can only turn a pass into a
    gap, never the reverse."""
    text = _HTML_COMMENT.sub("", text)
    lines = text.split("\n")
    untrusted = injection_lines(text)
    empty: set[int] = set()
    in_template = in_copied = False
    for i, ln in enumerate(lines):
        if in_template and not ln.strip():
            in_template = False
        if _TEMPLATE_HEADER.search(ln):
            in_template = True
        if _COPIED_START.search(ln):
            in_copied = True
        if in_template or in_copied:
            untrusted.add(i)
        elif _UNCHECKED.match(ln) or _BLANK_FIELD.search(ln):
            empty.add(i)
        if in_copied and _COPIED_END.search(ln):
            in_copied = False
    out = []
    for i, ln in enumerate(lines):
        if i in untrusted:
            # A header in place of the removed block, so the section before it
            # ends where it ended in the original note.
            if not out or out[-1] != _SCREENED:
                out.append(_SCREENED)
        elif i not in empty:
            out.append(_CHECKED.sub(r"\1", ln))
    return "\n".join(out)


def screened(docs: list[Doc]) -> list[Doc]:
    return [Doc(d.index, d.kind, d.filename, screen_text(d.text), d.author) for d in docs]


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


_MED_LINE = re.compile(r"^[ \t]*(?:[-*•]|\d{1,3}[.)])[ \t]*([A-Za-z][A-Za-z-]{2,40})", re.M)
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

def _sentence_at(text: str, start: int, end: int) -> str:
    """The sentence holding text[start:end], plus the next sentence on the same
    line (so "Faxed to Dr. Ruiz. Never transmitted." reads as one claim)."""
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    line_end = len(text) if line_end == -1 else line_end
    line = text[line_start:line_end]
    a, b = start - line_start, end - line_start
    cuts = [0] + [m.end() for m in _SENTENCE_END.finditer(line)] + [len(line)]
    i = max(k for k in range(len(cuts) - 1) if cuts[k] <= a)
    j = min(len(cuts) - 1, next(k for k in range(i + 1, len(cuts)) if cuts[k] >= b) + 1)
    return line[cuts[i] : cuts[j]]


def _is_rule_header(line: str, rule: Rule) -> bool:
    m = _HEADER.match(line)
    return bool(m) and m.group(1).strip().lower() in rule.sections


_DOSE = re.compile(r"\b\d+(\.\d+)?\s*(mg|mcg|g|units?|mEq|mL|%|puffs?|tablets?|capsules?)\b", re.I)
_PENDING_ITEM = re.compile(r"\b(pending|outstanding|in process|awaiting|not yet (resulted|final))\b", re.I)
_NONE_PENDING = re.compile(r"^[ \t]*(none\b|no (tests?|results?|labs?|studies)\b[^\n]{0,20}\bpending|nothing pending)", re.I)
_PENDING_OWNER = re.compile(
    r"(\b(Dr\.?\s+[A-Z][\w'-]*|PCP|primary care|team|clinic|office|service|attending|physician|oncology|cardiology|GI|nephrology|surgery)\b[^\n]{0,60}"
    r"\b(will|to)\b[^\n]{0,20}\b(follow|review|call|forward|route|notify|contact|track|check)"
    r"|\b(route|forward|send|go)s? to (Dr\.?\s+[A-Z]|the PCP|the (\w+ )?team)"
    r"|\bfollowed (up )?by (Dr\.?\s+[A-Z]|the PCP|the (\w+ )?team))"
)
_STILL_PENDING = re.compile(
    r"\b(remains?|still|currently) (in process|pending|outstanding)\b|\b(in process|pending|outstanding) at (the time of )?discharge\b"
    r"|\bno growth to date\b|\bfinal (read|result|report) (is )?(due|pending|outstanding)\b|\bawaiting (the )?(final|result)",
    re.I,
)
_CODE_LIMITED = re.compile(r"\b(DNR|DNI|do not resuscitate|do not intubate|comfort (measures|care) only|allow natural death)\b", re.I)
_CODE_FULL = re.compile(r"\bfull code\b", re.I)


# Sections whose prose describes the stay; "never needed oxygen" there is
# clinical content, not a missing element.
_NARRATIVE = {"hospital_course", "discharge_condition", "final_diagnosis", "functional_status"}


def _section_problem(rule: Rule, key: str, body: str) -> tuple[str, str] | None:
    """Why a present section is not evidence for the rule, or None if it is."""
    first300 = body[:300]
    first_line = next((ln for ln in body.split("\n") if ln.strip()), "")
    cut = _PERIOD_END.search(first_line)
    lead = "" if rule.id in _NARRATIVE else first_line[: cut.end()] if cut else first_line
    if rule.id not in ("pending_results", "med_changes") and _NONE_VALUE.match(body):
        return "fail", f"Section '{key}' says none."
    if _POINTER.search(body) and len(body) < 160:
        return "unclear", "Section only points to another document; the content itself is not here."
    if _NEGATED.search(first300) or _NOT_DONE.search(lead):
        return "unclear", "Section is present but says it was not done or is unknown."
    if _HEDGED.search(lead):
        return "unclear", "Section describes something planned or likely, not something done."
    if rule.min_chars and len(body) < rule.min_chars:
        return "unclear", "Section is very short; outcome may not be described."
    if rule.needs_timeframe and not _TIMEFRAME.search(body):
        return "unclear", "Follow-up is listed but no date or timeframe was found."
    if rule.id == "discharge_meds" and not _DOSE.search(body):
        return "unclear", "Section names no medication with a dose; it may not be the list itself."
    if rule.id == "pending_results" and not _NONE_PENDING.match(body) and _PENDING_ITEM.search(body) and not _PENDING_OWNER.search(body):
        return "unclear", "Results are listed as pending but no one is named to follow them up."
    return None


# Rules whose evidence is a claim that something was done for the patient
# (a list given, a choice offered, data shared, a summary sent). For these, a
# sentence elsewhere saying it was not done makes the record contradictory.
_CONTRADICTABLE = {"info_transmitted", "pac_list", "pac_choice", "pac_quality_data"}
# A choice among providers needs the list, so "not offered a list" also
# contradicts a claimed choice.
_CONTRADICTED_BY = {"pac_choice": ("pac_list",)}


def _contradiction(rule: Rule, docs: list[Doc], passed: Finding) -> Finding | None:
    """A pass is downgraded when the record also says the opposite."""
    if rule.id == "goals_of_care":
        limited = [(d, m) for d in docs for m in [_CODE_LIMITED.search(d.text)] if m]
        full = [(d, m) for d in docs for m in [_CODE_FULL.search(d.text)] if m]
        if limited and full:
            (d1, m1), (d2, m2) = limited[0], full[0]
            return Finding(rule.id, "unclear", _clip(_line_at(d1.text, m1.start())), f"{d1.filename}, {d2.filename}",
                           f"The record contradicts itself on code status ({_clip(_line_at(d2.text, m2.start()), 120)}).")
    if rule.id == "pending_results":
        for d in docs:
            if d.kind != "discharge_summary":
                continue
            body = next((d.sections[k] for k in rule.sections if k in d.sections), "")
            if body and _NONE_PENDING.match(body):
                rest = "\n".join(ln for ln in d.text.split("\n") if not _is_rule_header(ln, rule) and ln.strip() not in body)
                m = _STILL_PENDING.search(rest)
                if m:
                    return Finding(rule.id, "unclear", _clip(_line_at(rest, m.start())), d.filename,
                                   "The summary says nothing is pending, but elsewhere describes a result still outstanding.")
    if rule.id not in _CONTRADICTABLE:
        return None
    patterns = list(rule.patterns) + [p for rid in _CONTRADICTED_BY.get(rule.id, ()) for p in RULES_BY_ID[rid].patterns]
    for d in docs:
        if d.kind not in rule.kinds:
            continue
        for pat in patterns:
            for m in re.finditer(pat, d.text, re.I):
                sent = _sentence_at(d.text, m.start(), m.end())
                if _NOT_DONE.search(sent) or _NEGATED.search(sent):
                    return Finding(rule.id, "unclear", _clip(sent), d.filename,
                                   f"The record contradicts itself: '{_clip(passed.evidence, 100)}' but also this.")
    return None


def _check_generic(rule: Rule, docs: list[Doc]) -> Finding:
    candidates = [d for d in docs if d.kind in rule.kinds] or []
    if not candidates:
        names = ", ".join(k.replace("_", " ") for k in rule.kinds)
        return Finding(rule.id, "fail", note=f"No {names} uploaded for this patient.")
    weak: Finding | None = None
    found: Finding | None = None
    for d in candidates:
        for key in rule.sections:
            body = d.sections.get(key)
            if body is None:
                continue
            first = next((ln for ln in body.split("\n") if ln.strip()), "")
            if not body.strip():
                weak = weak or Finding(rule.id, "fail", source=d.filename, note=f"Section '{key}' is empty.")
                continue
            problem = _section_problem(rule, key, body)
            if problem:
                weak = Finding(rule.id, problem[0], _clip(first), d.filename, problem[1])
                continue
            found = Finding(rule.id, "pass", _clip(f"{key.title()}: {first}"), d.filename)
            break
        if found:
            break
        for pat in rule.patterns:
            for m in re.finditer(pat, d.text, re.I):
                line = _line_at(d.text, m.start())
                if _is_rule_header(line, rule):
                    continue  # the section itself was judged above
                sent = _sentence_at(d.text, m.start(), m.end())
                if _NEGATED.search(sent) or _NOT_DONE.search(sent):
                    weak = Finding(rule.id, "unclear", _clip(sent), d.filename, "Mentioned, but the note says it was not done or is unknown.")
                    continue
                if _HEDGED.search(sent):
                    weak = Finding(rule.id, "unclear", _clip(sent), d.filename, "Mentioned only as something planned or likely, not done.")
                    continue
                if rule.needs_timeframe and not _TIMEFRAME.search(line):
                    weak = weak or Finding(rule.id, "unclear", _clip(line), d.filename, "No date or timeframe found.")
                    continue
                found = Finding(rule.id, "pass", _clip(line), d.filename)
                break
            if found:
                break
        if found:
            break
    if found:
        return _contradiction(rule, docs, found) or found
    return weak or Finding(rule.id, "fail", note="Not found in the uploaded documents.")


def _signature(doc: Doc) -> tuple[str, str] | None:
    """(line, problem) for the note's last author signature line. problem is
    "" when the line names a signer and carries a date and a time. Returns
    None when the note has no signature line at all."""
    best: tuple[int, str, str] | None = None
    for rx in (_SIGNED, _SIGNATURE_LINE):
        for m in rx.finditer(doc.text):
            line, rest = m.group(0).strip(), m.group(1)
            if _NOT_A_SIGNER.search(rest) or not _SIGNER_NAME.search(rest):
                problem = "The signature line names no signer (blank, pending or 'on file')."
            else:
                missing = " and ".join(x for x, ok in (("date", _DATE.search(line)), ("time", _TIME.search(line))) if not ok)
                problem = f"Signature line has no {missing}." if missing else ""
            if best is None or m.start() > best[0]:
                best = (m.start(), line, problem)
    return (best[1], best[2]) if best else None


def _check_authenticated(rule: Rule, docs: list[Doc]) -> Finding:
    summaries = [d for d in docs if d.kind == "discharge_summary"]
    if not summaries:
        return Finding(rule.id, "fail", note="No discharge summary uploaded.")
    first_problem: Finding | None = None
    for d in summaries:
        sig = _signature(d)
        if sig is None:
            continue
        line, problem = sig
        if not problem:
            return Finding(rule.id, "pass", _clip(line), d.filename)
        first_problem = first_problem or Finding(rule.id, "fail", _clip(line), d.filename, problem)
    return first_problem or Finding(rule.id, "fail", source=summaries[0].filename, note="No signature line found; the summary looks unsigned.")


def _check_timeliness(rule: Rule, docs: list[Doc], dc_date: date | None, today: date) -> Finding:
    if dc_date is None:
        return Finding(rule.id, "unclear", note="Discharge date not found, so the 30-day deadline cannot be checked.")
    for d in docs:
        if d.kind != "discharge_summary":
            continue
        sig = _signature(d)
        if sig and (not sig[1] or sig[1] == "Signature line has no time."):
            dm = _DATE.search(sig[0])
            signed = parse_date(dm.group(1)) if dm else None
            if signed:
                days = (signed - dc_date).days
                status = "pass" if days <= 30 else "fail"
                return Finding(rule.id, status, _clip(sig[0]), d.filename, f"Signed {days} days after discharge on {dc_date.isoformat()}.")
    elapsed = (today - dc_date).days
    if elapsed > 30:
        return Finding(rule.id, "fail", note=f"Unsigned {elapsed} days after discharge; the record is delinquent.")
    return Finding(rule.id, "unclear", note=f"Not signed yet. {30 - elapsed} days remain before the 30-day limit.")


def _check_meds_consistent(rule: Rule, docs: list[Doc]) -> Finding:
    summary = next((d for d in docs if d.kind == "discharge_summary"), None)
    nursing = next((d for d in docs if d.kind == "nursing_instructions"), None)
    if not nursing:
        return Finding(rule.id, "not_applicable", note="No nursing discharge instructions uploaded.")
    if not summary:
        return Finding(rule.id, "unclear", note="No discharge summary to compare against.")
    a, b = med_names(_med_section(summary)), med_names(_med_section(nursing))
    if not a or not b:
        return Finding(rule.id, "unclear", note="Could not find a medication list in both documents.")
    only_a, only_b = sorted(a - b), sorted(b - a)
    if not only_a and not only_b:
        return Finding(rule.id, "pass", note=f"Both documents list the same {len(a)} medications.", source=f"{summary.filename}, {nursing.filename}")
    parts = []
    if only_a:
        parts.append("only in summary: " + ", ".join(only_a))
    if only_b:
        parts.append("only in nursing instructions: " + ", ".join(only_b))
    return Finding(rule.id, "fail", note="Medication lists differ (" + "; ".join(parts) + ").", source=f"{summary.filename}, {nursing.filename}")


def run_pattern_checks(docs: list[Doc], disposition_hint: str = "", discharge_hint: str = "", today: date | None = None) -> list[Finding]:
    today = today or date.today()
    docs = screened(docs)
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
