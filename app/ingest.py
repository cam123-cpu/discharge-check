"""Turning uploaded files into clean text the checker can read.

Accepted: plain text (.txt, .md) and FHIR R4 JSON (.json, a Bundle or a
single DocumentReference). Everything else is rejected before it is read."""
from __future__ import annotations

import base64
import binascii
import json
import re
import unicodedata
from dataclasses import dataclass, field

DOC_KINDS = {
    "discharge_summary": "Discharge summary",
    "nursing_instructions": "Nursing discharge instructions",
    "case_management": "Case management note",
    "progress_note": "Progress note",
    "other": "Other",
}
ALLOWED_EXTENSIONS = {".txt", ".md", ".json"}
MAX_CHARS = 200_000


class IngestError(ValueError):
    """Shown to the user, so messages must not echo file contents."""


@dataclass
class ParsedDocument:
    kind: str
    filename: str
    text: str
    author: str = ""
    warnings: list[str] = field(default_factory=list)


# ---------------- validation ----------------

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._ -]")


def safe_filename(name: str) -> str:
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    base = _SAFE_NAME.sub("_", base).strip(" .")
    return base[:120] or "upload.txt"


def _extension(name: str) -> str:
    return ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""


def decode_upload(raw: bytes, filename: str, max_bytes: int) -> tuple[str, str]:
    name = safe_filename(filename)
    ext = _extension(name)
    if ext not in ALLOWED_EXTENSIONS:
        raise IngestError("Only .txt, .md and FHIR .json files are accepted.")
    if len(raw) == 0:
        raise IngestError("The file is empty.")
    if len(raw) > max_bytes:
        raise IngestError(f"The file is larger than {max_bytes // 1024} KB.")
    if b"\x00" in raw:
        raise IngestError("The file looks binary, not text.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise IngestError("The file must be UTF-8 text.") from exc
    return name, clean_text(text)


# Control characters, and invisible or direction-changing characters that can
# hide text from a human reviewer while a model still reads it.
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_INVISIBLE = re.compile("[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f\ufeff\ufff9-\ufffb]")


def clean_text(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _INVISIBLE.sub("", _CONTROL.sub("", text))
    if len(text) > MAX_CHARS:
        raise IngestError("The file has too much text for one record.")
    return text


# ---------------- PHI screen ----------------
# The prototype is for synthetic or de-identified data only. This screen is a
# guard rail, not a de-identification tool.

# Every quantifier is bounded so a hostile file cannot make these slow
# (an unbounded `[\w.+-]+@` took 30+ seconds on 100 KB of "a.a.a.").
_SSN = re.compile(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b")
_EMAIL = re.compile(r"[\w.+-]{1,64}@[\w-]{1,63}\.[\w.-]{2,63}")
_PHONE = re.compile(r"\(?\b(\d{3})\)?[-. ]?(\d{3})[-. ]?(\d{4})\b")


def phi_screen(text: str) -> list[str]:
    folded = unicodedata.normalize("NFKC", text)  # fullwidth digits count as digits
    if _SSN.search(folded):
        raise IngestError(
            "The file contains what looks like a Social Security number. "
            "Only synthetic or de-identified records may be uploaded."
        )
    warnings = []
    if "@" in folded and _EMAIL.search(folded):
        warnings.append("Contains an email address. Confirm it is synthetic.")
    phones = [m for m in _PHONE.finditer(folded) if m.group(2) != "555"]
    if phones:
        warnings.append("Contains a phone number outside the fictional 555 range. Confirm it is synthetic.")
    if injection_signals(text):
        warnings.append("Contains text that reads like instructions to an AI reviewer. Model review cannot mark rules complete for this record.")
    return warnings


# ---------------- prompt-injection screen ----------------
# Clinical notes do not address AI systems. Text that does is either a test or
# an attempt to steer the model review, so the analysis treats the model's
# "complete" verdicts on such a record as needing a human check.

_INJECTION = re.compile(
    r"(\b(ignore|disregard|forget|override)\b[^\n]{0,40}\b(previous|prior|above|earlier|all|any|system|these|those)\b[^\n]{0,40}\b(instructions?|rules?|prompts?|directions?|guidelines?)\b"
    r"|\bsystem prompt\b|\bnew instructions?\b|\byou are (now )?(an? |the )?(ai|assistant|language model|llm|reviewer|claude|gpt)\b"
    r"|\b(ai|model|llm|automated) (reviewer|checker|review|system)s?\b[^\n]{0,40}\b(must|should|will|shall)\b"
    r"|\bmark (all|every|each|these|the)\b[^\n]{0,40}\b(as )?(pass(ed)?|complete|compliant)\b"
    r"|<\s*/?\s*(document|rules|system|instructions?)\b|^[ \t]*(assistant|system|human)[ \t]*:)",
    re.I | re.M,
)


def injection_signals(text: str) -> bool:
    return bool(_INJECTION.search(unicodedata.normalize("NFKC", text)))


# ---------------- sections ----------------

_HEADER = re.compile(r"^\s*([A-Z][A-Za-z0-9 /&()'-]{2,60}):[ \t]*(.*)$")


def split_sections(text: str) -> dict[str, str]:
    """Map lower-cased section headers to their text. Text before the first
    header is stored under ''."""
    sections: dict[str, list[str]] = {"": []}
    current = ""
    for line in text.split("\n"):
        m = _HEADER.match(line)
        if m and len(m.group(1).split()) <= 6:
            current = m.group(1).strip().lower()
            sections.setdefault(current, [])
            if m.group(2).strip():
                sections[current].append(m.group(2).strip())
        else:
            sections[current].append(line)
    return {k: "\n".join(v).strip() for k, v in sections.items()}


# ---------------- FHIR ----------------
# FHIR files come from outside the hospital's control, so every field is
# treated as possibly the wrong type: a string where an object belongs, a
# number where a list belongs. Nothing here may raise anything but IngestError.

MAX_RESOURCES = 2000


def _d(x) -> dict:
    return x if isinstance(x, dict) else {}


def _l(x) -> list:
    return x if isinstance(x, list) else []


def _s(x, n: int = 500) -> str:
    return x[:n] if isinstance(x, str) else ""


def _cc_text(cc) -> str:
    cc = _d(cc)
    if _s(cc.get("text")):
        return _s(cc.get("text"))
    return ", ".join(_s(_d(c).get("display")) for c in _l(cc.get("coding")) if _s(_d(c).get("display")))


def _attachment_text(att) -> str:
    att = _d(att)
    ctype = _s(att.get("contentType")) or "text/plain"
    if ctype.split(";")[0].strip().lower() not in ("text/plain", "text/markdown"):
        return ""
    data = att.get("data")
    if not isinstance(data, str) or len(data) > 4 * MAX_CHARS:
        return ""
    try:
        return base64.b64decode(data, validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return ""


def fhir_to_text(obj) -> tuple[str, str]:
    """Flatten a FHIR Bundle (or DocumentReference) into sectioned text.
    Patient names, addresses and identifiers are never copied."""
    if not isinstance(obj, dict) or obj.get("resourceType") not in ("Bundle", "DocumentReference"):
        raise IngestError("JSON files must be a FHIR R4 Bundle or DocumentReference.")
    if obj["resourceType"] == "Bundle":
        entries = _l(obj.get("entry"))
        if len(entries) > MAX_RESOURCES:
            raise IngestError(f"The FHIR bundle has more than {MAX_RESOURCES} entries.")
        resources = [_d(e).get("resource") for e in entries]
    else:
        resources = [obj]
    resources = [r for r in resources if isinstance(r, dict)]

    out: dict[str, list[str]] = {}
    narrative: list[str] = []
    author = ""

    def add(section: str, line: str):
        if line and line.strip(" -"):
            out.setdefault(section, []).append(line)

    for r in resources:
        rt = r.get("resourceType")
        if rt == "Encounter":
            hosp = _d(r.get("hospitalization"))
            add("Discharge Disposition", _cc_text(hosp.get("dischargeDisposition")))
            period = _d(r.get("period"))
            add("Admission Date", _s(period.get("start"))[:10])
            add("Discharge Date", _s(period.get("end"))[:10])
            for reason in _l(r.get("reasonCode")):
                add("Reason for Admission", _cc_text(reason))
        elif rt == "Condition":
            cats = " ".join(_cc_text(c).lower() for c in _l(r.get("category")))
            label = "Discharge Diagnosis" if "encounter" in cats or not cats else "Past Medical History"
            add(label, "- " + _cc_text(r.get("code")))
        elif rt == "MedicationRequest":
            med = _cc_text(r.get("medicationCodeableConcept"))
            dose = "; ".join(_s(_d(d).get("text")) for d in _l(r.get("dosageInstruction")) if _s(_d(d).get("text")))
            note = " ".join(_s(_d(n).get("text")) for n in _l(r.get("note")) if _s(_d(n).get("text")))
            line = f"- {med} {dose}".strip()
            if note:
                line += f" ({note})"
            add("Medications Stopped" if r.get("status") == "stopped" else "Discharge Medications", line)
        elif rt == "AllergyIntolerance":
            add("Allergies", _cc_text(r.get("code")))
        elif rt in ("Appointment", "ServiceRequest") and r.get("status") not in ("cancelled", "revoked"):
            desc = _s(r.get("description")) or _cc_text(r.get("code")) or "Follow-up"
            when = (_s(r.get("start")) or _s(_d(r.get("occurrencePeriod")).get("start")))[:10]
            add("Followup Instructions", f"- {desc} {when}".strip())
        elif rt == "DiagnosticReport":
            status = _s(r.get("status"), 40)
            if status in ("registered", "partial", "preliminary"):
                add("Pending Results", f"- {_cc_text(r.get('code'))} (status: {status})")
        elif rt == "Goal":
            add("Goals of Care", _cc_text(r.get("description")))
        elif rt == "DocumentReference":
            for c in _l(r.get("content")):
                t = _attachment_text(_d(c).get("attachment"))
                if t:
                    narrative.append(t)
            for a in _l(r.get("author")):
                if _s(_d(a).get("display")) and not author:
                    author = _s(_d(a).get("display"), 80)

    parts = [f"{k}:\n" + "\n".join(v) for k, v in out.items()]
    text = clean_text("\n\n".join(narrative + parts).strip())
    if not text:
        raise IngestError("No usable clinical content was found in the FHIR file.")
    return text, author


# [ \t]* rather than \s*: with re.M, a leading \s* re-scans every following
# blank line from every line start (minutes on a file of newlines).
_AUTHOR = re.compile(r"^[ \t]*(?:Attending|Author|Signed by|Electronically signed by)[ \t]*:[ \t]*(\S.*)$", re.I | re.M)


def parse_upload(raw: bytes, filename: str, kind: str, max_bytes: int) -> ParsedDocument:
    if kind not in DOC_KINDS:
        raise IngestError("Choose a valid document type.")
    name, text = decode_upload(raw, filename, max_bytes)
    author = ""
    if name.lower().endswith(".json"):
        try:
            obj = json.loads(text)
        except (json.JSONDecodeError, RecursionError) as exc:  # RecursionError: deeply nested arrays
            raise IngestError("The JSON file could not be parsed.") from exc
        text, author = fhir_to_text(obj)
    warnings = phi_screen(text)
    if not author:
        m = _AUTHOR.search(text)
        if m:
            author = m.group(1).strip()[:80]
    return ParsedDocument(kind=kind, filename=name, text=text, author=author, warnings=warnings)
