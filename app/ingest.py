"""Turning uploaded files into clean text the checker can read.

Accepted: plain text (.txt, .md) and FHIR R4 JSON (.json, a Bundle or a
single DocumentReference). Everything else is rejected before it is read."""
from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass, field

from .fhir.parse import FhirExtract, FhirParseError, parse_fhir

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
# The parser lives in app/fhir/parse.py so the EHR client can share it.


def fhir_to_text(obj) -> tuple[str, str]:
    """Flatten a FHIR Bundle or DocumentReference into sectioned text.
    Patient names, addresses and identifiers are never copied."""
    ex = _parse_fhir(obj)
    return ex.text, ex.author


def _parse_fhir(obj) -> FhirExtract:
    try:
        ex = parse_fhir(obj)
    except FhirParseError as exc:
        raise IngestError(str(exc)) from exc
    # Attachment text arrives base64-encoded, so clean it like a typed upload.
    ex.text = clean_text(ex.text)
    return ex


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
        extract = _parse_fhir(obj)
        text, author, fhir_warnings = extract.text, extract.author, extract.warnings
    else:
        fhir_warnings = []
    warnings = fhir_warnings + phi_screen(text)
    if not author:
        m = _AUTHOR.search(text)
        if m:
            author = m.group(1).strip()[:80]
    return ParsedDocument(kind=kind, filename=name, text=text, author=author, warnings=warnings)
