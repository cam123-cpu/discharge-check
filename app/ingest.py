"""Turning uploaded files into clean text the checker can read.

Accepted: plain text (.txt, .md) and FHIR R4 JSON (.json, a Bundle or a
single DocumentReference). Everything else is rejected before it is read."""
from __future__ import annotations

import base64
import binascii
import json
import re
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
    text = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text).replace("\r\n", "\n")
    if len(text) > MAX_CHARS:
        raise IngestError("The file has too much text for one record.")
    return name, text


# ---------------- PHI screen ----------------
# The prototype is for synthetic or de-identified data only. This screen is a
# guard rail, not a de-identification tool.

_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_PHONE = re.compile(r"\(?\b(\d{3})\)?[-. ]?(\d{3})[-. ]?(\d{4})\b")


def phi_screen(text: str) -> list[str]:
    if _SSN.search(text):
        raise IngestError(
            "The file contains what looks like a Social Security number. "
            "Only synthetic or de-identified records may be uploaded."
        )
    warnings = []
    if _EMAIL.search(text):
        warnings.append("Contains an email address. Confirm it is synthetic.")
    phones = [m for m in _PHONE.finditer(text) if m.group(2) != "555"]
    if phones:
        warnings.append("Contains a phone number outside the fictional 555 range. Confirm it is synthetic.")
    return warnings


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

def _cc_text(cc) -> str:
    if not isinstance(cc, dict):
        return ""
    if cc.get("text"):
        return str(cc["text"])
    codings = cc.get("coding") or []
    return ", ".join(str(c.get("display", "")) for c in codings if isinstance(c, dict) and c.get("display"))


def _attachment_text(att: dict) -> str:
    if not isinstance(att, dict) or att.get("contentType", "text/plain").split(";")[0] not in ("text/plain", "text/markdown"):
        return ""
    data = att.get("data")
    if not isinstance(data, str):
        return ""
    try:
        return base64.b64decode(data, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return ""


def fhir_to_text(obj) -> tuple[str, str]:
    """Flatten a FHIR Bundle (or DocumentReference) into sectioned text.
    Patient names, addresses and identifiers are never copied."""
    if not isinstance(obj, dict) or obj.get("resourceType") not in ("Bundle", "DocumentReference"):
        raise IngestError("JSON files must be a FHIR R4 Bundle or DocumentReference.")
    resources = (
        [e.get("resource") for e in obj.get("entry", []) if isinstance(e, dict)]
        if obj["resourceType"] == "Bundle"
        else [obj]
    )
    resources = [r for r in resources if isinstance(r, dict)][:2000]

    out: dict[str, list[str]] = {}
    narrative: list[str] = []
    author = ""

    def add(section: str, line: str):
        if line:
            out.setdefault(section, []).append(line)

    for r in resources:
        rt = r.get("resourceType")
        if rt == "Encounter":
            hosp = r.get("hospitalization") or {}
            add("Discharge Disposition", _cc_text(hosp.get("dischargeDisposition")))
            period = r.get("period") or {}
            add("Admission Date", str(period.get("start", ""))[:10])
            add("Discharge Date", str(period.get("end", ""))[:10])
            for reason in r.get("reasonCode", []) or []:
                add("Reason for Admission", _cc_text(reason))
        elif rt == "Condition":
            cats = " ".join(_cc_text(c).lower() for c in r.get("category", []) or [])
            label = "Discharge Diagnosis" if "encounter" in cats or not cats else "Past Medical History"
            add(label, "- " + _cc_text(r.get("code")))
        elif rt == "MedicationRequest":
            med = _cc_text(r.get("medicationCodeableConcept"))
            dose = "; ".join(str(d.get("text", "")) for d in r.get("dosageInstruction", []) or [] if isinstance(d, dict))
            note = " ".join(str(n.get("text", "")) for n in r.get("note", []) or [] if isinstance(n, dict))
            status = r.get("status", "")
            line = f"- {med} {dose}".strip()
            if note:
                line += f" ({note})"
            if status == "stopped":
                add("Medications Stopped", line)
            else:
                add("Discharge Medications", line)
        elif rt == "AllergyIntolerance":
            add("Allergies", _cc_text(r.get("code")))
        elif rt in ("Appointment", "ServiceRequest") and r.get("status") not in ("cancelled", "revoked"):
            desc = r.get("description") or _cc_text(r.get("code")) or "Follow-up"
            when = str(r.get("start") or (r.get("occurrencePeriod") or {}).get("start") or "")[:10]
            add("Followup Instructions", f"- {desc} {when}".strip())
        elif rt == "DiagnosticReport":
            name = _cc_text(r.get("code"))
            if r.get("status") in ("registered", "partial", "preliminary"):
                add("Pending Results", f"- {name} (status: {r.get('status')})")
        elif rt == "Goal":
            add("Goals of Care", _cc_text(r.get("description")))
        elif rt == "DocumentReference":
            for c in r.get("content", []) or []:
                t = _attachment_text((c or {}).get("attachment"))
                if t:
                    narrative.append(t)
            for a in r.get("author", []) or []:
                if isinstance(a, dict) and a.get("display") and not author:
                    author = str(a["display"])[:80]

    parts = [f"{k}:\n" + "\n".join(v) for k, v in out.items()]
    text = "\n\n".join(narrative + parts).strip()
    if not text:
        raise IngestError("No usable clinical content was found in the FHIR file.")
    return text, author


_AUTHOR = re.compile(r"^\s*(?:Attending|Author|Signed by|Electronically signed by)\s*:\s*(.+)$", re.I | re.M)


def parse_upload(raw: bytes, filename: str, kind: str, max_bytes: int) -> ParsedDocument:
    if kind not in DOC_KINDS:
        raise IngestError("Choose a valid document type.")
    name, text = decode_upload(raw, filename, max_bytes)
    author = ""
    if name.lower().endswith(".json"):
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as exc:
            raise IngestError("The JSON file could not be parsed.") from exc
        text, author = fhir_to_text(obj)
    warnings = phi_screen(text)
    if not author:
        m = _AUTHOR.search(text)
        if m:
            author = m.group(1).strip()[:80]
    return ParsedDocument(kind=kind, filename=name, text=text, author=author, warnings=warnings)
