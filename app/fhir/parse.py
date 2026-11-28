"""Hardened FHIR R4 parser.

Flattens a Bundle (any type), DocumentReference, Composition or Encounter into
the sectioned text the rule engine reads ("Discharge Medications:\\n- ...").

FHIR files come from outside the hospital's control, so every field is treated
as possibly the wrong type: a string where an object belongs, a dict where a
list belongs, a number, None. Nothing here raises anything but FhirParseError,
and no error message echoes file contents.

Patient identity is never copied: Patient and RelatedPerson resources,
identifiers, telecom, addresses and birth dates are not read except to collect
the patient's name parts so they can be redacted from narrative text."""
from __future__ import annotations

import base64
import binascii
import math
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser

__all__ = ["FhirParseError", "FhirExtract", "parse_fhir", "fhir_to_text", "SECTION_ORDER", "KIND_BY_LOINC"]

MAX_RESOURCES = 5000
MAX_FIELD = 2000
MAX_OUTPUT = 200_000
# Base64 longer than this decodes to more than MAX_OUTPUT, so reject it before decoding.
MAX_ATTACHMENT_B64 = (MAX_OUTPUT * 4) // 3 + 8
MAX_BUNDLE_DEPTH = 3  # batch-response bundles nest searchset bundles one level down
MAX_SECTION_DEPTH = 4
MAX_AUTHOR = 80
MAX_PATIENT_NAMES = 100
MAX_REDACT_TERMS = 200

ERR_NOT_FHIR = "JSON files must be a FHIR R4 Bundle, DocumentReference, Composition or Encounter."
ERR_VERSION = "Only FHIR R4 files are supported."
ERR_TOO_MANY = f"The FHIR file has more than {MAX_RESOURCES} resources."
ERR_TOO_LONG = "The FHIR file has too much text for one record."
ERR_EMPTY = "No usable clinical content was found in the FHIR file."
ERR_ENCOUNTER = "The selected encounter was not found in the FHIR file."
ERR_UNREADABLE = "The FHIR file could not be read."

# Structured sections, in the order they are emitted after any narrative.
# The rule engine matches on these names, so they must not change.
SECTION_ORDER: tuple[str, ...] = (
    "Discharge Disposition",
    "Admission Date",
    "Discharge Date",
    "Reason for Admission",
    "Discharge Diagnosis",
    "Past Medical History",
    "Procedures",
    "Discharge Medications",
    "Medications Stopped",
    "Allergies",
    "Followup Instructions",
    "Pending Results",
    "Goals of Care",
)

# DocumentReference.type / Composition.type LOINC code -> document kind.
KIND_BY_LOINC: dict[str, str] = {
    "18842-5": "discharge_summary",     # Discharge summary
    "11490-0": "discharge_summary",     # Physician Discharge summary
    "28655-9": "discharge_summary",     # Attending physician Discharge summary
    "34745-0": "nursing_instructions",  # Nurse Discharge summary
    "34746-8": "nursing_instructions",  # Nurse Note
    "8653-8": "nursing_instructions",   # Hospital Discharge instructions
    "11506-3": "progress_note",         # Progress note
    "34109-9": "progress_note",         # Note (generic E&M note)
    "11488-4": "other",                 # Consult note
    "34117-2": "other",                 # History and physical note
    "28570-0": "other",                 # Procedure note
    "18761-7": "other",                 # Transfer summary
}
# LOINC has no single widely used case-management document code, so case
# management (and anything uncoded) is recognised from type text/display.
KIND_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("discharge summary", "discharge_summary"),
    ("case manag", "case_management"),
    ("discharge planning", "case_management"),
    ("care coordination", "case_management"),
    ("social work", "case_management"),
    ("discharge instruction", "nursing_instructions"),
    ("nurs", "nursing_instructions"),
    ("progress", "progress_note"),
)
KIND_PRIORITY = ("discharge_summary", "nursing_instructions", "case_management", "progress_note", "other")

# SNOMED CT "no known ..." situation codes; shown as a statement, not an allergen.
NO_KNOWN_ALLERGY: dict[str, str] = {
    "716186003": "No known allergies",
    "409137002": "No known drug allergies",
    "429625007": "No known food allergies",
    "428607008": "No known environmental allergies",
}

INPATIENT_CLASSES = {"IMP", "ACUTE", "NONAC", "inpatient"}

# Composition.section.code -> section name, used only when a section has no title.
SECTION_BY_LOINC: dict[str, str] = {
    "8648-8": "Hospital Course",
    "11535-2": "Discharge Diagnosis",
    "46241-6": "Reason for Admission",
    "10183-2": "Discharge Medications",
    "48765-2": "Allergies",
    "11450-4": "Past Medical History",
    "47519-4": "Procedures",
    "18776-5": "Plan of Care",
    "8653-8": "Discharge Instructions",
    "11493-4": "Pending Results",
}

_PERIOD_UNITS = {"s": "second", "min": "minute", "h": "hour", "d": "day", "wk": "week", "mo": "month", "a": "year"}
_ONE_PERIOD = {"d": "daily", "wk": "weekly", "mo": "monthly", "a": "yearly", "h": "every hour"}


class FhirParseError(ValueError):
    """Message is shown to users; never echo file contents."""


@dataclass
class FhirExtract:
    text: str
    author: str = ""
    kind_hint: str | None = None
    encounter_id: str | None = None
    admission_date: str | None = None  # YYYY-MM-DD
    discharge_date: str | None = None
    disposition: str | None = None
    warnings: list[str] = field(default_factory=list)


# ---------------- defensive accessors ----------------

def _d(x) -> dict:
    return x if isinstance(x, dict) else {}


def _l(x) -> list:
    # A lone object where FHIR expects an array is a common hand-written mistake.
    if isinstance(x, list):
        return x
    return [x] if isinstance(x, dict) else []


def _s(x, n: int = MAX_FIELD) -> str:
    return x[:n] if isinstance(x, str) else ""


_WS = re.compile(r"\s+")


def _line(x, n: int = MAX_FIELD) -> str:
    """A single-line value. Newlines are collapsed so a coded field cannot
    forge a section header of its own."""
    return _WS.sub(" ", _s(x, n)).strip()


def _num(x) -> float | None:
    if isinstance(x, bool) or not isinstance(x, (int, float)):
        return None
    return float(x) if math.isfinite(x) and abs(x) < 1e9 else None


def _fmt(x: float) -> str:
    return f"{x:g}"


_DATE = re.compile(r"^(\d{4}-\d{2}-\d{2})")


def _date(x) -> str | None:
    m = _DATE.match(_s(x, 40))
    return m.group(1) if m else None


def _codings(cc) -> list[dict]:
    return [c for c in _l(_d(cc).get("coding")) if isinstance(c, dict)]


def _codes(cc) -> set[str]:
    return {_s(c.get("code"), 100) for c in _codings(cc)} - {""}


def _cc_text(cc) -> str:
    cc = _d(cc)
    if _line(cc.get("text")):
        return _line(cc.get("text"))
    displays = [_line(c.get("display")) for c in _codings(cc)]
    if any(displays):
        return ", ".join(dict.fromkeys(d for d in displays if d))
    return ", ".join(sorted(_codes(cc)))


def _status(r: dict, key: str = "status") -> str:
    return _s(r.get(key), 40).strip().lower()


def _concept_status(r: dict, key: str) -> set[str]:
    """Codes of a status that is a CodeableConcept in R4 but a string in STU3."""
    v = r.get(key)
    if isinstance(v, str):
        return {v[:40].lower()}
    return {c.lower() for c in _codes(v)}


# ---------------- text cleaning ----------------

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_INVISIBLE = re.compile("[­​-‏‪-‮⁠-⁤⁦-⁯﻿￹-￻]")
# Mirrors the section-header pattern in app.ingest: a structured value that
# would parse as a header is bulleted so it stays inside its own section.
_HEADER_LIKE = re.compile(r"^\s*[A-Z][A-Za-z0-9 /&()'-]{2,60}:")


def _clean(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return _INVISIBLE.sub("", _CONTROL.sub("", text))


class _TextExtractor(HTMLParser):
    """XHTML/HTML to plain text. Script and style content is dropped; entities
    are unescaped by the parser (convert_charrefs)."""

    _SKIP = {"script", "style", "head", "title", "template", "noscript", "iframe", "object", "svg", "math"}
    _HEADINGS = {"h1", "h2", "h3", "h4", "h5", "h6"}
    _BLOCK = {"p", "div", "br", "tr", "table", "ul", "ol", "h1", "h2", "h3", "h4", "h5", "h6", "section", "pre", "blockquote", "hr"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.skip = 0
        self.heading_at: int | None = None

    def handle_starttag(self, tag, attrs):
        if tag in self._SKIP:
            self.skip += 1
        elif tag == "li":
            self.parts.append("\n- ")
        elif tag in self._BLOCK:
            self.parts.append("\n")
            if tag in self._HEADINGS:
                self.heading_at = len(self.parts)
        elif tag in ("td", "th"):
            self.parts.append(" ")

    def handle_startendtag(self, tag, attrs):
        if tag in self._BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self._SKIP:
            self.skip = max(0, self.skip - 1)
        elif tag in self._HEADINGS and self.heading_at is not None:
            # A heading becomes "Heading:" so the rule engine sees a section.
            heading = "".join(self.parts[self.heading_at:]).strip()
            if heading and len(heading) <= 60 and "\n" not in heading:
                self.parts[self.heading_at:] = [heading.rstrip(":") + ":"]
            self.heading_at = None
            self.parts.append("\n")
        elif tag in self._BLOCK:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)


def _html_to_text(html: str) -> str:
    p = _TextExtractor()
    try:
        p.feed(html)
        p.close()
    except Exception:  # html.parser is lenient, but the input is hostile
        return ""
    return _tidy("".join(p.parts))


def _tidy(text: str) -> str:
    lines = [re.sub(r"[ \t\xa0]+", " ", ln).strip() for ln in _clean(text).split("\n")]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def _b64(data: str) -> bytes | None:
    data = re.sub(r"\s+", "", data)
    data += "=" * (-len(data) % 4)
    for decode in (lambda s: base64.b64decode(s, validate=True), base64.urlsafe_b64decode):
        try:
            return decode(data)
        except (binascii.Error, ValueError):
            continue
    return None


_CHARSETS = {"utf-8", "utf8", "us-ascii", "ascii", "iso-8859-1", "latin-1", "windows-1252"}


def _decode_bytes(raw: bytes, ctype: str) -> str | None:
    m = re.search(r"charset=\"?([A-Za-z0-9_-]{1,20})", ctype)
    charset = m.group(1).lower() if m and m.group(1).lower() in _CHARSETS else "utf-8"
    try:
        return raw.decode("utf-8-sig" if charset in ("utf-8", "utf8") else charset)
    except (UnicodeDecodeError, LookupError):
        return None


_TEXT_TYPES = {"text/plain": 0, "text/markdown": 1, "text/html": 2, "application/xhtml+xml": 2}


# ---------------- references ----------------

_TAIL = re.compile(r"(?:^|/)([A-Z][A-Za-z]{1,63})/([A-Za-z0-9.\-]{1,64})(?:/_history/[A-Za-z0-9.\-]{1,64})?$")


def _ref_str(ref) -> str:
    if isinstance(ref, str):
        return ref[:500].strip()
    return _s(_d(ref).get("reference"), 500).strip()


def _ref_keys(s: str) -> list[str]:
    if not s:
        return []
    keys = [s]
    m = _TAIL.search(s)
    if m:
        keys.append(f"{m.group(1)}/{m.group(2)}")
    return keys


def _ref_type(s: str) -> str:
    m = _TAIL.search(s)
    return m.group(1) if m else ""


class _Index:
    """Resolves references by fullUrl (urn:uuid or absolute), by "Type/id",
    and "#id" against a resource's contained list."""

    def __init__(self) -> None:
        self.by_key: dict[str, dict] = {}
        self.keys: dict[int, set[str]] = {}

    def add(self, res: dict, full_url: str) -> None:
        keys = set(_ref_keys(full_url))
        rid = _s(res.get("id"), 64)
        rt = _s(res.get("resourceType"), 64)
        if rid and rt:
            keys.add(f"{rt}/{rid}")
        for k in keys:
            self.by_key.setdefault(k, res)
        self.keys.setdefault(id(res), set()).update(keys)

    def resolve(self, ref, container: dict | None = None) -> dict | None:
        s = _ref_str(ref)
        if not s:
            return None
        if s.startswith("#") and container is not None:
            for c in _l(container.get("contained")):
                if isinstance(c, dict) and _s(c.get("id"), 64) == s[1:]:
                    return c
            return None
        for k in _ref_keys(s):
            if k in self.by_key:
                return self.by_key[k]
        return None

    def keys_of(self, res: dict) -> set[str]:
        return self.keys.get(id(res), set())


def _human_name(names) -> str:
    names = [n for n in _l(names) if isinstance(n, dict)]
    names.sort(key=lambda n: 0 if _s(n.get("use")) == "official" else 1)
    for n in names:
        if _line(n.get("text")):
            return _line(n.get("text"), MAX_AUTHOR)
        parts = [_line(p, 80) for p in _l_str(n.get("prefix")) + _l_str(n.get("given"))]
        parts += [_line(f, 80) for f in _l_str(n.get("family"))]
        parts += [_line(p, 80) for p in _l_str(n.get("suffix"))]
        name = " ".join(p for p in parts if p)
        if name:
            return name[:MAX_AUTHOR]
    return ""


def _l_str(x) -> list[str]:
    if isinstance(x, str):
        return [x]
    return [v for v in x if isinstance(v, str)] if isinstance(x, list) else []


# Reference fields whose display names the patient.
_PATIENT_REF_KEYS = ("subject", "patient", "beneficiary")
# Two-letter clinical/common tokens and titles never treated as name parts.
_NAME_STOPLIST = frozenset("""IV PO MD RN DO OR ER BP HR PT OT NO ON IN AT TO OF BY AN AS IS IT BE WE HE ME MY
US UP SO GO IF AM PM MR MS DR JR SR II III IV MRS MISS MX""".split())


def _date_forms(v: str) -> list[str]:
    m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})", v.strip()[:10]) if v else None
    if not m:
        return []
    y, mo, d = m.groups()
    out = [f"{y}-{mo}-{d}"]
    for a in {mo, str(int(mo))}:
        for b in {d, str(int(d))}:
            out.append(f"{a}/{b}/{y}")
    return out


# ---------------- parser ----------------

class _Parser:
    def __init__(self, encounter_id: str | None) -> None:
        self.want_encounter = encounter_id.strip()[:200] if isinstance(encounter_id, str) and encounter_id.strip() else None
        self.warnings: list[str] = []
        self.index = _Index()
        self.resources: list[dict] = []
        self.count = 0
        self.saw_outcome = False
        self.skipped_error = 0
        self.patient_names: set[str] = set()
        self._redact_re: re.Pattern | None = None
        self._redact_terms: dict[str, str] = {}
        self.out: dict[str, list[str]] = {}
        self.seen: dict[str, set[str]] = {}
        self.narrative: list[str] = []
        self.narrative_seen: set[str] = set()
        self.narrative_len = 0
        self.consumed: set[int] = set()
        self.unreadable_attachments = 0
        self.unsupported_attachments = 0
        self.external_attachments = 0

    # ----- top level -----

    def run(self, obj) -> FhirExtract:
        if not isinstance(obj, dict):
            raise FhirParseError(ERR_NOT_FHIR)
        rt = obj.get("resourceType")
        if rt not in ("Bundle", "DocumentReference", "Composition", "Encounter"):
            raise FhirParseError(ERR_NOT_FHIR)
        self._check_version(obj)
        self._collect(obj, "", 0)
        self._harvest_patient_names()
        live = [r for r in self.resources if self._live(r)]
        if self.skipped_error:
            self.warnings.append(f"Skipped {self.skipped_error} entered-in-error resource{'s' if self.skipped_error != 1 else ''}")
        encounter, kept = self._select_encounter(live)

        ext = FhirExtract(text="")
        if encounter is not None:
            self._encounter(encounter, ext)
        docs = []
        for r in kept:
            handler = getattr(self, "_r_" + _s(r.get("resourceType"), 64), None)
            if r.get("resourceType") in ("DocumentReference", "Composition"):
                docs.append(r)
            elif handler is not None and r is not encounter:
                handler(r)
        ext.author, ext.kind_hint = self._documents(docs)

        if self.saw_outcome:
            self.warnings.append("The FHIR server reported an issue (OperationOutcome); the data may be incomplete")
        if self.external_attachments:
            self.warnings.append(f"Skipped {self.external_attachments} attachment(s) stored outside the file")
        if self.unsupported_attachments:
            self.warnings.append(f"Skipped {self.unsupported_attachments} attachment(s) in formats other than text, markdown or HTML")
        if self.unreadable_attachments:
            self.warnings.append(f"Skipped {self.unreadable_attachments} attachment(s) that could not be decoded")

        parts = list(self.narrative)
        for sec in SECTION_ORDER:
            if self.out.get(sec):
                parts.append(f"{sec}:\n" + "\n".join(self.out[sec]))
        text = self._redact(_clean("\n\n".join(parts))).strip()
        if len(text) > MAX_OUTPUT:
            raise FhirParseError(ERR_TOO_LONG)
        if not text:
            raise FhirParseError(ERR_EMPTY)
        ext.text = text
        ext.warnings = self.warnings
        return ext

    def _check_version(self, obj: dict) -> None:
        for v in (obj.get("fhirVersion"), _d(obj.get("meta")).get("fhirVersion")):
            if v is None:
                continue
            v = str(v)[:20].strip().lower() if isinstance(v, (str, int, float)) else ""
            if not (v.startswith("4.") or v in ("4", "r4", "r4b")):
                raise FhirParseError(ERR_VERSION)

    def _bump(self, n: int = 1) -> None:
        self.count += n
        if self.count > MAX_RESOURCES:
            raise FhirParseError(ERR_TOO_MANY)

    def _collect(self, obj: dict, full_url: str, depth: int) -> None:
        rt = obj.get("resourceType")
        if rt == "Bundle":
            if depth >= MAX_BUNDLE_DEPTH:
                return
            for e in _l(obj.get("entry")):
                e = _d(e)
                res = e.get("resource")
                if not isinstance(res, dict):
                    continue
                if _s(_d(e.get("search")).get("mode"), 20) == "outcome" or res.get("resourceType") == "OperationOutcome":
                    self.saw_outcome = True
                    continue
                self._collect(res, _s(e.get("fullUrl"), 500), depth + 1)
            return
        if not isinstance(rt, str) or not rt:
            return
        if rt == "OperationOutcome":
            self.saw_outcome = True
            return
        self._bump(1 + len(_l(obj.get("contained"))))
        self.index.add(obj, full_url)
        self.resources.append(obj)

    def _harvest_patient_names(self) -> None:
        """Collect what identifies the patient so narrative text can be redacted:
        name parts (Patient/RelatedPerson names and patient reference displays),
        birth date, identifier values and telecom values."""
        people = []
        for r in self.resources:
            people.append(r)
            people.extend(c for c in _l(r.get("contained")) if isinstance(c, dict))
        dobs: list[str] = []
        ids: list[str] = []
        contacts: list[str] = []
        for r in people:
            rt = r.get("resourceType")
            for key in _PATIENT_REF_KEYS:
                for ref in _l(r.get(key)):
                    ref = _d(ref)
                    disp = _s(ref.get("display"), 200)
                    if disp and self._points_at_patient(ref, r):
                        self._add_name_tokens(disp)
            if rt not in ("Patient", "RelatedPerson"):
                continue
            for n in _l(r.get("name")):
                n = _d(n)
                for part in _l_str(n.get("given")) + _l_str(n.get("family")) + _l_str(n.get("text")):
                    self._add_name_tokens(part)
            for t in _l(r.get("telecom")):
                v = _s(_d(t).get("value"), 100).strip()
                if len(v) >= 4:
                    contacts.append(v)
                    digits = re.sub(r"\D", "", v)
                    if len(digits) >= 7 and digits != v:
                        contacts.append(digits)
            if rt != "Patient":
                continue
            dobs.extend(_date_forms(_s(r.get("birthDate"), 40)))
            for ident in _l(r.get("identifier")):
                v = _s(_d(ident).get("value"), 100).strip()
                if len(v) >= 4:
                    ids.append(v)
        # Priority order under the MAX_REDACT_TERMS cap: dob, names, contacts, ids.
        terms: dict[str, str] = {}
        names = sorted(self.patient_names, key=lambda n: (-len(n), n))
        for label, values in (("[dob]", dobs), ("[patient]", names), ("[contact]", contacts), ("[id]", ids)):
            for v in values:
                if len(terms) >= MAX_REDACT_TERMS:
                    break
                terms.setdefault(v.lower(), label)
        self._build_redactor(terms)

    def _add_name_tokens(self, part: str) -> None:
        for tok in re.split(r"[\s,]+", part[:200]):
            tok = tok.strip(".'-()")
            if len(self.patient_names) >= MAX_PATIENT_NAMES:
                return
            for t in {tok, re.sub(r"\d+$", "", tok)}:  # Synthea: "Abe604" -> also "Abe"
                t = t.strip(".'-")
                if len(t) < 2 or not any(ch.isalpha() for ch in t):
                    continue
                if t.upper() in _NAME_STOPLIST:
                    continue
                if len(self.patient_names) < MAX_PATIENT_NAMES:
                    self.patient_names.add(t[:60])

    def _points_at_patient(self, ref: dict, container: dict) -> bool:
        s = _ref_str(ref)
        if not s:
            return True  # display-only patient/subject reference
        target = self.index.resolve(ref, container)
        if target is not None:
            return target.get("resourceType") == "Patient"
        rt = _ref_type(s)
        return rt in ("", "Patient")

    def _build_redactor(self, terms: dict[str, str]) -> None:
        self._redact_terms = terms
        self._redact_re = None
        if terms:
            alts = "|".join(re.escape(k) for k in sorted(terms, key=lambda k: (-len(k), k)))
            self._redact_re = re.compile(rf"(?<!\w)(?:{alts})(?!\w)", re.I)

    def _redact(self, text: str) -> str:
        if self._redact_re is None:
            return text
        terms = self._redact_terms
        return self._redact_re.sub(lambda m: terms.get(m.group(0).lower(), "[patient]"), text)

    def _live(self, r: dict) -> bool:
        """False for resources a clinician marked as wrong."""
        st = _status(r)
        bad = st == "entered-in-error" or _status(r, "docStatus") == "entered-in-error"
        vs = _concept_status(r, "verificationStatus")
        if bad or "entered-in-error" in vs:
            self.skipped_error += 1
            return False
        return "refuted" not in vs

    # ----- encounter selection -----

    def _enc_refs(self, r: dict) -> set[str]:
        refs = _l(r.get("encounter")) + _l(_d(r.get("context")).get("encounter"))
        if _ref_str(r.get("context")):  # STU3-style MedicationRequest.context
            refs.append(r.get("context"))
        keys: set[str] = set()
        for ref in refs:
            keys.update(_ref_keys(_ref_str(ref)))
        return keys

    def _select_encounter(self, live: list[dict]) -> tuple[dict | None, list[dict]]:
        encs = [r for r in live if r.get("resourceType") == "Encounter"]
        chosen = None
        filtering = False
        if self.want_encounter:
            want = set(_ref_keys(self.want_encounter)) | {f"Encounter/{self.want_encounter}"}
            chosen = next((e for e in encs if self.index.keys_of(e) & want), None)
            keys = self.index.keys_of(chosen) if chosen else want
            if chosen is None and not any(self._enc_refs(r) & keys for r in live):
                raise FhirParseError(ERR_ENCOUNTER)
            filtering = True
        elif len(encs) > 1:
            chosen = self._doc_encounter(live, encs)
            if chosen is None:
                inpatient = [e for e in encs if self._enc_classes(e) & INPATIENT_CLASSES] or encs
                chosen = max(inpatient, key=self._enc_sort_key)
                self.warnings.append(f"Bundle had {len(encs)} encounters; used the most recent")
            else:
                self.warnings.append(f"Bundle had {len(encs)} encounters; used the one the document refers to")
            keys = self.index.keys_of(chosen)
            filtering = True
        else:
            chosen = encs[0] if encs else None
            keys = set()
        if not filtering:
            return chosen, live

        # Sub-encounters (partOf the chosen one) belong to the same stay.
        keys = set(keys)
        for e in encs:
            if e is not chosen and set(_ref_keys(_ref_str(e.get("partOf")))) & keys:
                keys |= self.index.keys_of(e)
        linked = self._encounter_linked(chosen)
        start = _date(self._period(chosen)[0]) if chosen else None
        kept, dropped = [], 0
        for r in live:
            rt = r.get("resourceType")
            if rt == "Encounter":
                continue
            refs = self._enc_refs(r)
            if refs:
                ok = bool(refs & keys)
            elif id(r) in linked:
                ok = True
            else:
                ok = self._patient_level(r, start)
            if ok:
                kept.append(r)
            elif rt not in _SUPPORT_TYPES:
                dropped += 1
        if dropped:
            self.warnings.append(f"Left out {dropped} resource(s) not linked to the selected encounter")
        return chosen, kept

    def _doc_encounter(self, live: list[dict], encs: list[dict]) -> dict | None:
        """In a document Bundle the Composition names its encounter."""
        for r in live:
            if r.get("resourceType") == "Composition":
                target = self.index.resolve(r.get("encounter"))
                if target is not None and any(target is e for e in encs):
                    return target
        return None

    def _encounter_linked(self, enc: dict | None) -> set[int]:
        if enc is None:
            return set()
        refs = [_d(dx).get("condition") for dx in _l(enc.get("diagnosis"))]
        refs += _l(enc.get("reasonReference")) + _l(enc.get("appointment"))
        return {id(t) for t in (self.index.resolve(ref, enc) for ref in refs) if t is not None}

    @staticmethod
    def _patient_level(r: dict, start: str | None) -> bool:
        """Resources with no encounter that still describe this stay."""
        rt = r.get("resourceType")
        if rt in ("AllergyIntolerance", "Goal"):
            return True
        if rt == "Condition":
            cats = set().union(*(_codes(c) for c in _l(r.get("category")))) if _l(r.get("category")) else set()
            texts = " ".join(_cc_text(c).lower() for c in _l(r.get("category")))
            clinical = _concept_status(r, "clinicalStatus")
            is_problem = "problem-list-item" in cats or "problem" in texts
            return is_problem and not (clinical & {"inactive", "resolved", "remission"})
        if rt == "Appointment":
            when = _date(r.get("start"))
            return when is None or start is None or when >= start
        return False

    @staticmethod
    def _enc_classes(e: dict) -> set[str]:
        out = set()
        for c in _l(e.get("class")):
            c = _d(c)
            out.add(_s(c.get("code"), 40))
            out |= _codes(c)
        return out - {""}

    @staticmethod
    def _period(e: dict | None) -> tuple[str, str]:
        e = _d(e)
        p = _d(e.get("period")) or _d(e.get("actualPeriod"))
        return _s(p.get("start"), 40), _s(p.get("end"), 40)

    def _enc_sort_key(self, e: dict) -> tuple:
        start, end = self._period(e)
        return (bool(end), end, start)

    # ----- sections -----

    def add(self, section: str, line: str, bullet: bool = True) -> None:
        line = line.strip()
        if not line.strip(" -"):
            return
        if bullet:
            line = "- " + line
        elif _HEADER_LIKE.match(line):
            line = "- " + line
        key = _WS.sub(" ", line).casefold()
        seen = self.seen.setdefault(section, set())
        if key not in seen:
            seen.add(key)
            self.out.setdefault(section, []).append(line)

    def add_narrative(self, text: str) -> None:
        text = text.strip()
        if not text:
            return
        key = _WS.sub(" ", text).casefold()
        if key in self.narrative_seen:
            return
        self.narrative_len += len(text)
        if self.narrative_len > MAX_OUTPUT:
            raise FhirParseError(ERR_TOO_LONG)
        self.narrative_seen.add(key)
        self.narrative.append(text)

    def _encounter(self, e: dict, ext: FhirExtract) -> None:
        ext.encounter_id = _line(e.get("id"), 64) or None
        hosp = _d(e.get("hospitalization")) or _d(e.get("admission"))  # R5 renamed it
        dispo = _cc_text(hosp.get("dischargeDisposition"))
        if dispo:
            ext.disposition = dispo
            self.add("Discharge Disposition", dispo, bullet=False)
        start, end = self._period(e)
        ext.admission_date, ext.discharge_date = _date(start), _date(end)
        if ext.admission_date:
            self.add("Admission Date", ext.admission_date, bullet=False)
        if ext.discharge_date:
            self.add("Discharge Date", ext.discharge_date, bullet=False)
        for reason in _l(e.get("reasonCode")):
            self.add("Reason for Admission", _cc_text(reason), bullet=False)
        for ref in _l(e.get("reasonReference")):
            target = self.index.resolve(ref, e)
            if target is not None and self._live_quiet(target):
                self.consumed.add(id(target))
                self.add("Reason for Admission", _cc_text(target.get("code")), bullet=False)
            elif target is None:
                self.add("Reason for Admission", _line(_d(ref).get("display")), bullet=False)
        diags = []
        for i, dx in enumerate(_l(e.get("diagnosis"))):
            dx = _d(dx)
            rank = dx.get("rank")
            rank = rank if isinstance(rank, int) and not isinstance(rank, bool) and rank > 0 else 10**6
            diags.append((rank, i, dx))
        for _, _, dx in sorted(diags, key=lambda t: (t[0], t[1])):
            target = self.index.resolve(dx.get("condition"), e)
            if target is not None:
                if not self._live_quiet(target):
                    continue
                self.consumed.add(id(target))
                label = _cc_text(target.get("code"))
            else:
                label = _line(_d(dx.get("condition")).get("display"))
            uses = {c.upper() for c in _codes(dx.get("use"))}
            section = "Reason for Admission" if uses & {"AD", "CC"} else "Discharge Diagnosis"
            self.add(section, label, bullet=section != "Reason for Admission")

    @staticmethod
    def _live_quiet(r: dict) -> bool:
        vs = _concept_status(r, "verificationStatus")
        return _status(r) != "entered-in-error" and not (vs & {"entered-in-error", "refuted"})

    def _r_Condition(self, r: dict) -> None:
        if id(r) in self.consumed:
            return
        cats = set()
        texts = []
        for c in _l(r.get("category")):
            cats |= {x.lower() for x in _codes(c)}
            texts.append(_cc_text(c).lower())
        text = " ".join(texts)
        if "encounter-diagnosis" in cats or (not cats and ("encounter" in text or not text)):
            section = "Discharge Diagnosis"
        else:
            section = "Past Medical History"
        self.add(section, _cc_text(r.get("code")))

    def _med_name(self, r: dict) -> str:
        name = _cc_text(r.get("medicationCodeableConcept"))
        if name:
            return name
        refs = [r.get("medicationReference")]
        med = _d(r.get("medication"))  # R5 CodeableReference
        if _cc_text(med.get("concept")):
            return _cc_text(med.get("concept"))
        refs.append(med.get("reference"))
        for ref in refs:
            target = self.index.resolve(ref, r)
            if target is not None and target.get("resourceType") == "Medication":
                if _cc_text(target.get("code")):
                    return _cc_text(target.get("code"))
            if _line(_d(ref).get("display")):
                return _line(_d(ref).get("display"))
        return ""

    @staticmethod
    def _dosage(d) -> str:
        d = _d(d)
        if _line(d.get("text")):
            return _line(d.get("text"))
        parts = []
        dar = _d(next(iter(_l(d.get("doseAndRate"))), None))
        q = _d(dar.get("doseQuantity"))
        val = _num(q.get("value"))
        if val is not None:
            unit = _line(q.get("unit"), 40) or _line(q.get("code"), 40)
            parts.append(f"{_fmt(val)} {unit}".strip())
        route = _cc_text(d.get("route"))
        if route:
            parts.append(route.lower())
        timing = _d(d.get("timing"))
        rep = _d(timing.get("repeat"))
        freq, period = _num(rep.get("frequency")), _num(rep.get("period"))
        unit = _PERIOD_UNITS.get(_s(rep.get("periodUnit"), 5))
        if period and unit:
            f = freq or 1
            if f == 1:
                parts.append(_ONE_PERIOD.get(_s(rep.get("periodUnit"), 5), f"every {unit}") if period == 1 else f"every {_fmt(period)} {unit}s")
            else:
                parts.append(f"{_fmt(f)} times a {unit}" if period == 1 else f"{_fmt(f)} times every {_fmt(period)} {unit}s")
        elif _cc_text(timing.get("code")):
            parts.append(_cc_text(timing.get("code")))
        if d.get("asNeededBoolean") is True:
            parts.append("as needed")
        elif _cc_text(d.get("asNeededCodeableConcept")):
            parts.append("as needed for " + _cc_text(d.get("asNeededCodeableConcept")))
        return " ".join(parts)

    def _r_MedicationRequest(self, r: dict) -> None:
        st = _status(r)
        if st in ("draft", "cancelled"):
            return
        cats = set().union(*(_codes(c) for c in _l(r.get("category")))) if _l(r.get("category")) else set()
        if "inpatient" in cats:  # an order given during the stay, not a discharge medication
            return
        name = self._med_name(r)
        if not name:
            return
        dose = "; ".join(x for x in (self._dosage(d) for d in _l(r.get("dosageInstruction"))) if x)
        note = " ".join(_line(_d(n).get("text")) for n in _l(r.get("note")) if _line(_d(n).get("text")))
        line = f"{name} {dose}".strip()
        if note:
            line += f" ({note})"
        if st == "on-hold":
            line += " (on hold)"
        self.add("Medications Stopped" if st == "stopped" else "Discharge Medications", line)

    def _r_AllergyIntolerance(self, r: dict) -> None:
        if _concept_status(r, "clinicalStatus") & {"inactive", "resolved"}:
            return
        nka = next((NO_KNOWN_ALLERGY[c] for c in _codes(r.get("code")) if c in NO_KNOWN_ALLERGY), None)
        if nka:
            self.add("Allergies", nka, bullet=False)
            return
        name = _cc_text(r.get("code"))
        if not name:
            return
        manifest = []
        for rx in _l(r.get("reaction")):
            manifest += [_cc_text(m) for m in _l(_d(rx).get("manifestation")) if _cc_text(m)]
        line = name
        if manifest:
            line += " - reaction " + ", ".join(dict.fromkeys(manifest))
        crit = _s(r.get("criticality"), 30)
        if crit in ("low", "high"):
            line += f" - {crit} criticality"
        self.add("Allergies", line, bullet=False)

    def _r_DiagnosticReport(self, r: dict) -> None:
        st = _status(r)
        if st in ("registered", "partial", "preliminary"):
            self.add("Pending Results", f"{_cc_text(r.get('code')) or 'Diagnostic report'} (status: {st})")

    def _r_ServiceRequest(self, r: dict) -> None:
        if _status(r) in ("revoked", "cancelled", "draft", "completed"):
            return
        desc = _cc_text(r.get("code")) or "Follow-up"
        when = _date(r.get("occurrenceDateTime")) or _date(_d(r.get("occurrencePeriod")).get("start")) or ""
        self.add("Followup Instructions", f"{desc} {when}")

    def _r_Appointment(self, r: dict) -> None:
        if _status(r) in ("cancelled", "noshow"):
            return
        desc = _line(r.get("description"))
        for key in ("serviceType", "specialty"):
            for cc in _l(r.get(key)):
                desc = desc or _cc_text(cc)
        desc = desc or _cc_text(r.get("appointmentType")) or "Follow-up appointment"
        self.add("Followup Instructions", f"{desc} {_date(r.get('start')) or ''}")

    def _r_CarePlan(self, r: dict) -> None:
        if _status(r) in ("revoked", "completed"):
            return
        for act in _l(r.get("activity")):
            det = _d(_d(act).get("detail"))
            if _status(det) in ("cancelled", "stopped", "entered-in-error", "completed"):
                continue
            desc = _line(det.get("description")) or _cc_text(det.get("code"))
            when = _date(_d(det.get("scheduledPeriod")).get("start")) or _line(det.get("scheduledString"), 100)
            if desc:
                self.add("Followup Instructions", f"{desc} {when or ''}")

    def _r_Goal(self, r: dict) -> None:
        if _s(r.get("lifecycleStatus"), 30) in ("cancelled", "rejected", "entered-in-error", "completed"):
            return
        desc = _cc_text(r.get("description"))
        due = next((_date(_d(t).get("dueDate")) for t in _l(r.get("target")) if _date(_d(t).get("dueDate"))), None)
        if desc:
            self.add("Goals of Care", f"{desc} (target {due})" if due else desc, bullet=False)

    def _r_Procedure(self, r: dict) -> None:
        if _status(r) != "completed":
            return
        when = _date(r.get("performedDateTime")) or _date(_d(r.get("performedPeriod")).get("start")) or ""
        self.add("Procedures", f"{_cc_text(r.get('code')) or 'Procedure'} {when}")

    # ----- documents -----

    def _documents(self, docs: list[dict]) -> tuple[str, str | None]:
        """Narrative from the most recent current document of each type."""
        groups: dict[str, list[tuple[int, dict]]] = {}
        for i, r in enumerate(docs):
            if _status(r) in ("superseded", "entered-in-error"):
                continue
            groups.setdefault(self._doc_type_key(r, i), []).append((i, r))
        chosen: list[tuple[int, dict]] = []
        for members in groups.values():
            best = max(members, key=lambda t: (self._doc_date(t[1]), -t[0]))
            chosen.append(best)
            if len(members) > 1:
                self.warnings.append(f"Used the most recent of {len(members)} documents of the same type")
        chosen.sort(key=lambda t: t[0])
        author, kinds = "", []
        for _, r in chosen:
            if r.get("resourceType") == "Composition":
                self._composition_text(r)
                a = self._author(r.get("author"), r) or self._author([_d(x).get("party") for x in _l(r.get("attester"))], r)
            else:
                self._docref_text(r)
                a = self._author(r.get("author"), r) or self._author(r.get("authenticator"), r)
            author = author or a
            k = _kind(r.get("type"))
            if k:
                kinds.append(k)
        kind = next((k for k in KIND_PRIORITY if k in kinds), None)
        return author, kind

    @staticmethod
    def _doc_type_key(r: dict, i: int) -> str:
        codings = _codings(r.get("type"))
        loinc = [_s(c.get("code"), 40) for c in codings if "loinc" in _s(c.get("system"), 200).lower()]
        codes = [c for c in loinc if c] or sorted(_codes(r.get("type")))
        text = _cc_text(r.get("type")).lower()
        # Untyped documents are never treated as versions of one another.
        return codes[0] if codes else (f"text:{text}" if text else f"untyped:{i}")

    @staticmethod
    def _doc_date(r: dict) -> str:
        ctx_end = _s(_d(_d(r.get("context")).get("period")).get("end"), 40)
        return _s(r.get("date"), 40) or ctx_end or _s(_d(r.get("meta")).get("lastUpdated"), 40)

    def _composition_text(self, r: dict) -> None:
        blocks: list[str] = []
        self._sections(_l(r.get("section")), blocks, 0)
        if not blocks:
            blocks.append(self._div(r.get("text")))
        for b in blocks:
            self.add_narrative(b)

    def _div(self, narrative) -> str:
        div = _d(narrative).get("div")
        if not isinstance(div, str):
            return ""
        if len(div) > MAX_ATTACHMENT_B64:
            raise FhirParseError(ERR_TOO_LONG)
        return _html_to_text(div)

    def _sections(self, sections: list, blocks: list[str], depth: int) -> None:
        if depth >= MAX_SECTION_DEPTH:
            return
        for sec in sections:
            sec = _d(sec)
            title = _line(sec.get("title"), 120).rstrip(": ")
            if not title:
                title = next((SECTION_BY_LOINC[c] for c in sorted(_codes(sec.get("code"))) if c in SECTION_BY_LOINC), "")
            body = self._div(sec.get("text"))
            if body:
                blocks.append(f"{title}:\n{body}" if title else body)
            self._sections(_l(sec.get("section")), blocks, depth + 1)

    def _docref_text(self, r: dict) -> None:
        best: tuple[int, str] | None = None
        for c in _l(r.get("content")):
            got = self._attachment(_d(_d(c).get("attachment")))
            if got and (best is None or got[0] < best[0]):
                best = got
        if best:
            self.add_narrative(best[1])

    def _attachment(self, att: dict) -> tuple[int, str] | None:
        ctype = _s(att.get("contentType"), 200)
        data = att.get("data")
        if not isinstance(data, str) and _ref_str(att.get("url")):
            binary = self.index.resolve(att.get("url"))
            if binary is None or binary.get("resourceType") != "Binary":
                self.external_attachments += 1
                return None
            data = binary.get("data", binary.get("content"))  # STU3 called it content
            ctype = ctype or _s(binary.get("contentType"), 200)
        if not isinstance(data, str):
            return None
        mime = (ctype.split(";")[0].strip().lower() or "text/plain")
        if mime not in _TEXT_TYPES:
            self.unsupported_attachments += 1
            return None
        if len(data) > MAX_ATTACHMENT_B64:
            raise FhirParseError(ERR_TOO_LONG)
        raw = _b64(data)
        text = _decode_bytes(raw, ctype) if raw is not None else None
        if text is None:
            self.unreadable_attachments += 1
            return None
        text = _html_to_text(text) if _TEXT_TYPES[mime] == 2 else _tidy(text)
        return (_TEXT_TYPES[mime], text) if text else None

    def _author(self, refs, container: dict) -> str:
        """First Practitioner name among refs. Patients, relatives, devices and
        organisations are never authors."""
        for ref in _l(refs):
            ref = _d(ref)
            target = self.index.resolve(ref, container)
            rt = _s(target.get("resourceType"), 64) if target else _ref_type(_ref_str(ref))
            name = ""
            if rt == "Practitioner" and target:
                name = _human_name(target.get("name"))
            elif rt == "PractitionerRole" and target:
                prac = _d(target.get("practitioner"))
                inner = self.index.resolve(prac, target)
                name = _human_name(inner.get("name")) if inner and inner.get("resourceType") == "Practitioner" else _line(prac.get("display"), MAX_AUTHOR)
            if not name and rt in ("", "Practitioner", "PractitionerRole"):
                name = _line(ref.get("display"), MAX_AUTHOR)
            if name and not self._mentions_patient(name):
                return name[:MAX_AUTHOR]
        return ""

    def _mentions_patient(self, s: str) -> bool:
        return self._redact(s) != s


_SUPPORT_TYPES = {"Patient", "RelatedPerson", "Practitioner", "PractitionerRole", "Organization", "Location", "Medication", "Binary", "Device"}


def _kind(cc) -> str | None:
    has_loinc = False
    for c in _codings(cc):
        system = _s(c.get("system"), 200).lower()
        code = _s(c.get("code"), 40)
        if "loinc" in system or not system:
            if code in KIND_BY_LOINC:
                return KIND_BY_LOINC[code]
            has_loinc = has_loinc or ("loinc" in system and bool(code))
    words = " ".join([_cc_text(cc)] + [_line(c.get("display")) for c in _codings(cc)]).lower()
    for needle, kind in KIND_KEYWORDS:
        if needle in words:
            return kind
    return "other" if has_loinc else None


# ---------------- public API ----------------

def parse_fhir(obj, encounter_id: str | None = None) -> FhirExtract:
    """Parse a FHIR R4 Bundle, DocumentReference, Composition or Encounter.
    With encounter_id, keep only that encounter's resources plus patient-level
    ones (allergies, active problem list, goals, later appointments)."""
    try:
        return _Parser(encounter_id).run(obj)
    except FhirParseError:
        raise
    except Exception:  # RecursionError, MemoryError-adjacent oddities, our own bugs
        raise FhirParseError(ERR_UNREADABLE) from None


def fhir_to_text(obj) -> tuple[str, str]:
    """Backwards-compatible wrapper: (text, author)."""
    ext = parse_fhir(obj)
    return ext.text, ext.author
