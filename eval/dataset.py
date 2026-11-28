"""Loading and validating the labeled case set.

A case is a folder under eval/cases holding case.json and the documents it
names. Documents are read through the app's own ingest path (parse_upload),
so the engines see exactly what they would see after an upload, including
invisible-character stripping and FHIR flattening."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from app.ingest import DOC_KINDS, IngestError, parse_upload
from app.rules import RULES, RULES_BY_ID, Doc

CASES_DIR = Path(__file__).resolve().parent / "cases"
STATUSES = ("pass", "fail", "unclear", "not_applicable")
GAP = ("fail", "unclear")
CATEGORIES = ("control", "gap", "linguistic", "adversarial", "edge")
DEFAULT_TODAY = "2026-11-27"
MAX_BYTES = 2_000_000


class CaseError(ValueError):
    pass


@dataclass
class Case:
    id: str
    category: str
    title: str
    disposition: str
    discharge_date: str
    today: date
    docs: list[Doc]
    expected: dict[str, str]
    acceptable: dict[str, set[str]]
    rationale: dict[str, str] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    attack: dict = field(default_factory=dict)
    path: Path | None = None

    @property
    def injection(self) -> bool:
        return "injection" in self.tags

    def ok(self, rule_id: str, status: str) -> bool:
        return status in self.acceptable[rule_id]


def _load_case(folder: Path) -> Case:
    meta_path = folder / "case.json"
    if not meta_path.is_file():
        raise CaseError(f"{folder.name}: missing case.json")
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CaseError(f"{folder.name}: case.json is not valid JSON ({exc})") from exc

    cid = meta.get("id")
    if cid != folder.name:
        raise CaseError(f"{folder.name}: id {cid!r} must equal the folder name")
    if meta.get("category") not in CATEGORIES:
        raise CaseError(f"{cid}: category must be one of {CATEGORIES}")
    for key in ("title", "documents", "expected"):
        if not meta.get(key):
            raise CaseError(f"{cid}: '{key}' is required")

    expected = meta["expected"]
    missing = [r.id for r in RULES if r.id not in expected]
    extra = [k for k in expected if k not in RULES_BY_ID]
    if missing or extra:
        raise CaseError(f"{cid}: expected must label every rule exactly once (missing {missing}, unknown {extra})")
    bad = {k: v for k, v in expected.items() if v not in STATUSES}
    if bad:
        raise CaseError(f"{cid}: invalid statuses {bad}")

    acceptable = {k: {v} for k, v in expected.items()}
    for k, alts in (meta.get("also_acceptable") or {}).items():
        if k not in RULES_BY_ID or not isinstance(alts, list) or any(a not in STATUSES for a in alts):
            raise CaseError(f"{cid}: bad also_acceptable entry for {k!r}")
        if expected[k] == "not_applicable" or "not_applicable" in alts:
            raise CaseError(f"{cid}: applicability is never ambiguous; do not list not_applicable in also_acceptable ({k})")
        if (expected[k] == "pass") != all(a == "pass" for a in alts):
            raise CaseError(f"{cid}: also_acceptable for {k} crosses the pass/gap line; pick one side")
        acceptable[k] |= set(alts)

    docs = []
    for i, d in enumerate(meta["documents"]):
        kind, fname = d.get("kind"), d.get("file")
        if kind not in DOC_KINDS:
            raise CaseError(f"{cid}: document {fname!r} has unknown kind {kind!r}")
        p = folder / str(fname)
        if not p.is_file() or p.parent != folder:
            raise CaseError(f"{cid}: document file {fname!r} not found in the case folder")
        try:
            parsed = parse_upload(p.read_bytes(), p.name, kind, MAX_BYTES)
        except IngestError as exc:
            raise CaseError(f"{cid}: {fname} rejected by ingest: {exc}") from exc
        docs.append(Doc(i, parsed.kind, parsed.filename, parsed.text, parsed.author))

    tags = list(meta.get("tags") or [])
    if meta["category"] == "adversarial" and "injection" not in tags and "tampering" not in tags:
        raise CaseError(f"{cid}: adversarial cases need an 'injection' or 'tampering' tag")
    attack = meta.get("attack") or {}
    for r in attack.get("target_rules", []):
        if r not in RULES_BY_ID:
            raise CaseError(f"{cid}: attack.target_rules has unknown rule {r!r}")

    return Case(
        id=cid,
        category=meta["category"],
        title=meta["title"],
        disposition=meta.get("disposition", ""),
        discharge_date=meta.get("discharge_date", ""),
        today=date.fromisoformat(meta.get("today", DEFAULT_TODAY)),
        docs=docs,
        expected=dict(expected),
        acceptable=acceptable,
        rationale=dict(meta.get("rationale") or {}),
        tags=tags,
        attack=attack,
        path=folder,
    )


def load_cases(root: Path = CASES_DIR, only: list[str] | None = None) -> list[Case]:
    folders = sorted(p for p in root.iterdir() if p.is_dir() and not p.name.startswith((".", "_")))
    if only:
        folders = [f for f in folders if any(f.name.startswith(o) for o in only)]
    errors, cases = [], []
    for f in folders:
        try:
            cases.append(_load_case(f))
        except CaseError as exc:
            errors.append(str(exc))
    if errors:
        raise CaseError("Invalid cases:\n  " + "\n  ".join(errors))
    return cases


def dataset_hash(cases: list[Case]) -> str:
    """Content hash of every file of the scored cases, so a report names the
    exact labels and notes it was scored on."""
    h = hashlib.sha256()
    for c in sorted(cases, key=lambda c: c.id):
        for p in sorted(c.path.rglob("*")):
            if p.is_file():
                h.update(f"{c.id}/{p.relative_to(c.path).as_posix()}".encode() + b"\0" + p.read_bytes() + b"\0")
    return h.hexdigest()[:16]
