import json
from pathlib import Path

import pytest

from app.ingest import IngestError, parse_upload, safe_filename

MAX = 10_000


def test_rejects_disallowed_extension():
    with pytest.raises(IngestError):
        parse_upload(b"hello", "evil.exe", "other", MAX)


def test_rejects_binary_and_oversize():
    with pytest.raises(IngestError):
        parse_upload(b"abc\x00def", "a.txt", "other", MAX)
    with pytest.raises(IngestError):
        parse_upload(b"a" * (MAX + 1), "a.txt", "other", MAX)


def test_rejects_ssn():
    with pytest.raises(IngestError):
        parse_upload(b"SSN 123-45-6789", "a.txt", "other", MAX)


def test_warns_on_real_looking_phone():
    doc = parse_upload(b"Call 415 867 5309", "a.txt", "other", MAX)
    assert doc.warnings
    assert not parse_upload(b"Call 555-0142", "a.txt", "other", MAX).warnings


def test_rejects_bad_kind():
    with pytest.raises(IngestError):
        parse_upload(b"x", "a.txt", "nope", MAX)


def test_filename_is_sanitized():
    assert safe_filename("../../etc/passwd") == "passwd"
    assert "<" not in safe_filename("<script>.txt")


def test_fhir_drops_patient_identity():
    bundle = {"resourceType": "Bundle", "entry": [
        {"resource": {"resourceType": "Patient", "name": [{"family": "Realname"}]}},
        {"resource": {"resourceType": "Condition", "code": {"text": "Pneumonia"}}},
    ]}
    doc = parse_upload(json.dumps(bundle).encode(), "b.json", "discharge_summary", MAX)
    assert "Pneumonia" in doc.text
    assert "Realname" not in doc.text


def test_non_fhir_json_rejected():
    with pytest.raises(IngestError):
        parse_upload(b'{"hello": 1}', "b.json", "other", MAX)


@pytest.mark.parametrize("text", [
    b"DOB: 01/02/1940",
    b"Date of birth: 1940-01-02",
    b"MRN: 1234567",
    b"Medical record number AB-4491",
    b"Lives at 12 Maple Street",
])
def test_blocks_direct_identifiers(text):
    with pytest.raises(IngestError):
        parse_upload(text, "a.txt", "other", MAX)


def test_age_is_not_treated_as_an_identifier():
    doc = parse_upload(b"71-year-old man walked the unit.\nDischarge Diagnosis:\n- Pneumonia", "a.txt", "other", MAX)
    assert "Pneumonia" in doc.text


def test_bundled_samples_pass_the_identifier_screen():
    root = Path(__file__).resolve().parent.parent / "samples"
    for path in sorted(root.iterdir()):
        if path.suffix.lower() not in {".txt", ".md", ".json"} or path.name == "README.md":
            continue
        parse_upload(path.read_bytes(), path.name, "discharge_summary", 2_000_000)
