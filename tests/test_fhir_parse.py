"""Tests for the hardened FHIR R4 parser (app/fhir/parse.py). Synthetic data only."""
import base64
import json
import re
from pathlib import Path

import pytest

from app.fhir.parse import (
    KIND_BY_LOINC,
    MAX_RESOURCES,
    SECTION_ORDER,
    FhirExtract,
    FhirParseError,
    fhir_to_text,
    parse_fhir,
)
from app.ingest import split_sections

ROOT = Path(__file__).resolve().parent.parent
FIX = Path(__file__).resolve().parent / "fixtures" / "fhir"
LOINC = "http://loinc.org"


def load(name: str) -> dict:
    return json.loads((FIX / name).read_text())


def bundle(*resources, type_="collection", **extra) -> dict:
    return {"resourceType": "Bundle", "type": type_, "entry": [{"resource": r} for r in resources], **extra}


def b64(s: str, pad: bool = True) -> str:
    out = base64.b64encode(s.encode()).decode()
    return out if pad else out.rstrip("=")


def docref(text: str, ctype: str = "text/plain", **extra) -> dict:
    return {"resourceType": "DocumentReference", "status": "current",
            "content": [{"attachment": {"contentType": ctype, "data": b64(text)}}], **extra}


def sections(ext: FhirExtract) -> dict[str, str]:
    return split_sections(ext.text)


ENC = {"resourceType": "Encounter", "id": "e1", "period": {"start": "2026-11-01", "end": "2026-11-03"}}


# ---------------- accepted inputs ----------------

def test_sample_bundle_matches_legacy_sections():
    ext = parse_fhir(json.loads((ROOT / "samples" / "syn-0004-bundle.json").read_text()))
    s = sections(ext)
    assert s["discharge disposition"].startswith("Inpatient rehabilitation facility (IRF)")
    # The narrative carries the same dates, so each section holds them twice.
    assert set(s["admission date"].split()) == {"2026-11-16"} and set(s["discharge date"].split()) == {"2026-11-19"}
    assert "- Apixaban 2.5 mg by mouth twice daily for 35 days (new, DVT prophylaxis)" in s["discharge medications"]
    assert s["medications stopped"] == "- Meloxicam 15 mg (stopped while on apixaban)"
    assert s["allergies"] == "Sulfa drugs (hives)"
    assert "(status: preliminary)" in s["pending results"]
    assert "2026-11-30" in s["followup instructions"]
    assert ext.author == "Dr. Felix Grant"
    assert ext.disposition.startswith("Inpatient rehabilitation")
    assert (ext.admission_date, ext.discharge_date) == ("2026-11-16", "2026-11-19")


def test_fhir_to_text_wrapper():
    text, author = fhir_to_text(docref("Discharge Diagnosis: CHF", author=[{"display": "Dr. Test Doc"}]))
    assert text == "Discharge Diagnosis: CHF"
    assert author == "Dr. Test Doc"


@pytest.mark.parametrize("btype", ["document", "collection", "searchset", "transaction", "batch-response", "history", None])
def test_any_bundle_type_accepted(btype):
    b = bundle({"resourceType": "Condition", "code": {"text": "Pneumonia"}})
    if btype is None:
        del b["type"]
    else:
        b["type"] = btype
    assert "- Pneumonia" in parse_fhir(b).text


def test_batch_response_nested_searchsets_are_flattened():
    inner = bundle({"resourceType": "Condition", "code": {"text": "Pneumonia"}}, type_="searchset")
    outer = {"resourceType": "Bundle", "type": "batch-response",
             "entry": [{"resource": inner, "response": {"status": "200 OK"}}]}
    assert "- Pneumonia" in parse_fhir(outer).text


def test_single_encounter_and_composition_accepted():
    enc = dict(ENC, hospitalization={"dischargeDisposition": {"text": "Home"}})
    ext = parse_fhir(enc)
    assert sections(ext)["discharge disposition"] == "Home"
    assert ext.encounter_id == "e1"
    comp = {"resourceType": "Composition", "status": "final",
            "section": [{"title": "Hospital Course", "text": {"div": "<div>Uneventful stay.</div>"}}]}
    assert sections(parse_fhir(comp))["hospital course"] == "Uneventful stay."


# ---------------- rejected inputs ----------------

@pytest.mark.parametrize("obj", [
    None, 5, "Bundle", [], [{"resourceType": "Bundle"}],
    {}, {"resourceType": 7}, {"resourceType": "Patient", "name": [{"family": "X"}]},
    {"resourceType": "Observation"}, {"hello": 1}, {"resourceType": "bundle"},
])
def test_non_fhir_rejected_with_fixed_message(obj):
    with pytest.raises(FhirParseError) as exc:
        parse_fhir(obj)
    assert str(exc.value) == "JSON files must be a FHIR R4 Bundle, DocumentReference, Composition or Encounter."


@pytest.mark.parametrize("version", ["3.0.2", "1.0.2", "5.0.0", "6.0.0-ballot", "STU3", True])
def test_non_r4_versions_rejected(version):
    b = bundle({"resourceType": "Condition", "code": {"text": "Pneumonia"}}, meta={"fhirVersion": version})
    with pytest.raises(FhirParseError, match="Only FHIR R4"):
        parse_fhir(b)
    with pytest.raises(FhirParseError, match="Only FHIR R4"):
        parse_fhir(dict(b, meta={}, fhirVersion=version))


@pytest.mark.parametrize("version", ["4.0.1", "4.0.0", "4.3.0", "R4", 4])
def test_r4_versions_accepted(version):
    b = bundle({"resourceType": "Condition", "code": {"text": "Pneumonia"}}, meta={"fhirVersion": version})
    assert "Pneumonia" in parse_fhir(b).text


def test_empty_content_rejected():
    for obj in (bundle(), {"resourceType": "Bundle", "entry": 5}, bundle({"resourceType": "Patient", "name": [{"family": "Zed"}]})):
        with pytest.raises(FhirParseError, match="No usable clinical content"):
            parse_fhir(obj)


def test_resource_cap():
    many = bundle(*[{"resourceType": "Condition", "code": {"text": f"c{i}"}} for i in range(MAX_RESOURCES + 1)])
    with pytest.raises(FhirParseError, match="more than 5000"):
        parse_fhir(many)
    contained = {"resourceType": "Condition", "code": {"text": "x"}, "contained": [{"resourceType": "Medication"}] * (MAX_RESOURCES + 1)}
    with pytest.raises(FhirParseError, match="more than 5000"):
        parse_fhir(bundle(contained))


def test_output_cap():
    with pytest.raises(FhirParseError, match="too much text"):
        parse_fhir(docref("A" * 300_000))
    lots = [docref(f"Note {i} " + "word " * 9000, type={"text": f"t{i}"}) for i in range(6)]
    with pytest.raises(FhirParseError, match="too much text"):
        parse_fhir(bundle(*lots))


def test_single_fields_truncated():
    ext = parse_fhir(bundle({"resourceType": "Condition", "code": {"text": "Z" * 50_000}}))
    assert max(len(ln) for ln in ext.text.split("\n")) <= 2002  # "- " + 2000


# ---------------- malformed shapes ----------------

MALFORMED = [
    {"resourceType": "Bundle", "entry": 5},
    {"resourceType": "Bundle", "entry": "x"},
    {"resourceType": "Bundle", "entry": [None, 3, "x", [], {"resource": "x"}, {"resource": None}]},
    {"resourceType": "Bundle", "entry": {"resource": {"resourceType": "Condition", "code": {"text": "Single entry dict"}}}},
    {"resourceType": "Bundle", "entry": [{"resource": {"resourceType": "Encounter", "hospitalization": [1], "period": "x", "class": 5,
                                                       "diagnosis": [None, {"condition": 3, "rank": "1", "use": []}], "reasonReference": "x"}}]},
    {"resourceType": "Bundle", "entry": [{"resource": {"resourceType": "Encounter", "reasonCode": 7}}]},
    {"resourceType": "DocumentReference", "content": ["x"]},
    {"resourceType": "DocumentReference", "content": [{"attachment": {"contentType": 5, "data": 9, "url": 3}}]},
    {"resourceType": "DocumentReference", "content": {"attachment": {"data": b64("dict content")}}, "author": "x", "type": 3},
    {"resourceType": "Bundle", "entry": [{"resource": {"resourceType": "Condition", "code": {"coding": "x"}, "category": {"a": 1}}}]},
    {"resourceType": "Bundle", "entry": [{"resource": {"resourceType": "Condition", "code": {"coding": [None, 1, {"display": 5}]},
                                                       "verificationStatus": 4, "clinicalStatus": "active"}}]},
    {"resourceType": "Bundle", "entry": [{"resource": {"resourceType": "MedicationRequest", "dosageInstruction": [None, 3, "x"], "note": {}}}]},
    {"resourceType": "Bundle", "entry": [{"resource": {"resourceType": "MedicationRequest", "medicationReference": "Medication/x",
                                                       "medicationCodeableConcept": "Aspirin",
                                                       "dosageInstruction": [{"doseAndRate": {"doseQuantity": {"value": "1"}},
                                                                              "timing": {"repeat": {"frequency": True, "period": float("inf"), "periodUnit": 3}}}]}}]},
    {"resourceType": "Bundle", "entry": [{"resource": {"resourceType": "Appointment", "status": ["x"], "start": 20261101}}]},
    {"resourceType": "Bundle", "entry": [{"resource": {"resourceType": "AllergyIntolerance", "code": [], "reaction": "x", "criticality": 9}}]},
    {"resourceType": "Bundle", "entry": [{"resource": {"resourceType": "Composition", "section": [None, {"text": "x", "section": "y"}],
                                                       "author": [None], "attester": "z"}}]},
    {"resourceType": "Bundle", "entry": [{"resource": {"resourceType": "CarePlan", "activity": [None, {"detail": "x"}]}},
                                         {"resource": {"resourceType": "Goal", "description": [], "target": 5}}]},
    {"resourceType": "Bundle", "entry": [{"resource": {"resourceType": "Patient", "name": "x"}},
                                         {"resource": {"resourceType": "Patient", "name": [{"given": "Solo", "family": ["List", 4]}]}}]},
    {"resourceType": "Bundle", "meta": "x", "entry": [{"fullUrl": 5, "search": "x", "resource": {"resourceType": "Procedure", "status": "completed"}}]},
]


@pytest.mark.parametrize("obj", MALFORMED)
def test_malformed_shapes_never_raise_other_errors(obj):
    try:
        ext = parse_fhir(obj)
    except FhirParseError:
        return
    assert isinstance(ext.text, str) and ext.text


def test_dict_where_list_expected_is_tolerated():
    assert "Single entry dict" in parse_fhir(MALFORMED[3]).text
    assert "dict content" in parse_fhir(MALFORMED[8]).text


def test_unexpected_internal_errors_become_parse_errors(monkeypatch):
    from app.fhir import parse as mod

    def boom(self, r):
        raise KeyError("internal")
    monkeypatch.setattr(mod._Parser, "_r_Condition", boom)
    with pytest.raises(FhirParseError, match="could not be read"):
        parse_fhir(bundle({"resourceType": "Condition", "code": {"text": "x"}}))


def test_error_messages_never_echo_content():
    secret = "SecretMarker"
    cases = [
        {"resourceType": secret},
        bundle(meta={"fhirVersion": secret}),
        docref(secret * 40_000),
    ]
    for obj in cases:
        with pytest.raises(FhirParseError) as exc:
            parse_fhir(obj)
        assert secret.lower() not in str(exc.value).lower()


# ---------------- searchset / OperationOutcome ----------------

def test_searchset_outcome_entries_skipped_with_warning():
    b = {"resourceType": "Bundle", "type": "searchset", "entry": [
        {"search": {"mode": "outcome"}, "resource": {"resourceType": "Condition", "code": {"text": "Should be skipped"}}},
        {"resource": {"resourceType": "OperationOutcome", "issue": [{"diagnostics": "server secret"}]}},
        {"search": {"mode": "match"}, "resource": {"resourceType": "Condition", "code": {"text": "Pneumonia"}}},
    ]}
    ext = parse_fhir(b)
    assert "Should be skipped" not in ext.text and "server secret" not in ext.text
    assert "Pneumonia" in ext.text
    assert any("OperationOutcome" in w for w in ext.warnings)
    assert not any("server secret" in w for w in ext.warnings)


# ---------------- references ----------------

def test_reference_resolution_by_urn_absolute_and_relative():
    b = {"resourceType": "Bundle", "type": "collection", "entry": [
        {"fullUrl": "urn:uuid:aaaaaaaa-0000-4000-8000-000000000001", "resource": {"resourceType": "Medication", "code": {"text": "Medurn 1 mg"}}},
        {"fullUrl": "https://fhir.example.test/r4/Medication/m2", "resource": {"resourceType": "Medication", "id": "m2", "code": {"text": "Medabs 2 mg"}}},
        {"resource": {"resourceType": "Medication", "id": "m3", "code": {"text": "Medrel 3 mg"}}},
        {"resource": {"resourceType": "MedicationRequest", "status": "active", "medicationReference": {"reference": "urn:uuid:aaaaaaaa-0000-4000-8000-000000000001"}}},
        {"resource": {"resourceType": "MedicationRequest", "status": "active", "medicationReference": {"reference": "Medication/m2"}}},
        {"resource": {"resourceType": "MedicationRequest", "status": "active", "medicationReference": {"reference": "https://other.example.test/fhir/Medication/m3/_history/2"}}},
        {"resource": {"resourceType": "MedicationRequest", "status": "active", "medicationReference": {"reference": "#c1"},
                      "contained": [{"resourceType": "Medication", "id": "c1", "code": {"text": "Medcontained 4 mg"}}]}},
        {"resource": {"resourceType": "MedicationRequest", "status": "active", "medicationReference": {"reference": "Medication/missing", "display": "Meddisplay 5 mg"}}},
        {"resource": {"resourceType": "MedicationRequest", "status": "active", "medication": {"concept": {"text": "Medfive 6 mg"}}}},
    ]}
    meds = sections(parse_fhir(b))["discharge medications"]
    for name in ("Medurn", "Medabs", "Medrel", "Medcontained", "Meddisplay", "Medfive"):
        assert f"- {name}" in meds


def test_binary_attachment_resolved_and_external_url_warned():
    ext = parse_fhir(load("searchset_two_encounters.json"))
    assert "Call the clinic" in ext.text
    assert any("stored outside the file" in w for w in ext.warnings)


def test_encounter_reason_reference_and_diagnosis_rank():
    ext = parse_fhir(load("document_bundle.json"))
    s = sections(ext)
    assert s["reason for admission"] == "Fever and productive cough"
    assert s["discharge diagnosis"] == "- Pneumonia\n- Sepsis due to pneumonia"  # rank 1 before rank 2
    # The reason-for-admission condition is not repeated as a discharge diagnosis.
    assert "Fever" not in s["discharge diagnosis"]


def test_encounter_diagnosis_admission_use():
    b = bundle(dict(ENC, diagnosis=[{"condition": {"reference": "Condition/a"}, "use": {"coding": [{"code": "AD"}]}},
                                    {"condition": {"display": "Displayonly diagnosis"}, "rank": 1}]),
               {"resourceType": "Condition", "id": "a", "code": {"text": "Chest pain"}})
    s = sections(parse_fhir(b))
    assert s["reason for admission"] == "Chest pain"
    assert s["discharge diagnosis"] == "- Displayonly diagnosis"


# ---------------- encounter selection ----------------

def test_multiple_encounters_uses_most_recent_inpatient():
    ext = parse_fhir(load("searchset_two_encounters.json"))
    s = sections(ext)
    assert ext.encounter_id == "new"
    assert ext.discharge_date == "2026-11-14"
    assert s["discharge disposition"] == "Home with home health services"
    assert "Heart failure" in s["discharge diagnosis"] and "Hip fracture" not in ext.text
    assert "Oldmed" not in ext.text and "Furosemide" in s["discharge medications"]
    assert s["past medical history"] == "- Chronic kidney disease stage 3"  # active problem list kept, resolved dropped
    assert s["allergies"] == "No known allergies"
    assert "Bundle had 3 encounters; used the most recent" in ext.warnings
    assert any("not linked to the selected encounter" in w for w in ext.warnings)


def test_explicit_encounter_id_selects_that_encounter():
    ext = parse_fhir(load("searchset_two_encounters.json"), encounter_id="old")
    s = sections(ext)
    assert ext.encounter_id == "old"
    assert s["discharge disposition"] == "Skilled nursing facility (SNF)"
    assert "Hip fracture" in s["discharge diagnosis"] and "Heart failure" not in ext.text
    assert "Oldmed" in ext.text and "Furosemide" not in ext.text
    assert "Chronic kidney disease" in ext.text and "No known allergies" in ext.text
    assert "Call the clinic" not in ext.text  # documents of the other encounter
    assert not any("most recent" in w and "encounters" in w for w in ext.warnings)
    assert parse_fhir(load("searchset_two_encounters.json"), encounter_id="Encounter/old").encounter_id == "old"


def test_unknown_encounter_id_rejected():
    with pytest.raises(FhirParseError, match="selected encounter was not found"):
        parse_fhir(load("searchset_two_encounters.json"), encounter_id="nope")


def test_composition_encounter_preferred_over_most_recent():
    b = bundle({"resourceType": "Composition", "status": "final", "encounter": {"reference": "Encounter/a"},
                "section": [{"title": "Hospital Course", "text": {"div": "<div>Stay A.</div>"}}]},
               {"resourceType": "Encounter", "id": "a", "class": {"code": "IMP"}, "period": {"start": "2026-01-01", "end": "2026-01-05"}},
               {"resourceType": "Encounter", "id": "b", "class": {"code": "IMP"}, "period": {"start": "2026-06-01", "end": "2026-06-05"}})
    ext = parse_fhir(b)
    assert ext.encounter_id == "a" and ext.discharge_date == "2026-01-05"


def test_sub_encounter_resources_belong_to_parent_stay():
    b = bundle({"resourceType": "Encounter", "id": "a", "class": {"code": "IMP"}, "period": {"start": "2026-01-01", "end": "2026-01-05"}},
               {"resourceType": "Encounter", "id": "a-icu", "partOf": {"reference": "Encounter/a"}, "period": {"start": "2026-01-02"}},
               {"resourceType": "Procedure", "status": "completed", "code": {"text": "Central line placement"}, "encounter": {"reference": "Encounter/a-icu"}})
    assert "Central line placement" in parse_fhir(b, encounter_id="a").text


def test_r5_shaped_encounter_tolerated():
    enc = {"resourceType": "Encounter", "id": "r5", "class": [{"coding": [{"code": "IMP"}]}],
           "actualPeriod": {"start": "2026-02-01", "end": "2026-02-02"}, "admission": {"dischargeDisposition": {"text": "Home"}}}
    ext = parse_fhir(enc)
    assert ext.discharge_date == "2026-02-02" and ext.disposition == "Home"


# ---------------- per-resource rules ----------------

def test_condition_categories_by_code_and_text():
    b = bundle({"resourceType": "Condition", "code": {"text": "Codeddx"}, "category": [{"coding": [{"code": "encounter-diagnosis"}]}]},
               {"resourceType": "Condition", "code": {"text": "Codedpl"}, "category": [{"coding": [{"code": "problem-list-item"}]}]},
               {"resourceType": "Condition", "code": {"text": "Textdx"}, "category": [{"text": "encounter-diagnosis"}]},
               {"resourceType": "Condition", "code": {"text": "Nocategory"}},
               {"resourceType": "Condition", "code": {"text": "Refuted"}, "verificationStatus": {"coding": [{"code": "refuted"}]}},
               {"resourceType": "Condition", "code": {"text": "Errored"}, "verificationStatus": "entered-in-error"})
    ext = parse_fhir(b)
    s = sections(ext)
    assert s["discharge diagnosis"] == "- Codeddx\n- Textdx\n- Nocategory"
    assert s["past medical history"] == "- Codedpl"
    assert "Refuted" not in ext.text and "Errored" not in ext.text
    assert "Skipped 1 entered-in-error resource" in ext.warnings


def test_medication_statuses():
    ext = parse_fhir(load("document_bundle.json"))
    s = sections(ext)
    meds = s["discharge medications"]
    assert "- Metformin 500 mg twice daily with meals (on hold)" in meds
    assert "Lisinopril" not in meds and "- Lisinopril 10 mg (held for low blood pressure)" == s["medications stopped"]
    assert "Cancelledmed" not in ext.text and "Errormed" not in ext.text
    assert "Skipped 2 entered-in-error resources" in ext.warnings


def test_structured_dosage_built():
    meds = sections(parse_fhir(load("document_bundle.json")))["discharge medications"]
    assert "- Amoxicillin 875 mg / clavulanate 125 mg tablet 1 tablet oral 2 times a day" in meds
    assert "- Acetaminophen 500 mg 2 tablet every 6 hours as needed for pain" in meds


@pytest.mark.parametrize("repeat,expected", [
    ({"frequency": 1, "period": 1, "periodUnit": "d"}, "daily"),
    ({"period": 8, "periodUnit": "h"}, "every 8 hours"),
    ({"frequency": 3, "period": 1, "periodUnit": "d"}, "3 times a day"),
    ({"frequency": 2, "period": 3, "periodUnit": "wk"}, "2 times every 3 weeks"),
])
def test_timing_phrases(repeat, expected):
    mr = {"resourceType": "MedicationRequest", "status": "active", "medicationCodeableConcept": {"text": "Drugx"},
          "dosageInstruction": [{"timing": {"repeat": repeat}}]}
    assert sections(parse_fhir(bundle(mr)))["discharge medications"] == f"- Drugx {expected}"


def test_inpatient_only_medication_orders_left_out():
    mr = {"resourceType": "MedicationRequest", "status": "active", "medicationCodeableConcept": {"text": "Heparin drip"},
          "category": [{"coding": [{"code": "inpatient"}]}]}
    keep = {"resourceType": "MedicationRequest", "status": "active", "medicationCodeableConcept": {"text": "Aspirin 81 mg"},
            "category": [{"coding": [{"code": "discharge"}]}]}
    ext = parse_fhir(bundle(mr, keep))
    assert "Heparin" not in ext.text and "Aspirin" in ext.text


def test_allergies_with_reaction_and_criticality():
    s = sections(parse_fhir(load("document_bundle.json")))
    assert s["allergies"] == "Penicillin - reaction Hives, Wheezing - high criticality"


def test_no_known_allergies_code():
    a = {"resourceType": "AllergyIntolerance", "code": {"coding": [{"system": "http://snomed.info/sct", "code": "716186003", "display": "No known allergy (situation)"}]}}
    inactive = {"resourceType": "AllergyIntolerance", "code": {"text": "Latex"}, "clinicalStatus": {"coding": [{"code": "inactive"}]}}
    s = sections(parse_fhir(bundle(a, inactive)))
    assert s["allergies"] == "No known allergies"


def test_pending_followup_goals_procedures():
    ext = parse_fhir(load("document_bundle.json"))
    s = sections(ext)
    assert s["pending results"] == "- Blood culture (status: preliminary)"
    assert "Complete blood count" not in ext.text
    assert s["followup instructions"] == "- Primary care follow-up 2026-11-27\n- Repeat chest radiograph in 6 weeks"
    assert "Cancelled" not in ext.text
    assert s["goals of care"] == "Full code; return to independent living (target 2027-01-15)"
    assert s["procedures"] == "- Chest radiograph 2026-11-15"
    assert "Bronchoscopy" not in ext.text


def test_service_request_statuses():
    srs = [{"resourceType": "ServiceRequest", "status": st, "code": {"text": f"Test {st}"}, "occurrenceDateTime": "2026-12-01"}
           for st in ("active", "revoked", "entered-in-error", "completed")]
    s = sections(parse_fhir(bundle(*srs)))
    assert s["followup instructions"] == "- Test active 2026-12-01"


# ---------------- narrative ----------------

def test_html_narrative_stripped_safely():
    html = ("<html><head><title>Ttl</title><style>.x{}</style></head><body><h2>Discharge Medications</h2>"
            "<ul><li>Aspirin 81 mg daily</li><li>Statin &amp; diet</li></ul><script>steal()</script>"
            "<p>Line&nbsp;one<br/>Line two &#169;</p></body></html>")
    for ctype in ("text/html", "application/xhtml+xml; charset=utf-8"):
        ext = parse_fhir(docref(html, ctype))
        assert "steal" not in ext.text and ".x{}" not in ext.text and "Ttl" not in ext.text and "<" not in ext.text
        s = sections(ext)
        assert "- Aspirin 81 mg daily\n- Statin & diet" in s["discharge medications"]
        assert "Line two ©" in ext.text


def test_markdown_and_unpadded_base64():
    ref = {"resourceType": "DocumentReference",
           "content": [{"attachment": {"contentType": "text/markdown", "data": b64("# Note\n\nGoals of Care: Full code", pad=False)}}]}
    assert "Goals of Care: Full code" in parse_fhir(ref).text
    spaced = b64("Hospital Course: wrapped base64 text")
    spaced = "\n".join(spaced[i:i + 8] for i in range(0, len(spaced), 8))
    ref["content"][0]["attachment"] = {"data": spaced}
    assert "wrapped base64 text" in parse_fhir(ref).text


def test_bad_attachments_warned_not_raised():
    b = bundle({"resourceType": "DocumentReference", "content": [
        {"attachment": {"contentType": "application/pdf", "data": b64("%PDF")}},
        {"attachment": {"contentType": "text/plain", "data": "!!!not base64!!!"}},
    ]}, {"resourceType": "Condition", "code": {"text": "Pneumonia"}})
    ext = parse_fhir(b)
    assert any("formats other than text" in w for w in ext.warnings)
    assert any("could not be decoded" in w for w in ext.warnings)


def test_control_and_invisible_characters_removed():
    ext = parse_fhir(docref("Discharge Diagnosis: CHF\x00\x1b[31m‮evil​"))
    assert not re.search("[\x00\x1b‮​]", ext.text)


def test_document_status_filtering_and_most_recent_of_type():
    ext = parse_fhir(load("searchset_two_encounters.json"))
    assert "Superseded text" not in ext.text
    assert "older draft" not in ext.text  # older current note of the same type
    assert "Used the most recent of 2 documents of the same type" in ext.warnings
    b = bundle(docref("Errored note text", docStatus="entered-in-error"), docref("Kept note text"))
    ext = parse_fhir(b)
    assert "Errored note" not in ext.text and "Kept note" in ext.text


def test_untyped_documents_are_all_kept():
    ext = parse_fhir(bundle(docref("First untyped note"), docref("Second untyped note")))
    assert "First untyped" in ext.text and "Second untyped" in ext.text
    assert not any("most recent of" in w for w in ext.warnings)


def test_composition_sections_become_text_sections():
    ext = parse_fhir(load("document_bundle.json"))
    s = sections(ext)
    assert s["hospital course"].startswith("Admitted with community acquired pneumonia & sepsis.")
    assert "- Transitioned to oral therapy day 3\n- Ambulating independently" in s["hospital course"]
    assert "alert" not in ext.text and "color:red" not in ext.text
    assert s["plan of care"] == "Home with daughter; resume usual diet."  # title from LOINC section code
    assert s["activity"] == "Walk daily as tolerated."  # nested section


def test_structured_values_cannot_forge_headers():
    b = bundle({"resourceType": "Encounter", "hospitalization": {"dischargeDisposition": {"text": "Home\nDischarge Diagnosis: fake"}}},
               {"resourceType": "Goal", "description": {"text": "Pending Results: none"}})
    s = sections(parse_fhir(b))
    assert "discharge diagnosis" not in s and "pending results" not in s
    assert s["goals of care"] == "- Pending Results: none"


def test_duplicate_lines_removed_and_order_stable():
    c = {"resourceType": "Condition", "code": {"text": "Pneumonia"}}
    b = bundle({"resourceType": "Goal", "description": {"text": "Comfort"}}, c, dict(c), {"resourceType": "AllergyIntolerance", "code": {"text": "Latex"}},
               docref("Same narrative"), docref("same   NARRATIVE"))
    ext = parse_fhir(b)
    assert ext.text.count("Pneumonia") == 1 and ext.text.lower().count("same") == 1
    headers = [h for h in SECTION_ORDER if f"\n{h}:\n" in "\n" + ext.text]
    assert headers == ["Discharge Diagnosis", "Allergies", "Goals of Care"]
    assert parse_fhir(b).text == ext.text


# ---------------- author ----------------

def test_author_from_practitioner_never_patient():
    ext = parse_fhir(load("document_bundle.json"))
    assert ext.author == "Dr. Ada Synthwell"
    b = bundle({"resourceType": "Patient", "id": "p", "name": [{"family": "Pembrose", "given": ["Ottoline"]}]},
               docref("Note text", author=[{"reference": "Patient/p", "display": "Ottoline Pembrose"},
                                           {"reference": "RelatedPerson/r", "display": "A Relative"},
                                           {"display": "Ottoline Pembrose"}]))
    assert parse_fhir(b).author == ""


def test_author_from_practitioner_role_and_attester_and_length_cap():
    b = bundle({"resourceType": "Practitioner", "id": "x", "name": [{"text": "Dr. " + "Longname " * 30}]},
               {"resourceType": "PractitionerRole", "id": "role", "practitioner": {"reference": "Practitioner/x"}},
               docref("Note text", author=[{"reference": "PractitionerRole/role"}]))
    author = parse_fhir(b).author
    assert author.startswith("Dr. Longname") and len(author) <= 80
    comp = {"resourceType": "Composition", "status": "final", "attester": [{"party": {"display": "Dr. Attesting Doc"}}],
            "section": [{"title": "Hospital Course", "text": {"div": "<div>Fine.</div>"}}]}
    assert parse_fhir(comp).author == "Dr. Attesting Doc"


# ---------------- patient identity ----------------

def test_patient_identity_never_copied():
    ext = parse_fhir(load("document_bundle.json"))
    for leaked in ("Testperson", "Quillfeather", "1950-01-01", "ZZ-TEST-1", "555-0142", "Marigoldine"):
        assert leaked not in ext.text
    assert "[patient] improved on IV antibiotics" in ext.text


def test_patient_names_redacted_case_insensitive_word_boundary():
    b = bundle({"resourceType": "Patient", "name": [{"family": "Hollowmere", "given": ["Ivy", "Al"]}]},
               docref("HOLLOWMERE was seen. hollowmere's niece visited. Hollowmeresque stays. Ivy improved. Al stays. Ivybridge too."))
    text = parse_fhir(b).text
    assert "[patient] was seen. [patient]'s niece visited." in text
    assert "Hollowmeresque" in text  # not a whole-word match
    assert "[patient] improved" in text and "Ivybridge" in text
    assert "Al stays" not in text and "[patient] stays" in text  # 2-letter name parts are redacted


def test_searchset_patient_text_name_redacted():
    ext = parse_fhir(load("searchset_two_encounters.json"))
    assert "Bramblewick" not in ext.text and "[patient] may shower" in ext.text



def test_subject_display_redacted_without_patient_resource():
    b = bundle(docref("Abe604 Smith123 was admitted. Abe tolerated diet; smith123 ambulating. Abernathy unaffected.",
                      subject={"reference": "Patient/p1", "display": "Abe604 Smith123"}))
    text = parse_fhir(b).text
    assert "Abe604" not in text and "Smith123" not in text.title() and "Abe " not in text
    assert "[patient] [patient] was admitted. [patient] tolerated diet; [patient] ambulating." in text
    assert "Abernathy unaffected" in text


def test_patient_and_beneficiary_display_redacted_but_not_other_subjects():
    b = bundle({"resourceType": "Coverage", "beneficiary": {"display": "Quinby Orrell"}},
               {"resourceType": "AllergyIntolerance", "patient": {"reference": "Patient/p1", "display": "Thaddeus"},
                "code": {"text": "Penicillin"}},
               {"resourceType": "Observation", "subject": {"reference": "Location/l1", "display": "Westwing"}},
               docref("Quinby Orrell and Thaddeus seen on Westwing."))
    text = parse_fhir(b).text
    assert "Quinby" not in text and "Orrell" not in text and "Thaddeus" not in text
    assert "Westwing" in text


def test_stub_patient_two_letter_names_redacted():
    stub = {"resourceType": "Patient", "id": "p1", "name": [{"given": ["Al"], "family": "Wu"}]}
    text = parse_fhir(bundle(stub, docref("Mr Al Wu was discharged. Wuhan trip noted."))).text
    assert "Mr [patient] [patient] was discharged." in text
    assert "Wuhan" in text


def test_stoplisted_two_letter_given_name_not_redacted():
    stub = {"resourceType": "Patient", "id": "p1", "name": [{"given": ["Po"], "family": "Lindqvist"}]}
    text = parse_fhir(bundle(stub, docref("Lindqvist to take amoxicillin PO twice daily. Mr Lindqvist ok."))).text
    # "Po" collides with the clinical abbreviation for oral; the family name is still redacted.
    assert "amoxicillin PO twice daily" in text
    assert "Lindqvist" not in text and "Mr [patient] ok" in text


def test_birthdate_identifier_telecom_redacted():
    pat = {"resourceType": "Patient", "id": "p1", "name": [{"given": ["Zebulon"], "family": "Marchetti"}],
           "birthDate": "1948-03-07",
           "identifier": [{"system": "urn:mrn", "value": "MRN-0048213"}, {"value": "ABC"}],
           "telecom": [{"system": "phone", "value": "(555) 014-2299"}, {"system": "email", "value": "zm@example.test"}]}
    note = ("DOB 1948-03-07 (3/7/1948, 03/07/1948). MRN MRN-0048213. Call (555) 014-2299 or 5550142299, "
            "email zm@example.test. ABC score 2. Seen 1948-03-08.")
    ext = parse_fhir(bundle(pat, docref(note)))
    for leaked in ("1948-03-07", "3/7/1948", "03/07/1948", "MRN-0048213", "014-2299", "5550142299", "zm@example.test"):
        assert leaked not in ext.text
        assert leaked not in ext.author and all(leaked not in w for w in ext.warnings)
    assert "DOB [dob] ([dob], [dob]). MRN [id]. Call [contact] or [contact], email [contact]." in ext.text
    assert "ABC score 2" in ext.text  # identifier values shorter than 4 are left alone
    assert "1948-03-08" in ext.text


def test_redaction_terms_bounded():
    pat = {"resourceType": "Patient", "name": [{"given": [f"Name{i:03d}x" for i in range(500)]}],
           "identifier": [{"value": f"ID{i:05d}"} for i in range(500)]}
    pat["name"].insert(0, {"family": "Okonkwo"})
    pat["birthDate"] = "1960-12-01"
    ext = parse_fhir(bundle(pat, docref("Plain clinical note for Okonkwo, born 1960-12-01.")))
    assert "Plain clinical note for [patient], born [dob]." in ext.text

# ---------------- kind hints ----------------

@pytest.mark.parametrize("code,kind", sorted(KIND_BY_LOINC.items()))
def test_kind_hint_from_loinc(code, kind):
    ref = docref("Note text", type={"coding": [{"system": LOINC, "code": code}]})
    assert parse_fhir(ref).kind_hint == kind


@pytest.mark.parametrize("type_,kind", [
    ({"text": "Case management note"}, "case_management"),
    ({"coding": [{"display": "Discharge planning note"}]}, "case_management"),
    ({"coding": [{"system": LOINC, "code": "99999-9"}]}, "other"),
    ({"coding": [{"system": "urn:local", "code": "abc"}]}, None),
    (None, None),
])
def test_kind_hint_fallbacks(type_, kind):
    ref = docref("Note text") if type_ is None else docref("Note text", type=type_)
    assert parse_fhir(ref).kind_hint == kind


def test_kind_hint_prefers_discharge_summary_and_composition_type():
    assert parse_fhir(load("document_bundle.json")).kind_hint == "discharge_summary"
    assert parse_fhir(load("searchset_two_encounters.json")).kind_hint == "nursing_instructions"
    b = bundle(docref("Progress text", type={"coding": [{"system": LOINC, "code": "11506-3"}]}),
               docref("Summary text", type={"coding": [{"system": LOINC, "code": "18842-5"}]}))
    assert parse_fhir(b).kind_hint == "discharge_summary"


# ---------------- fixtures stay synthetic ----------------

@pytest.mark.parametrize("name", ["document_bundle.json", "searchset_two_encounters.json"])
def test_fixtures_pass_phi_screen(name):
    from app.ingest import phi_screen
    raw = (FIX / name).read_text()
    assert not re.search(r"\b\d{3}-\d{2}-\d{4}\b", raw)
    assert not re.search(r"\b(DOB|MRN)\b", raw)
    phi_screen(parse_fhir(json.loads(raw)).text)  # raises on SSN-like text
