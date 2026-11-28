from datetime import date
from pathlib import Path

import pytest

from app.ingest import parse_upload
from app.rules import Doc, days_until_deadline, medication_reconciliation, run_pattern_checks

S = Path(__file__).resolve().parent.parent / "samples"
TODAY = date(2026, 11, 27)


def docs_for(*files):
    out = []
    for i, (f, kind) in enumerate(files):
        p = parse_upload((S / f).read_bytes(), f, kind, 2_000_000)
        out.append(Doc(i, p.kind, p.filename, p.text, p.author))
    return out


def statuses(docs, dispo, dc):
    return {f.rule_id: f.status for f in run_pattern_checks(docs, dispo, dc, TODAY)}


def test_control_case_has_no_failures():
    s = statuses(docs_for(("syn-0001-summary.txt", "discharge_summary"), ("syn-0001-nursing.txt", "nursing_instructions")), "Home", "2026-11-14")
    assert [k for k, v in s.items() if v in ("fail", "unclear")] == []
    assert s["pac_list"] == "not_applicable"


def test_snf_case_flags_planted_gaps():
    s = statuses(docs_for(("syn-0002-summary.txt", "discharge_summary"), ("syn-0002-nursing.txt", "nursing_instructions"),
                          ("syn-0002-casemgmt.txt", "case_management")), "Skilled nursing facility (SNF)", "2026-11-09")
    assert s["pending_results"] in ("fail", "unclear")
    assert s["goals_of_care"] == "fail"
    assert s["pac_quality_data"] == "fail"
    assert s["meds_consistent"] == "fail"
    assert s["pac_list"] == "pass" and s["pac_choice"] == "pass"


def test_unsigned_delinquent_summary():
    s = statuses(docs_for(("syn-0003-summary.txt", "discharge_summary"), ("syn-0003-casemgmt.txt", "case_management")),
                 "Home with home health services", "2026-10-10")
    assert s["authenticated"] == "fail"
    assert s["timeliness"] == "fail"
    assert s["followup"] == "unclear"
    assert s["goals_of_care"] == "unclear"


def test_fhir_bundle():
    s = statuses(docs_for(("syn-0004-bundle.json", "discharge_summary")), "Inpatient rehabilitation facility (IRF)", "2026-11-19")
    assert s["final_diagnosis"] == "pass"
    assert s["discharge_meds"] == "pass"
    assert s["pending_results"] == "pass"
    assert s["pac_quality_data"] == "pass"
    assert s["authenticated"] == "fail"
    assert s["timeliness"] == "unclear"


def test_signature_without_time():
    s = statuses(docs_for(("syn-0005-summary.txt", "discharge_summary")), "Home", "2026-11-21")
    assert s["authenticated"] == "fail"
    assert s["timeliness"] == "unclear"
    assert s["hospital_course"] == "unclear"


def test_medication_diff_names_the_mismatch():
    docs = docs_for(("syn-0002-summary.txt", "discharge_summary"), ("syn-0002-nursing.txt", "nursing_instructions"))
    diff = medication_reconciliation(docs)
    assert diff["status"] == "fail"
    assert any(name.startswith("insulin") for name in diff["only_summary"])
    assert any(name.startswith("lisinopril") for name in diff["only_nursing"])
    assert any("10" in name for name in diff["only_summary"])


def test_deadline_days_are_signed():
    assert days_until_deadline("2026-11-14", TODAY) == 17
    assert days_until_deadline("2026-10-10", TODAY) < 0
    assert days_until_deadline("", TODAY) is None


@pytest.mark.parametrize("text,expected", [
    ("Followup Instructions:\n- PCP within 7 days", "pass"),
    ("Followup Instructions:\n- See PCP", "unclear"),
    ("Followup Instructions:\n", "fail"),
])
def test_followup_timeframe(text, expected):
    s = {f.rule_id: f.status for f in run_pattern_checks([Doc(0, "discharge_summary", "x.txt", text)], "Home", "2026-11-01", TODAY)}
    assert s["followup"] == expected


def test_a_later_summary_hides_an_older_pass():
    old = "Discharge Diagnosis:\n- Community acquired pneumonia, treated and resolved.\n"
    new = "Discharge Diagnosis:\n\n"
    findings = run_pattern_checks(
        [Doc(0, "discharge_summary", "old.txt", old), Doc(1, "discharge_summary", "new.txt", new)],
        "Home", "2026-11-01", TODAY,
    )
    assert {f.rule_id: f.status for f in findings}["final_diagnosis"] == "fail"


def test_medication_strength_is_part_of_the_comparison():
    summary = Doc(0, "discharge_summary", "s.txt", "Discharge Medications:\n- Furosemide 40 mg daily\n")
    nursing = Doc(1, "nursing_instructions", "n.txt", "Medications:\n- Furosemide 20 mg daily\n")
    diff = medication_reconciliation([summary, nursing])
    assert diff["status"] == "fail"
    assert any("40" in name for name in diff["only_summary"])
    assert any("20" in name for name in diff["only_nursing"])


def test_the_latest_medication_list_is_the_one_compared():
    old = Doc(0, "nursing_instructions", "old.txt", "Medications:\n- Furosemide 40 mg daily\n")
    new = Doc(1, "nursing_instructions", "new.txt", "Medications:\n- Furosemide 20 mg daily\n")
    summary = Doc(2, "discharge_summary", "s.txt", "Discharge Medications:\n- Furosemide 40 mg daily\n")
    diff = medication_reconciliation([summary, old, new])
    assert diff["status"] == "fail"
    assert any("20" in name for name in diff["only_nursing"])


def test_continue_keeps_the_drug_and_changes_are_not_the_list():
    summary = Doc(0, "discharge_summary", "s.txt", "Discharge Medications:\n- Lisinopril 10 mg daily\n\nMedication Changes:\n- New: insulin glargine 10 units nightly\n")
    nursing = Doc(1, "nursing_instructions", "n.txt", "Medications:\n- Continue lisinopril 10 mg daily\n")
    diff = medication_reconciliation([summary, nursing])
    assert diff["status"] == "pass"
    assert any(name.startswith("lisinopril") for name in diff["shared"])


def test_signature_dated_before_discharge_is_not_on_time():
    text = (
        "Discharge Diagnosis:\n- Pneumonia, resolved.\n"
        "Electronically signed by A. Lee, MD on 2026-11-01 09:00\n"
    )
    statuses = {f.rule_id: f.status for f in run_pattern_checks(
        [Doc(0, "discharge_summary", "s.txt", text)], "Home", "2026-11-20", TODAY,
    )}
    assert statuses["timeliness"] == "unclear"
    assert statuses["authenticated"] == "pass"
