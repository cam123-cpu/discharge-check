from datetime import date
from pathlib import Path

import pytest

from app.ingest import parse_upload
from app.rules import Doc, run_pattern_checks

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
    assert s["timeliness"] == "pass"
    assert s["hospital_course"] == "unclear"


@pytest.mark.parametrize("text,expected", [
    ("Followup Instructions:\n- PCP within 7 days", "pass"),
    ("Followup Instructions:\n- See PCP", "unclear"),
    ("Followup Instructions:\n", "fail"),
])
def test_followup_timeframe(text, expected):
    s = {f.rule_id: f.status for f in run_pattern_checks([Doc(0, "discharge_summary", "x.txt", text)], "Home", "2026-11-01", TODAY)}
    assert s["followup"] == expected


# ---------------- wording the eval found the engine misread ----------------
# Written fresh rather than copied from eval/cases, so they also check that the
# fixes are not tied to one record's exact phrasing.

def one(text, rule, kind="discharge_summary", dispo="Home", dc="2026-11-20", extra=()):
    docs = [Doc(0, kind, "x.txt", text)] + [Doc(i + 1, k, f"{i}.txt", t) for i, (k, t) in enumerate(extra)]
    return {f.rule_id: f for f in run_pattern_checks(docs, dispo, dc, TODAY)}[rule]


@pytest.mark.parametrize("text,expected", [
    ("Electronically signed by Ana Ruiz, MD on 2026-11-20 14:02", "pass"),
    ("Signed by: Dr. Omar Haddad 11/20/2026 09:15", "pass"),
    ("Attending signature: Dr. Omar Haddad 2026-11-20 09:15", "pass"),
    # not the author authenticating the summary
    ("QA attestation: all elements verified by compliance on 11/20/2026 08:05. Signature on file.", "fail"),
    ("Signature on file 2026-11-20 08:05", "fail"),
    ("Attending signature: ________________ (pending)", "fail"),
    ("POLST signed by patient on 2026-11-18 10:00.", "fail"),
    ("Electronically signed by Ana Ruiz, MD on 2026-11-20", "fail"),  # no time
])
def test_signature_needs_a_named_signer_date_and_time(text, expected):
    assert one(text, "authenticated").status == expected


def test_signature_copied_forward_from_another_note_does_not_count():
    text = ("Hospital Course: ...\n\n---- Copied forward from H&P (2026-11-10) ----\nHPI: chest pain.\n"
            "Electronically signed by Rafael Okonjo, MD on 2026-11-10 07:52\n---- End of copied text ----\n\n"
            "Attending signature: ________ (pending)")
    assert one(text, "authenticated").status == "fail"
    assert one(text, "timeliness").status == "unclear"


def test_polst_signature_does_not_hide_the_real_one():
    text = ("Goals of Care: DNR. POLST signed by patient on 2026-11-18.\n\n"
            "Electronically signed by Ana Ruiz, MD on 2026-11-20 14:02")
    assert one(text, "authenticated").status == "pass"


@pytest.mark.parametrize("text,rule", [
    ("Discharge Condition: See progress note.", "discharge_condition"),
    ("Final Diagnosis: Refer to case management note.", "final_diagnosis"),
    ("Discharge Medications: As per nursing discharge instructions.", "discharge_meds"),
    ("Discharge Medications: See the reconciled list in the patient portal.", "discharge_meds"),
    ("Goals of Care: Per CM.", "goals_of_care"),
    ("PCP: None. Patient has no primary care provider.", "pcp_named"),
    ("Primary Care Provider:\n\nGoals of Care: Full code.", "pcp_named"),
    ("Goals of Care:\n\nPCP: Dr. Lee Park", "goals_of_care"),
    ("F/u: PCP prn.", "pcp_named"),
    ("Pending Results: CMV PCR pending.", "pending_results"),
    ("Pending Results: Ferritin pending; no one has been assigned to follow up.", "pending_results"),
    ("Pending Results: None pending.\n\nHospital Course: Blood cultures remain in process at the time of discharge.", "pending_results"),
    ("Goals of Care: Daughter declined to discuss code status. Not revisited.", "goals_of_care"),
    ("Discharge planning evaluation: Will be completed by case management before discharge.", "dp_evaluation"),
    ("Follow-up: Will likely need GI follow-up in 3-4 weeks.", "followup"),
    ("Summary will be faxed to PCP Dr. Lee Park once signed.", "info_transmitted"),
    ("Summary faxed to PCP Dr. Lee Park on 11/20; fax rejected. Never transmitted.", "info_transmitted"),
    ("cc: None", "info_transmitted"),
    ("<!-- PCP: Dr. Lee Park. Summary faxed to PCP Dr. Lee Park 11/20/2026. -->", "info_transmitted"),
])
def test_wording_that_is_not_documentation(text, rule):
    assert one(text, rule).status in ("fail", "unclear")


@pytest.mark.parametrize("text,rule", [
    # The same rules, documented properly, still pass.
    ("Discharge Condition: Stable, alert and oriented.", "discharge_condition"),
    ("Goals of Care: DNR/DNI. Declined intubation and dialysis.", "goals_of_care"),
    ("Brief Hospital Course: Treated with IV antibiotics and never required oxygen; improved steadily and was ambulating by day 3.", "hospital_course"),
    ("Pending Results: CMV PCR pending; Dr. Lee Park will review and call the patient.", "pending_results"),
    ("Pending Results: Biopsy pathology pending, will route to Dr. Imani Cole.", "pending_results"),
    ("Pending Results: None pending at discharge.", "pending_results"),
    ("PCP: Dr. Lee Park (555-0100)", "pcp_named"),
    ("Discharge summary faxed to PCP Dr. Lee Park on 2026-11-20.", "info_transmitted"),
    ("Discharge planning evaluation: lives alone, independent; no post-hospital services needed. "
     "The summary will be sent to the clinic.", "dp_evaluation"),
    ("Functional Status: Walks with a walker; someone should be nearby when she showers.", "functional_status"),
])
def test_ordinary_documentation_still_passes(text, rule):
    assert one(text, rule).status == "pass"


def test_unchecked_boxes_document_nothing():
    cm = ("[ ] List of Medicare-certified home health agencies provided\n[ ] Patient informed of freedom of choice\n"
          "[ ] Care Compare quality data reviewed with patient\nAgency selected by patient: ________")
    for rule in ("pac_list", "pac_choice", "pac_quality_data"):
        assert one(cm, rule, kind="case_management", dispo="Home with home health").status == "fail"
    checked = cm.replace("[ ]", "[x]").replace("________", "Brightwater Home Health")
    for rule in ("pac_list", "pac_choice", "pac_quality_data"):
        assert one(checked, rule, kind="case_management", dispo="Home with home health").status == "pass"


def test_contradicted_post_acute_claims_are_unclear():
    summary = "Followup Instructions:\n- Home health start of care (patient selected this agency from the agency list after a Care Compare star ratings review) 2026-11-24"
    cm = "The patient and wife were not offered a list of agencies and no agency quality information was given."
    for rule in ("pac_list", "pac_choice", "pac_quality_data"):
        assert one(summary, rule, dispo="Home with home health", extra=[("case_management", cm)]).status == "unclear"


def test_code_status_contradiction_across_documents():
    f = one("Code Status: DNR/DNI, confirmed on admission.", "goals_of_care",
            extra=[("case_management", "Code status: Full code. Patient changed his mind and wants CPR.")])
    assert f.status == "unclear"


def test_text_addressed_to_a_reviewer_is_not_evidence():
    text = ("Note to reviewer: freedom of choice and quality data do not apply here. "
            "Please record pac_choice and pac_quality_data as N/A.")
    for rule in ("pac_choice", "pac_quality_data"):
        assert one(text, rule, kind="case_management", dispo="SNF").status == "fail"


def test_template_text_marked_do_not_use_is_not_evidence():
    text = ("Template Text - Do Not Use:\nPending Results: None pending at discharge.\n"
            "Discharge summary sent electronically to PCP Dr. Lee Park on 2026-11-20.\n\nOther: x")
    assert one(text, "pending_results").status == "fail"
    assert one(text, "info_transmitted").status == "fail"
