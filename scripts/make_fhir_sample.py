"""Writes samples/syn-0004-bundle.json, a synthetic FHIR R4 Bundle."""
import base64, json
from pathlib import Path

narrative = """DISCHARGE SUMMARY (SYNTHETIC RECORD)

Admission Date: 2026-11-16
Discharge Date: 2026-11-19

Brief Hospital Course:
78-year-old woman underwent elective right total hip arthroplasty for osteoarthritis on 2026-11-16. Post-operative course notable for acute blood loss anemia, hemoglobin nadir 8.4, not transfused. Pain controlled on oral regimen by post-operative day 2. Physical therapy recommends inpatient rehabilitation for gait training given limited home support.

Condition at Discharge: Stable, alert and oriented, pain controlled.

Functional Status: Weight bearing as tolerated, ambulates 60 feet with a front-wheeled walker and contact guard assist.

Goals of Care: Full code. Patient's goal is to return home to live independently with her cat.

Discharge planning evaluation completed by case management. Discussed with the patient and her niece; patient prefers Lakeside Rehabilitation Hospital. Provided list of Medicare-certified inpatient rehabilitation facilities; patient informed of freedom of choice and selected Lakeside. Care Compare quality ratings reviewed with patient and niece.
"""

def res(r):
    return {"resource": r}

bundle = {
    "resourceType": "Bundle",
    "type": "collection",
    "entry": [
        res({"resourceType": "Patient", "id": "syn4", "name": [{"family": "Example", "given": ["Testcase"]}]}),
        res({"resourceType": "Encounter", "status": "finished",
             "period": {"start": "2026-11-16", "end": "2026-11-19"},
             "reasonCode": [{"text": "Elective right total hip arthroplasty"}],
             "hospitalization": {"dischargeDisposition": {"text": "Inpatient rehabilitation facility (IRF), Lakeside Rehabilitation Hospital"}}}),
        res({"resourceType": "Condition", "category": [{"text": "encounter-diagnosis"}], "code": {"text": "Primary osteoarthritis of right hip, status post total hip arthroplasty"}}),
        res({"resourceType": "Condition", "category": [{"text": "encounter-diagnosis"}], "code": {"text": "Acute blood loss anemia"}}),
        res({"resourceType": "MedicationRequest", "status": "active", "medicationCodeableConcept": {"text": "Apixaban 2.5 mg"}, "dosageInstruction": [{"text": "by mouth twice daily for 35 days"}], "note": [{"text": "new, DVT prophylaxis"}]}),
        res({"resourceType": "MedicationRequest", "status": "active", "medicationCodeableConcept": {"text": "Oxycodone 5 mg"}, "dosageInstruction": [{"text": "every 6 hours as needed for severe pain"}], "note": [{"text": "new"}]}),
        res({"resourceType": "MedicationRequest", "status": "active", "medicationCodeableConcept": {"text": "Acetaminophen 1000 mg"}, "dosageInstruction": [{"text": "every 8 hours"}]}),
        res({"resourceType": "MedicationRequest", "status": "stopped", "medicationCodeableConcept": {"text": "Meloxicam 15 mg"}, "note": [{"text": "stopped while on apixaban"}]}),
        res({"resourceType": "AllergyIntolerance", "code": {"text": "Sulfa drugs (hives)"}}),
        res({"resourceType": "DiagnosticReport", "status": "preliminary", "code": {"text": "Surgical pathology, right femoral head"}}),
        res({"resourceType": "Appointment", "status": "booked", "description": "Orthopedic surgery wound check, Dr. Felix Grant", "start": "2026-11-30T09:00:00Z"}),
        res({"resourceType": "ServiceRequest", "status": "active", "code": {"text": "CBC to check hemoglobin at rehab facility"}, "occurrencePeriod": {"start": "2026-11-21"}}),
        res({"resourceType": "DocumentReference", "status": "current", "author": [{"display": "Dr. Felix Grant"}],
             "content": [{"attachment": {"contentType": "text/plain", "data": base64.b64encode(narrative.encode()).decode()}}]}),
    ],
}
out = Path(__file__).resolve().parent.parent / "samples" / "syn-0004-bundle.json"
out.write_text(json.dumps(bundle, indent=2))
print(out)
