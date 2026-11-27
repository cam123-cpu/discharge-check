# Synthetic records

Every file here was written for testing. No real patient is described. Names
are fictional and phone numbers use the reserved 555-01xx range.

| Patient | Story | Gaps built in on purpose |
| --- | --- | --- |
| SYN-0001 | Heart failure, discharged home | None (control case) |
| SYN-0002 | Pneumonia, discharged to SNF | No pending results (blood cultures still in process), no goals of care, no quality data shared, nursing medication list differs from the summary |
| SYN-0003 | COPD, home with home health | Summary unsigned 48 days after discharge, follow-up has no timeframe, goals of care not discussed, no provider list or choice documented, no functional status, not sent to PCP |
| SYN-0004 | Hip replacement, to inpatient rehab (FHIR Bundle) | No signature, no PCP named, no evidence the summary was sent |
| SYN-0005 | Heart attack, discharged home | Thin hospital course, no condition at discharge, no functional status, no PCP, not sent, no discharge planning, signature has no time |
