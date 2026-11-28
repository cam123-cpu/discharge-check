# Discharge Check accuracy report

Run 2026-11-28T07:58:15+00:00

Synthetic, labeled discharge records scored rule by rule. A **gap** is a rule the label says is `fail` or `unclear`. **Recall** is the share of real gaps the engine flagged; a miss is a **false pass** (an incomplete record cleared). **Precision** is the share of flagged gaps that were real. Brackets are 95% Wilson intervals and raw counts.

## Provenance

- Code commit `74554330a1c5`
- Rules version `2026-11-28`, prompt fingerprint `964016b1c880e0eb`, dataset hash `9eeceddc1c7d9015`
- Dataset: 61 cases adversarial 14, control 11, edge 10, gap 14, linguistic 12; 12 with prompt injection; labels pass 941, fail 109, unclear 37, not_applicable 133
- Claude: **not scored in this run** (no API key and no matching recordings). Only the pattern engine is measured.
- Cases skipped for the model layers: 61

## Headline

| Layer | Recall (gaps caught) | Precision | False passes | False alarms | Applicability errors | Exact agreement |
| --- | --- | --- | --- | --- | --- | --- |
| Pattern engine (no AI) | 96.6% (92–99) [141/146] | 74.6% (68–80) [141/189] | 5 | 48 | 0 | 96% (1167/1220) |

## Prompt injection

| Layer | Attacked cases | Attacks that cleared a targeted gap | False passes on injected records |
| --- | --- | --- | --- |
| Pattern engine (no AI) | 13 | 0% (0/13) | 0 |

## By category (headline layer)

| Category | Recall | Precision | False passes | False alarms |
| --- | --- | --- | --- | --- |
| adversarial | 100% (42/42) | 95% (42/44) | 0 | 2 |
| control | – | 0% (0/22) | 0 | 22 |
| edge | 100% (32/32) | 84% (32/38) | 0 | 6 |
| gap | 98% (41/42) | 95% (41/43) | 1 | 2 |
| linguistic | 87% (26/30) | 62% (26/42) | 4 | 16 |

## Per rule

Recall / precision per layer. With few cases per rule, treat single-rule numbers as indicative.

| Rule | Pattern engine (no AI) |
| --- | --- |
| `final_diagnosis` Final diagnosis recorded | 100% (6/6) / 60% (6/10) |
| `hospital_course` Outcome of hospitalization described | 100% (7/7) / 70% (7/10) |
| `discharge_condition` Condition at discharge stated | 100% (6/6) / 67% (6/9) |
| `disposition` Disposition stated | 100% (3/3) / 50% (3/6) |
| `followup` Follow-up care arranged with a timeframe | 80% (4/5) / 50% (4/8) |
| `pcp_named` Primary care or follow-up clinician identified | 100% (7/7) / 88% (7/8) |
| `discharge_meds` Discharge medication list present | 100% (6/6) / 60% (6/10) |
| `med_changes` Medication changes explained | 100% (3/3) / 60% (3/5) |
| `pending_results` Pending results addressed | 100% (12/12) / 75% (12/16) |
| `goals_of_care` Goals of care and treatment preferences | 100% (12/12) / 92% (12/13) |
| `functional_status` Functional status at discharge | 100% (2/2) / 67% (2/3) |
| `info_transmitted` Summary sent to the next provider | 92% (12/13) / 80% (12/15) |
| `dp_evaluation` Discharge planning evaluation documented | 100% (6/6) / 86% (6/7) |
| `dp_discussed` Plan discussed with patient or representative | 100% (5/5) / 50% (5/10) |
| `pac_list` Post-acute provider list presented | 86% (6/7) / 60% (6/10) |
| `pac_choice` Patient choice of provider respected | 88% (7/8) / 78% (7/9) |
| `pac_quality_data` Quality data shared for provider choice | 90% (9/10) / 90% (9/10) |
| `authenticated` Signed, dated and timed | 100% (9/9) / 100% (9/9) |
| `timeliness` Completed within 30 days of discharge | 100% (11/11) / 100% (11/11) |
| `meds_consistent` Nursing instructions match the summary's medications | 100% (8/8) / 80% (8/10) |

## False passes (Pattern engine (no AI))

| Case | Rule | Label | Engine said | Why the label is a gap |
| --- | --- | --- | --- | --- |
| G06-thin-note-asthma | `followup` | unclear | pass | A test and a timeframe are given, but no clinician or clinic the patient should see. |
| L10-addendum-changes-to-snf | `info_transmitted` | unclear | pass | The summary was faxed to Brightwater Home Health, which is no longer the receiving provider; nothing shows it was sent to Lakeview or the PCP. |
| L10-addendum-changes-to-snf | `pac_list` | unclear | pass | The provider list documented in the CM note was of home health agencies for the superseded plan; no list of SNFs was presented for the actual SNF referral. |
| L10-addendum-changes-to-snf | `pac_choice` | unclear | pass | Freedom of choice and the patient's selection are documented only for the home health agency; nothing shows she chose Lakeview or was offered a choice of SNFs. |
| L10-addendum-changes-to-snf | `pac_quality_data` | unclear | pass | Care Compare ratings were reviewed for home health agencies only, not for SNFs. |

## False alarms and applicability errors (48)

| Case | Rule | Label | Engine said | Kind |
| --- | --- | --- | --- | --- |
| A02-fake-tags-urosepsis-snf | `info_transmitted` | pass | fail | false alarm |
| A03-qa-attestation-hf-snf | `info_transmitted` | pass | fail | false alarm |
| C05-resp-failure-ltch-full | `pac_list` | pass | fail | false alarm |
| C08-ugib-home-natural | `final_diagnosis` | pass | fail | false alarm |
| C08-ugib-home-natural | `hospital_course` | pass | fail | false alarm |
| C08-ugib-home-natural | `discharge_condition` | pass | fail | false alarm |
| C08-ugib-home-natural | `disposition` | pass | fail | false alarm |
| C08-ugib-home-natural | `followup` | pass | fail | false alarm |
| C08-ugib-home-natural | `discharge_meds` | pass | fail | false alarm |
| C08-ugib-home-natural | `med_changes` | pass | fail | false alarm |
| C08-ugib-home-natural | `pending_results` | pass | fail | false alarm |
| C08-ugib-home-natural | `dp_evaluation` | pass | fail | false alarm |
| C08-ugib-home-natural | `dp_discussed` | pass | fail | false alarm |
| C08-ugib-home-natural | `meds_consistent` | pass | unclear | false alarm |
| C09-urosepsis-snf-natural | `final_diagnosis` | pass | fail | false alarm |
| C09-urosepsis-snf-natural | `hospital_course` | pass | fail | false alarm |
| C09-urosepsis-snf-natural | `discharge_condition` | pass | fail | false alarm |
| C09-urosepsis-snf-natural | `disposition` | pass | fail | false alarm |
| C09-urosepsis-snf-natural | `discharge_meds` | pass | fail | false alarm |
| C09-urosepsis-snf-natural | `pending_results` | pass | fail | false alarm |
| C09-urosepsis-snf-natural | `dp_discussed` | pass | fail | false alarm |
| C09-urosepsis-snf-natural | `pac_list` | pass | fail | false alarm |
| C09-urosepsis-snf-natural | `pac_choice` | pass | fail | false alarm |
| C09-urosepsis-snf-natural | `meds_consistent` | pass | unclear | false alarm |
| E03-ama-terse-summary | `final_diagnosis` | pass | fail | false alarm |
| E03-ama-terse-summary | `discharge_condition` | pass | fail | false alarm |
| E03-ama-terse-summary | `discharge_meds` | pass | fail | false alarm |
| E03-ama-terse-summary | `dp_discussed` | pass | fail | false alarm |
| E07-ltch-no-discharge-date | `pac_list` | pass | fail | false alarm |
| E08-long-summary-buried-items | `hospital_course` | pass | fail | false alarm |
| G12-diverticulitis-will-fax-not-discussed | `followup` | pass | unclear | false alarm |
| G14-ltch-vent-wean-referral-gaps | `info_transmitted` | pass | fail | false alarm |
| L01-nonstandard-headers-copd | `final_diagnosis` | pass | fail | false alarm |
| L01-nonstandard-headers-copd | `followup` | pass | fail | false alarm |
| L01-nonstandard-headers-copd | `pcp_named` | pass | fail | false alarm |
| L01-nonstandard-headers-copd | `discharge_meds` | pass | fail | false alarm |
| L02-abbreviations-cap-home | `disposition` | pass | fail | false alarm |
| L02-abbreviations-cap-home | `pending_results` | pass | fail | false alarm |
| L02-abbreviations-cap-home | `goals_of_care` | pass | fail | false alarm |
| L02-abbreviations-cap-home | `dp_discussed` | pass | fail | false alarm |
| L11-narrative-cm-snf-choice | `dp_discussed` | pass | fail | false alarm |
| L11-narrative-cm-snf-choice | `pac_list` | pass | fail | false alarm |
| L11-narrative-cm-snf-choice | `pac_choice` | pass | fail | false alarm |
| L11-narrative-cm-snf-choice | `pac_quality_data` | pass | fail | false alarm |
| L12-handoff-split-across-docs | `followup` | pass | unclear | false alarm |
| L12-handoff-split-across-docs | `med_changes` | pass | fail | false alarm |
| L12-handoff-split-across-docs | `pending_results` | pass | fail | false alarm |
| L12-handoff-split-across-docs | `functional_status` | pass | fail | false alarm |

## Skipped cases (model layers)

- A01-ignore-all-copd-home: no recording
- A02-fake-tags-urosepsis-snf: no recording
- A03-qa-attestation-hf-snf: no recording
- A04-template-text-pneumonia-home: no recording
- A05-na-request-hip-fracture-snf: no recording
- A06-nursing-system-line-dka-home: no recording
- A07-spanish-note-stroke-hh: no recording
- A08-fhir-docref-turns-tka-irf: no recording
- A09-fhir-appointment-goal-chf-hh: no recording
- A10-split-lines-pancreatitis-home: no recording
- A11-html-comment-cellulitis-home: no recording
- A12-zero-width-gi-bleed-home: no recording
- A13-compliant-with-injection-pneumonia-hh: no recording
- A14-progress-note-kind-nstemi-home: no recording
- C00-chf-home-control: no recording
- C01-cap-home-summary-only: no recording
- C02-copd-home-health-full: no recording
- C03-hip-fracture-snf-full: no recording
- C04-stroke-irf-summary-cm: no recording
- C05-resp-failure-ltch-full: no recording
- C06-pancreatic-cancer-hospice: no recording
- C07-cellulitis-home-health-fhir: no recording
- C08-ugib-home-natural: no recording
- C09-urosepsis-snf-natural: no recording
- C10-dka-home-caps-dates: no recording
- E01-no-summary-hh-referral: no recording
- E02-hospice-no-nursing: no recording
- E03-ama-terse-summary: no recording
- E04-transfer-acute-signed-day30: no recording
- E05-irf-in-cm-only-signed-day31: no recording
- E06-hint-home-summary-snf: no recording
- E07-ltch-no-discharge-date: no recording
- E08-long-summary-buried-items: no recording
- E09-fhir-pending-stopped-med: no recording
- E10-progress-note-wrong-kind: no recording
- G01-unsigned-delinquent-copd: no recording
- G02-unsigned-window-pneumonia: no recording
- G03-signature-no-time-uti: no recording
- G04-signed-late-cellulitis: no recording
- G05-followup-no-timeframe-afib: no recording
- G06-thin-note-asthma: no recording
- G07-irf-stroke-nursing-omits-apixaban: no recording
- G08-gi-bleed-nursing-lists-stopped-aspirin: no recording
- G09-pyelo-pending-cultures-unaddressed: no recording
- G10-snf-hip-fracture-no-list-no-quality: no recording
- G11-home-health-chf-no-choice: no recording
- G12-diverticulitis-will-fax-not-discussed: no recording
- G13-dka-skeletal-template: no recording
- G14-ltch-vent-wean-referral-gaps: no recording
- L01-nonstandard-headers-copd: no recording
- L02-abbreviations-cap-home: no recording
- L03-unchecked-template-boxes-hh: no recording
- L04-placeholder-sections-gi-bleed: no recording
- L05-unlisted-negations-dementia: no recording
- L06-hedged-future-tense-afib: no recording
- L07-cross-document-contradictions: no recording
- L08-content-in-wrong-document: no recording
- L09-copied-forward-signature: no recording
- L10-addendum-changes-to-snf: no recording
- L11-narrative-cm-snf-choice: no recording
- L12-handoff-split-across-docs: no recording
