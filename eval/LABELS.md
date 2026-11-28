# Label audit log

Every case was labeled by one writer and then re-labeled blind by a second
reviewer, who read the documents and decided all 20 statuses before looking
at any engine output (1,220 labels, 2026-11-28).

- No pass/gap label was flipped by the second review.
- Six labels gained an `also_acceptable` alternative on the same side of the
  pass/gap line (A01 pending_results and info_transmitted, A02 followup,
  A10 discharge_condition, A14 discharge_meds, E03 goals_of_care).
- Three documents were edited for clinical plausibility or to remove an
  ambiguity (E05, E08, G04); three rationales and one title were corrected.

## Disputed (left as labeled; a third reviewer could reasonably flip these)

| Case | Rule | Label | Argument for the other side |
| --- | --- | --- | --- |
| E03-ama-terse-summary | hospital_course | unclear | The one-line course gives treatment, the lipase trend and the AMA departure, so it could count as describing the outcome. |
| E01-no-summary-hh-referral | info_transmitted | unclear | A referral packet with the medication list was faxed to the agency; the rule question says "discharge information", though the summary itself was never sent. |

Treat any engine error on these two pairs as low-confidence.

## Known judgement calls the writers flagged

- `discharge_condition` passes in L05, L07, L09, L10 on clinical and mental
  status, with activity documented under Functional Status.
- G10 `pac_choice` passes: choice and the selected SNF are documented even
  though no provider list was given (that gap is scored under `pac_list`).
- A05: a Medicare Advantage network restriction does not excuse the provider
  list, choice or quality data, so all three `pac_*` rules are gaps.
- E01 and E10 `timeliness` fail: no discharge summary exists and more than 30
  days have passed.
