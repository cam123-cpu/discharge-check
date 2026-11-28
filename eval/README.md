# Accuracy evaluation

This folder measures how well Discharge Check finds documentation gaps, rule by
rule, on a labeled set of synthetic discharge records. It scores the pattern
engine, Claude's review, and the combined result the app shows, and keeps a
dated history so accuracy can be shown over time.

Nothing here is imported by the app. Every record is synthetic.

## Run it

```bash
python -m eval.validate                 # check the case files; show where the pattern engine disagrees with labels
python -m eval.run                      # offline: pattern engine + replay of saved Claude responses
python -m eval.run --live               # call Claude for every case and save the responses (needs ANTHROPIC_API_KEY)
python -m eval.run --live --trials 3    # repeat, to measure run-to-run consistency
python -m eval.run --cases A            # only cases whose id starts with A
python -m eval.run --min-recall 0.95    # exit 1 if gap recall is below 0.95 (CI gate)
```

Each run writes `eval/reports/<timestamp>.json` (everything), a Markdown
report next to it, `eval/reports/latest.md`, and one line in
`eval/reports/history.jsonl`.

`--live` reads `ANTHROPIC_API_KEY` from the environment or `.env`, costs one
model call per case per trial, and writes the responses to
`eval/recordings/<model>/`. Commit those recordings: from then on anyone can
re-score them offline, with no key and no cost.

## What is scored

| Layer | Meaning |
| --- | --- |
| `pattern` | The regex engine alone. Always runs. |
| `model_raw` | What Claude answered, before any server-side checks. |
| `model_verified` | After `llm.review()` turns every pass whose quote is not in the record (or is in the wrong kind of document) into `unclear`. |
| `app` | What a user sees: `analysis.analyze()`, including the merge with the pattern engine, the rule-applicability override and the injection guard. This is the headline. |

The model layers cover the 18 rules Claude reviews. Signature and the 30-day
deadline are computed in code, so they are scored only in `pattern` and `app`.

For each rule, a label of `fail` or `unclear` is a **gap**.

- **Recall** = gaps flagged / real gaps. A missed gap is a **false pass**: an
  incomplete record that the tool cleared. This is the error that matters to a
  surveyor, so it is the headline number, and every false pass is listed by
  case and rule in the report.
- **Precision** = real gaps / gaps flagged. Low precision means false alarms
  and wasted staff time, not cleared records.
- **Applicability errors**: a rule labeled `not_applicable` that the engine
  reviewed anyway, or a passing rule it dismissed. A real gap dismissed as
  `not_applicable` counts as a false pass.
- **Exact agreement** uses all four statuses. `fail` vs `unclear` is often a
  judgement call, so labels may list `also_acceptable` alternatives on the
  same side of the pass/gap line.
- **Prompt injection**: for adversarial cases, the share whose targeted gaps
  were cleared by any layer.

All rates carry 95% Wilson intervals. With a few dozen cases per rule those
intervals are wide, and the report shows them rather than a bare percentage.

## Reproducibility

Every report records the git commit, whether `app/` or `eval/cases/` had
uncommitted changes, the rules version, a fingerprint of the system prompt and
rule text, and a hash of the exact case files scored.

Every recording stores a hash of the full request (model, system prompt,
documents, rules, output schema). If the prompt or rules change, old
recordings stop matching and those cases are reported as **stale** instead of
being scored against a prompt that did not produce them. Re-record with
`--live`. (`--allow-stale` replays them anyway and says so in the report.)

Recordings also keep the model that actually served the request, which can
differ from the one requested when the API falls back.

## The case set

`eval/cases/<ID>/case.json` plus the documents, read through the app's own
upload path (`parse_upload`), so invisible characters are stripped and FHIR is
flattened exactly as in production.

| Prefix | Category | What it tests |
| --- | --- | --- |
| C | control | Complete records across dispositions. Measures false alarms. |
| G | gap | Planted gaps; single-gap cases make each miss attributable to one rule. |
| L | linguistic | Paraphrase and odd headers (should pass) vs. boilerplate, negation, hedging, contradictions, wrong document (should be gaps). |
| A | adversarial | Prompt injection and fake attestations aimed at the reviewer, including attacks the injection regex does not detect. |
| E | edge | Missing documents, hospice/AMA/transfer, 30 vs 31 days, very long and very short notes, FHIR. |

`case.json` fields: `id` (= folder name), `category`, `title`,
`disposition` (the hint the app gets), `discharge_date`, `today` (the day the
check runs, for the 30-day rule), `documents` (`file`, `kind`), `expected`
(a status for all 20 rules), optional `also_acceptable`, `rationale` (why each
non-obvious label is what it is), `tags`, and for adversarial cases `attack`
(`technique`, `goal`, `target_rules`, `regex_detectable`).

Labels are what a careful compliance reviewer would conclude from the
documents and the rule question, never what an engine outputs.
`not_applicable` is used only for the three post-acute rules when the patient
is not referred to home health, SNF, IRF or LTCH, and for the nursing
medication cross-check when there are no nursing instructions.

### Adding cases

1. Copy a case folder, give it a new id, edit the documents and labels.
2. `python -m eval.validate <ID>`. Disagreements with the pattern engine are
   expected; check that the label, not the engine, is right.
3. `python -m pytest tests/test_eval.py` checks coverage rules (every rule is a
   gap and a pass in at least two cases, attack targets are real gaps).
4. Run `--live` for the new cases and commit the recordings.

## Limits

- The records are synthetic and written for this purpose. They test known
  failure modes; they do not estimate accuracy on a hospital's real notes,
  where the mix of gaps is different. A pilot on de-identified real records,
  labeled by two independent reviewers, is the next step for that.
- Labels were written by one pass and audited by a second; there is no
  inter-rater agreement figure yet.
- Model results vary between runs. Use `--trials` and look at the consistency
  line before relying on a single run.
