# Discharge Check (prototype)

A web app that reads a patient's discharge record (discharge summary, nursing
instructions, case management notes) and shows what the text does not yet
document, before someone signs. The home screen is a work queue ordered by the
30-day completion clock. Pattern rules are the record. An optional model review
can add a doubt; it cannot clear a miss. "Shown" means the uploaded text
contains what a rule looks for. It is not a determination that a regulation
was met, and a person decides whether to sign.

**Synthetic or de-identified data only.** Do not upload real patient records
until there is a signed Business Associate Agreement with every vendor that
touches the data (including Anthropic, if model review is on).

## What it does

- **Ingest:** `.txt`, `.md`, or FHIR R4 `.json` (Bundle or DocumentReference).
  FHIR resources (Encounter, Condition, MedicationRequest, Appointment,
  DiagnosticReport, Goal, DocumentReference) are flattened into sections;
  patient names and identifiers on the Patient resource are not copied.
  Uploads that look like an SSN, date of birth, medical record number, or
  street address are refused. This is a guard rail, not de-identification.
- **Check (20 rules):** keyword and section checks aimed at 42 CFR 482.24 and
  42 CFR 482.43. They are not a survey worksheet. Keyword rules live in
  `app/rules.json`. Signature, the 30-day clock, and the medication comparison
  are code.
- **Two engines:**
  - Pattern rules always run and need no API key. They are the stored result
    unless the model is *more cautious*.
  - With `ANTHROPIC_API_KEY` set, a person can opt in on that check. Claude
    (`claude-opus-5-5`) may review the rules and write a brief. A "shown"
    from the model must carry a verbatim quote that the server finds in the
    record. The model cannot turn a pattern miss into "shown". Disagreement
    is written on the row. Records that trip the identifier screen are not
    sent.
  - Signature, date/time and the 30-day deadline are always computed in code.
  - Medication lists: the chart page shows names that appear in the summary
    only, or in the nursing instructions only.
- **Screens:** work queue (30-day clock, then missing items), per-patient
  checklist, medication diff, patient brief, open-chart list for compliance,
  rule library, access log. Attending and unit counts are there to find
  charts, and are not sorted as a scoreboard.

## Run it

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env          # then fill DATA_KEY and SESSION_PEPPER (commands are in the file)
python -m scripts.seed        # creates demo users (prints passwords once) and 5 synthetic discharges
uvicorn app.main:get_app --factory --port 8000
```

Open http://localhost:8000, sign in as `compliance@demo.test`. The home screen
is the work queue. Open a discharge and press **Run check**. Model review
stays off unless that check's box is ticked and `ANTHROPIC_API_KEY` is set.
For a deployed server set `FORCE_HTTPS=1` and `PUBLIC_HOST` (see `.env.example`).

Tests and dependency scan:

```bash
python -m pytest -q
pip-audit -r requirements.txt
```

## Security checklist

| Item | How it is handled |
| --- | --- |
| Hide API keys | Keys only from environment / `.env`; `.env` is git-ignored; the browser never sees them |
| Purge Git secrets | No secrets in the repo; run `gitleaks detect` before the first push |
| Public DB key / row-level security | No browser-side database access at all. Every patient query requires the user's `org_id` (`app/db.py`); a cross-org test proves another hospital gets a 404. Move to Postgres RLS when multi-tenant |
| Encrypt sensitive data | Document text, results, and the label, unit, attending, disposition, and discharge date are encrypted at rest (Fernet, key from `DATA_KEY`). Rule-level pass/fail is only inside that sealed result |
| Stolen-database tampering | The work queue and the compliance page recompute from the sealed result. A rewritten findings row or tally column is ignored. A result that fails authentication is shown as unreadable, not as a pass |
| Server-side auth | Every route checks the session server-side; roles enforced on compliance pages and API |
| Lock record access / block field tampering | `org_id`, `role` and authorship come from the session, never from the form; forms accept only named fields with validation |
| Secure session cookies | Random token, only a keyed hash stored, `HttpOnly`, `SameSite=Strict`, `Secure` when `FORCE_HTTPS=1`, 8-hour expiry |
| Hash passwords | Argon2id |
| Rate limit login / bot protection | 5 failures per email and per IP per 15 minutes; the database stores a keyed hash of those keys, not the raw email or IP; hidden honeypot field; login form token; equal timing for unknown emails |
| Parameterize queries | All SQL uses placeholders |
| Validate input / escape output | Server-side validation on every field; Jinja autoescaping; strict CSP with no inline scripts |
| Restrict file uploads | Extension allow-list, 2 MB cap, UTF-8 text only, no binaries, filename sanitized. SSN, date-of-birth, medical-record-number, and street-address patterns are refused |
| Trim API responses | `/api/compliance/summary` returns aggregates only; no patient labels or text |
| Security headers / HTTPS | CSP, HSTS, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, `no-store` on pages. With `FORCE_HTTPS=1`, HTTP is refused unless `PUBLIC_HOST` is set, and the redirect goes only to that host. `X-Forwarded-Proto` is ignored unless `TRUST_PROXY=1`, and then only from loopback or `TRUSTED_PROXY_IPS` |
| Request size | Total body capped just above the 2 MB upload limit; form field count and text-field size are capped |
| Scan dependencies | `pip-audit` (clean at time of writing) |
| HIPAA-style access log | Every record view, upload, delete and check is logged and visible to compliance |

## Not done yet

- No live run against Claude yet in this environment (the model path is tested
  with a stubbed client). Add a key and run the check on the samples.
- No accuracy measurement. Do that on a hand-labeled set before calling a
  "shown" result agreement with a surveyor. The bundled samples were written
  to exercise these rules; they are not that measurement.
- No EHR integration, write-back, SSO, or multi-factor sign-in. Anyone in the
  organization can open every chart. Privacy and Terms pages are drafts.
- SQLite is for the prototype; use Postgres with row-level security and managed
  keys before a pilot. The database file is mode 0600, which is not disk encryption.
- Aggregate pass/fail counts and the access log are still plaintext. The log
  is not tamper-evident.
- The identifier screen is not HIPAA Safe Harbor. It misses names, ages, and
  unpunctuated identifiers, and it will false-positive on some addresses.
