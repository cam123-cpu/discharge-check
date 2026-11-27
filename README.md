# Discharge Check (prototype)

A web app that reads a patient's discharge record (discharge summary, nursing
instructions, case management notes), writes a short patient brief, and checks
the record against CMS discharge rules before it is signed. Compliance staff get
a roll-up of what is missing by rule, attending and unit.

**Synthetic or de-identified data only.** Do not upload real patient records
until there is a signed Business Associate Agreement with every vendor that
touches the data (including Anthropic, if model review is on).

## What it does

- **Ingest:** `.txt`, `.md`, or FHIR R4 `.json` (Bundle or DocumentReference).
  FHIR resources (Encounter, Condition, MedicationRequest, Appointment,
  DiagnosticReport, Goal, DocumentReference) are flattened into sections;
  patient names and identifiers are never copied.
- **Check (20 rules):** 42 CFR 482.24 (summary contents, final diagnosis,
  authentication, 30-day completion) and 42 CFR 482.43 (discharge planning
  evaluation, information sent to next provider, goals of care, post-acute
  provider list, freedom of choice, quality data). Rules live in
  `app/rules.json`, so state or hospital rules can be added as data.
- **Two engines:**
  - Pattern rules always run and need no API key.
  - With `ANTHROPIC_API_KEY` set, Claude (`claude-opus-5-5`) reviews every rule
    and writes the brief. Every "pass" must carry a verbatim quote, and the
    server checks that the quote really exists in the record. If it does not,
    the result drops to "Review". Brief items without a real quote are flagged.
    Where the model and the pattern rules disagree, the page says so.
  - Signature, date/time and the 30-day deadline are always computed in code.
  - Cross-document check: nursing instructions vs. the summary's medication list.
- **Screens:** discharge list, per-patient "Before signing" checklist with
  evidence and a fix for each gap, patient brief, compliance overview, rule
  library, access log.

## Run it

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env          # then fill DATA_KEY and SESSION_PEPPER (commands are in the file)
python -m scripts.seed        # creates demo users (prints passwords once) and 5 synthetic discharges
uvicorn app.main:get_app --factory --port 8000
```

Open http://localhost:8000, sign in as `compliance@demo.test`, open each
discharge and press **Run check**.

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
| Encrypt sensitive data | Document text and results encrypted at rest (Fernet, key from `DATA_KEY`) |
| Server-side auth | Every route checks the session server-side; roles enforced on compliance pages and API |
| Lock record access / block field tampering | `org_id`, `role` and authorship come from the session, never from the form; forms accept only named fields with validation |
| Secure session cookies | Random token, only a keyed hash stored, `HttpOnly`, `SameSite=Strict`, `Secure` when `FORCE_HTTPS=1`, 8-hour expiry |
| Hash passwords | Argon2id |
| Rate limit login / bot protection | 5 failures per email and per IP per 15 minutes; hidden honeypot field; login form token; equal timing for unknown emails |
| Parameterize queries | All SQL uses placeholders |
| Validate input / escape output | Server-side validation on every field; Jinja autoescaping; strict CSP with no inline scripts |
| Restrict file uploads | Extension allow-list, 2 MB cap, UTF-8 text only, no binaries, filename sanitized, SSN pattern refused |
| Trim API responses | `/api/compliance/summary` returns aggregates only; no patient labels or text |
| Security headers / HTTPS | CSP, HSTS, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, `no-store` on pages; HTTP redirects to HTTPS with `FORCE_HTTPS=1` |
| Scan dependencies | `pip-audit` (clean at time of writing) |
| HIPAA-style access log | Every record view, upload, delete and check is logged and visible to compliance |

## Not done yet

- No live run against Claude yet in this environment (the model path is tested
  with a stubbed client). Add a key and run the check on the samples.
- No accuracy measurement: next step is a hand-labeled set of 100 to 200
  MIMIC-IV-Note summaries to measure agreement per rule.
- No EHR integration, SSO, or multi-factor sign-in. Privacy and Terms pages are drafts.
- SQLite is for the prototype; use Postgres with RLS and managed keys before a pilot.
