# Discharge Check (prototype)

A web app that reads a patient's discharge record (discharge summary, nursing
instructions, case management notes), writes a short patient brief, and checks
the record against CMS discharge rules before it is signed. Compliance staff get
a roll-up of what is missing by rule, attending and unit.

**Synthetic or de-identified data only.** Do not upload real patient records
until there is a signed Business Associate Agreement with every vendor that
touches the data (including Anthropic, if model review is on).

## What it does

- **Ingest:** `.txt`, `.md`, or FHIR R4 `.json` (any Bundle type, DocumentReference, Composition or Encounter), or a pull from an EHR over SMART on FHIR (below).
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

You need Python 3.11 or newer and git. `python -m scripts.setup` creates
`.env` with fresh keys and loads the demo data. It is safe to run again: it
never changes keys that are already set, and it repairs a `.env` written by
Windows PowerShell (UTF-16) or with empty placeholder lines.

**macOS / Linux**

```bash
git clone https://github.com/cam123-cpu/discharge-check.git
cd discharge-check
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
python -m scripts.setup
uvicorn app.main:get_app --factory --port 8000 --no-server-header
```

**Windows (PowerShell)**

```powershell
git clone https://github.com/cam123-cpu/discharge-check.git
cd discharge-check
python -m venv .venv
Set-ExecutionPolicy -Scope Process Bypass   # lets this window run the activate script
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
python -m scripts.setup
uvicorn app.main:get_app --factory --port 8000 --no-server-header
```

Open http://localhost:8000. Setup prints five demo accounts with random
passwords, once. Sign in as `compliance@demo.test` (or `admin@demo.test`,
who can also remove documents), open a discharge and press **Run check**.

- Lost the passwords? `python -m scripts.setup --new-passwords`
- Start over? Delete the `data` folder and run `python -m scripts.setup`.
- Model review: add `ANTHROPIC_API_KEY=...` to `.env` and restart. Without it
  the built-in pattern rules run on their own.

Tests and dependency scan:

```bash
python -m pytest -q
pip-audit -r requirements.txt
```

In a deployment, set `FORCE_HTTPS=1` and `ALLOWED_HOSTS`, and when a proxy
terminates TLS add `--proxy-headers --forwarded-allow-ips=<proxy IP>` so the
app sees the real scheme and client IP (rate limits and the access log use it).

## Pull from an EHR sandbox (SMART on FHIR)

`app/fhir/smart.py` is a SMART on FHIR R4 client and `app/fhir/parse.py` turns
what it pulls into the same sectioned text an upload produces. Use synthetic
sandboxes only; the Patient resource is never saved and patient names are
redacted from narrative text.

Settings go in `.env` (see the `FHIR_*` block in `.env.example`). Three modes:

| Mode | Use it for | You need |
| --- | --- | --- |
| `open` | SMART Health IT open server (`https://r4.smarthealthit.org`), no login | `FHIR_BASE_URL` |
| `backend` | Epic sandbox or any server with SMART Backend Services (system-to-system) | client id, a private key (RS384 or ES384) whose public JWKS you registered, `FHIR_KEY_ID` |
| `standalone` | Sign in as a clinician in the browser (authorization code + PKCE) | client id, `FHIR_REDIRECT_URI` on `http://localhost:<port>/...` |

```bash
python -m scripts.fhir_pull discover                       # checks the server and its OAuth endpoints
python -m scripts.fhir_pull jwks --key keys/epic.pem       # public JWKS to register a backend app
python -m scripts.fhir_pull pull --patient <id> [--encounter <id>] --out data/pull.json
python -m scripts.fhir_pull import --bundle data/pull.json --org-id 1 --label SYN-0100
```

To find a test patient on the open server:
`curl -s 'https://r4.smarthealthit.org/Patient?_count=5' | python -m json.tool | grep '"id"'`.

`pull` picks the most recent finished inpatient encounter when `--encounter` is
left out, and fetches its Encounter, Conditions, MedicationRequests (with their
Medications), allergies, DocumentReferences (and Binary attachments), pending
DiagnosticReports, follow-up Appointments and ServiceRequests, CarePlans, Goals
and Procedures. Searches a server does not support for an encounter fall back
to patient-level and are filtered back to that encounter; types the token's
scopes do not cover are skipped with a warning. Paging stays on the configured
server, redirects are never followed, and tokens are never printed or logged.
Keep private keys outside the repo (`*.pem` and `*.key` are git-ignored).

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
| Rate limit login / bot protection | 5 failures per email and 50 per IP per 15 minutes (a hospital shares one IP); a successful sign-in clears only that account's counter; hidden honeypot field; login form token; equal timing for unknown emails |
| Rate limit costly actions | Per user: 30 checks and 120 uploads per hour |
| Automatic logoff | Sessions end after 30 idle minutes and 8 hours in total (HIPAA 164.312(a)(2)(iii)) |
| Parameterize queries | All SQL uses placeholders; path ids are range-checked before they reach SQLite |
| Validate input / escape output | Server-side validation on every field; Jinja autoescaping; strict CSP with no inline scripts; no page shows text taken from the URL (messages travel in a signed one-time cookie); validation errors never echo input |
| Restrict file uploads | Extension allow-list, 2 MB cap enforced before the body is parsed (also for signed-out callers), UTF-8 text only, no binaries, control and invisible characters stripped, filename sanitized, SSN pattern refused |
| Hostile files | Every text regex has bounded repetition (tested on 190 KB of crafted input); FHIR fields of the wrong type are rejected with a message, never a crash; nested JSON and oversized attachments are refused |
| Prompt injection into model review | Documents are fenced in tags that the record cannot close; a model "pass" needs a quote of 8+ characters found in the cited document, and that document must be a kind the rule accepts; whether a rule applies is decided in code, so the model cannot drop a rule as "not applicable"; records containing text aimed at an AI reviewer are flagged, and on those the model can only make results stricter, never clear or soften a gap |
| Record integrity | Removing a document is a soft delete kept for retention, allowed to the uploader or an administrator only |
| Errors | Unhandled errors return a plain page with security headers and no stack trace |
| Scan dependencies | `pip-audit` (clean at time of writing) |
| HIPAA-style access log | Every sign-in, sign-out, record view, upload, removal, check, compliance view and export is logged; compliance staff can page and filter it |
| Database file | Created owner-only (0600) in an owner-only folder |

Full findings from the November 2026 penetration test: [docs/security-review-2026-11.md](docs/security-review-2026-11.md).

## Not done yet

- No live run against Claude yet in this environment (the model path is tested
  with a stubbed client). Add a key and run the check on the samples.
- No accuracy measurement: next step is a hand-labeled set of 100 to 200
  MIMIC-IV-Note summaries to measure agreement per rule.
- No EHR integration, SSO, or multi-factor sign-in. Privacy and Terms pages are drafts.
- SQLite is for the prototype; use Postgres with RLS and managed keys before a pilot.
