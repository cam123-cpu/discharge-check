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

You need Python 3.11 or newer and git. `python -m scripts.setup` creates
`.env` with fresh keys and loads the demo data. It is safe to run again: it
never changes keys that are already set, and it repairs a `.env` written by
Windows PowerShell (UTF-16) or with empty placeholder lines. The database is a
SQLite file at `data/app.db` by default, which needs nothing installed; setup
prints which database it used. To use Postgres instead, see
[Using Postgres](#using-postgres).

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
- Start over? Delete the `data` folder and run `python -m scripts.setup`
  (on Postgres, drop and recreate the database instead).
- Model review: add `ANTHROPIC_API_KEY=...` to `.env` and restart. Without it
  the built-in pattern rules run on their own.

Tests and dependency scan:

```bash
python -m pytest -q
pip-audit -r requirements.txt
```

### Using Postgres

The app runs on Postgres 14 or newer through SQLAlchemy; the driver
(`psycopg`) is already in `requirements.txt`.

1. Create a database and a role that owns it. For a local Postgres 16:

   ```bash
   docker run -d --name dc-pg -p 5432:5432 -e POSTGRES_USER=dc -e POSTGRES_PASSWORD=dc -e POSTGRES_DB=discharge postgres:16
   ```

   On a server: `CREATE ROLE dc LOGIN PASSWORD '...'; CREATE DATABASE discharge OWNER dc;`
   The app's role must **not** be a superuser or have `BYPASSRLS`, or
   row-level security is skipped (the app logs a warning at start if so).
   The default `postgres` user in the Docker image is a superuser, so create
   an ordinary role like `dc` above for anything beyond a quick try.
2. Set `DATABASE_URL` in `.env` (it wins over `DATABASE_PATH`):

   ```
   DATABASE_URL=postgresql://dc:dc@localhost:5432/discharge
   ```

   Any host other than localhost gets `sslmode=require` automatically, so
   patient data never crosses the network in plaintext; add
   `?sslmode=verify-full&sslrootcert=...` to also check the server's
   certificate. Optional settings: `DATABASE_POOL_SIZE` and
   `DATABASE_MAX_OVERFLOW` (10 and 30, sized for uvicorn's 40 worker threads),
   `DATABASE_CONNECT_TIMEOUT` (10 seconds), and `DATABASE_PGBOUNCER=1` when
   the URL is a transaction-mode pooler (PgBouncer, or a provider's "pooler"
   URL).
3. Run `python -m scripts.setup`. It applies the migrations and loads the
   demo data; the app also applies any pending migrations when it starts.

The schema lives in `app/models.py` and changes only through Alembic. After
editing the models:

```bash
alembic revision --autogenerate -m "describe the change"   # review the file in migrations/versions/
alembic upgrade head
```

**Row-level security.** On Postgres each hospital's rows are also kept apart
by the database (migration `0004`). Every request opens its transaction with
`db.connect(user["org_id"])`, which sets `app.org_id`; policies on `orgs`,
`users`, `patients`, `documents`, `analyses`, `findings` and `audit_log` then
hide and refuse other hospitals' rows, even for a query that forgets its
`org_id` filter. Sign-in, session lookup, setup and the copy script run as
the system with `db.connect()`. A transaction with neither setting sees
nothing, so a mistake fails closed. A test checks that every route passes an
org_id. This backs up the org-scoped queries; it is not a defense against SQL
injection, which parameterized queries handle. SQLite has no row-level
security and relies on the org-scoped queries alone.

Run autogenerate against a fresh database at head, never against a
`data/app.db` carried over from before this change: those files work fine but
have unnamed constraints, so the diff would be noise.

To move an existing SQLite database into Postgres (same `DATA_KEY` and
`SESSION_PEPPER` on both sides; nothing is decrypted):

```bash
python -m scripts.sqlite_to_postgres --from data/app.db --to "$DATABASE_URL" --dry-run
python -m scripts.sqlite_to_postgres --from data/app.db --to "$DATABASE_URL"
```

To run the tests against Postgres, point `TEST_DATABASE_URL` at a database
used for nothing else. **Every test wipes that database's `public` schema.**

```bash
TEST_DATABASE_URL=postgresql://dc:dc@localhost/dc_test python -m pytest -q
```

In PowerShell, set the variables for the current window with `$env:`:

```powershell
$env:DATABASE_URL = "postgresql://dc:dc@localhost:5432/discharge"
python -m scripts.setup
$env:TEST_DATABASE_URL = "postgresql://dc:dc@localhost/dc_test"; python -m pytest -q
```

### Deployment

In a deployment, set `FORCE_HTTPS=1` and `ALLOWED_HOSTS`, and when a proxy
terminates TLS add `--proxy-headers --forwarded-allow-ips=<proxy IP>` so the
app sees the real scheme and client IP (rate limits and the access log use it).

## Security checklist

| Item | How it is handled |
| --- | --- |
| Hide API keys | Keys only from environment / `.env`; `.env` is git-ignored; the browser never sees them |
| Purge Git secrets | No secrets in the repo; run `gitleaks detect` before the first push |
| Public DB key / row-level security | No browser-side database access at all. Every patient query requires the user's `org_id` (`app/db.py`), and on Postgres row-level security enforces the same split in the database (`migrations/versions/0004_row_level_security.py`). Tests prove another hospital gets a 404 and that the database refuses cross-hospital reads and writes |
| Encrypt sensitive data | Document text and results encrypted at rest (Fernet, key from `DATA_KEY`) |
| Server-side auth | Every route checks the session server-side; roles enforced on compliance pages and API |
| Lock record access / block field tampering | `org_id`, `role` and authorship come from the session, never from the form; forms accept only named fields with validation |
| Secure session cookies | Random token, only a keyed hash stored, `HttpOnly`, `SameSite=Strict`, `Secure` when `FORCE_HTTPS=1`, 8-hour expiry |
| Hash passwords | Argon2id |
| Rate limit login / bot protection | 5 failures per email and 50 per IP per 15 minutes (a hospital shares one IP); a successful sign-in clears only that account's counter; hidden honeypot field; login form token; equal timing for unknown emails |
| Rate limit costly actions | Per user: 30 checks and 120 uploads per hour |
| Automatic logoff | Sessions end after 30 idle minutes and 8 hours in total (HIPAA 164.312(a)(2)(iii)) |
| Parameterize queries | All SQL uses placeholders; path ids are range-checked before they reach the database |
| Validate input / escape output | Server-side validation on every field; Jinja autoescaping; strict CSP with no inline scripts; no page shows text taken from the URL (messages travel in a signed one-time cookie); validation errors never echo input |
| Restrict file uploads | Extension allow-list, 2 MB cap enforced before the body is parsed (also for signed-out callers), UTF-8 text only, no binaries, control and invisible characters stripped, filename sanitized, SSN pattern refused |
| Hostile files | Every text regex has bounded repetition (tested on 190 KB of crafted input); FHIR fields of the wrong type are rejected with a message, never a crash; nested JSON and oversized attachments are refused |
| Prompt injection into model review | Documents are fenced in tags that the record cannot close; a model "pass" needs a quote of 8+ characters found in the cited document, and that document must be a kind the rule accepts; whether a rule applies is decided in code, so the model cannot drop a rule as "not applicable"; records containing text aimed at an AI reviewer are flagged, and on those the model can only make results stricter, never clear or soften a gap |
| Record integrity | Removing a document is a soft delete kept for retention, allowed to the uploader or an administrator only |
| Errors | Unhandled errors return a plain page with security headers and no stack trace |
| Scan dependencies | `pip-audit` (clean at time of writing) |
| HIPAA-style access log | Every sign-in, sign-out, record view, upload, removal, check, compliance view and export is logged; compliance staff can page and filter it |
| Database access | SQLite: the file is created owner-only (0600) in an owner-only folder. Postgres: connect with TLS (`sslmode=require`) as a least-privilege role that owns only the app's database |

Full findings from the November 2026 penetration test: [docs/security-review-2026-11.md](docs/security-review-2026-11.md).

## Not done yet

- No live run against Claude yet in this environment (the model path is tested
  with a stubbed client). Add a key and run the check on the samples.
- No accuracy measurement: next step is a hand-labeled set of 100 to 200
  MIMIC-IV-Note summaries to measure agreement per rule.
- No EHR integration, SSO, or multi-factor sign-in. Privacy and Terms pages are drafts.
- Managed encryption keys (KMS) are still to do before a pilot; `DATA_KEY`
  lives in `.env`. SQLite is for local use only.
