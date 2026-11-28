"""SQLite storage. Every query is parameterized, and every read of patient
data goes through a helper that requires the caller's org_id, so one
organization can never read another's records (row-level isolation).
Clinical text is encrypted before it is written."""
from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS orgs (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    org_id INTEGER NOT NULL REFERENCES orgs(id),
    email TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('physician','nurse','case_manager','compliance','admin')),
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    -- Two-factor (TOTP). Secrets are encrypted with DATA_KEY.
    totp_secret_enc BLOB,
    totp_pending_enc BLOB,
    totp_enabled_at TEXT,
    totp_last_step INTEGER NOT NULL DEFAULT 0
);

-- Single-use recovery codes for two-factor. Only a keyed hash is stored.
CREATE TABLE IF NOT EXISTS recovery_codes (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_recovery_user ON recovery_codes(user_id);

-- A password was right and a second step is still owed. Short-lived; only a
-- keyed hash of the token is stored, like sessions.
CREATE TABLE IF NOT EXISTS pending_logins (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0
);

-- Hospital single sign-on. One row per identity provider; an org may have several.
CREATE TABLE IF NOT EXISTS sso_providers (
    id INTEGER PRIMARY KEY,
    org_id INTEGER NOT NULL REFERENCES orgs(id),
    slug TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'oidc' CHECK (protocol IN ('oidc','saml')),
    issuer TEXT NOT NULL,
    client_id TEXT NOT NULL,
    client_secret_enc BLOB,
    email_domains TEXT NOT NULL DEFAULT '',
    default_role TEXT NOT NULL DEFAULT '',
    auto_provision INTEGER NOT NULL DEFAULT 0,
    enforce INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Links a provider's stable subject id to a local user.
CREATE TABLE IF NOT EXISTS sso_identities (
    id INTEGER PRIMARY KEY,
    provider_id INTEGER NOT NULL REFERENCES sso_providers(id) ON DELETE CASCADE,
    subject TEXT NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (provider_id, subject)
);

-- In-flight SSO redirects: state, nonce and PKCE verifier, single use.
CREATE TABLE IF NOT EXISTS sso_states (
    state_hash TEXT PRIMARY KEY,
    provider_id INTEGER NOT NULL REFERENCES sso_providers(id) ON DELETE CASCADE,
    nonce TEXT NOT NULL,
    code_verifier TEXT NOT NULL,
    browser_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_seen TEXT NOT NULL DEFAULT '',
    auth_method TEXT NOT NULL DEFAULT 'password',
    mfa_setup_required INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY,
    key TEXT NOT NULL,
    at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_key ON login_attempts(key, at);

CREATE TABLE IF NOT EXISTS patients (
    id INTEGER PRIMARY KEY,
    org_id INTEGER NOT NULL REFERENCES orgs(id),
    label TEXT NOT NULL,
    unit TEXT NOT NULL DEFAULT '',
    attending TEXT NOT NULL DEFAULT '',
    discharge_date TEXT NOT NULL DEFAULT '',
    disposition TEXT NOT NULL DEFAULT '',
    created_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_patients_org ON patients(org_id);

CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY,
    org_id INTEGER NOT NULL REFERENCES orgs(id),
    patient_id INTEGER NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    filename TEXT NOT NULL,
    author TEXT NOT NULL DEFAULT '',
    body_enc BLOB NOT NULL,
    uploaded_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    deleted_at TEXT,
    deleted_by INTEGER REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_documents_patient ON documents(org_id, patient_id);

CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY,
    org_id INTEGER NOT NULL REFERENCES orgs(id),
    patient_id INTEGER NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
    engine TEXT NOT NULL,
    result_enc BLOB NOT NULL,
    passed INTEGER NOT NULL,
    failed INTEGER NOT NULL,
    unclear INTEGER NOT NULL,
    created_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_analyses_patient ON analyses(org_id, patient_id);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    org_id INTEGER NOT NULL REFERENCES orgs(id),
    analysis_id INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    patient_id INTEGER NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pass','fail','unclear','not_applicable'))
);
CREATE INDEX IF NOT EXISTS idx_findings_org ON findings(org_id, rule_id);

CREATE INDEX IF NOT EXISTS idx_analyses_latest ON analyses(org_id, patient_id, id);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY,
    org_id INTEGER,
    user_id INTEGER,
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_log(org_id, id);
"""

# Columns added after the first release. Each is applied once to an older
# database; CREATE TABLE above already includes them for new ones.
MIGRATIONS = [
    ("sessions", "last_seen", "ALTER TABLE sessions ADD COLUMN last_seen TEXT NOT NULL DEFAULT ''"),
    ("documents", "deleted_at", "ALTER TABLE documents ADD COLUMN deleted_at TEXT"),
    ("documents", "deleted_by", "ALTER TABLE documents ADD COLUMN deleted_by INTEGER REFERENCES users(id)"),
    ("users", "totp_secret_enc", "ALTER TABLE users ADD COLUMN totp_secret_enc BLOB"),
    ("users", "totp_pending_enc", "ALTER TABLE users ADD COLUMN totp_pending_enc BLOB"),
    ("users", "totp_enabled_at", "ALTER TABLE users ADD COLUMN totp_enabled_at TEXT"),
    ("users", "totp_last_step", "ALTER TABLE users ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0"),
    ("sessions", "auth_method", "ALTER TABLE sessions ADD COLUMN auth_method TEXT NOT NULL DEFAULT 'password'"),
    ("sessions", "mfa_setup_required", "ALTER TABLE sessions ADD COLUMN mfa_setup_required INTEGER NOT NULL DEFAULT 0"),
]


class Database:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not path.exists():
            # Create the file owner-only before SQLite opens it: it holds password
            # hashes, labels and the audit log even though clinical text is encrypted.
            os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600))
        with self.connect() as conn:
            # Old tables first get their new columns, then the script adds any
            # indexes that depend on them.
            for table, column, ddl in MIGRATIONS:
                cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
                if cols and column not in cols:
                    conn.execute(ddl)
            conn.executescript(SCHEMA)
            conn.execute("PRAGMA journal_mode = WAL")

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ---- org-scoped helpers: the only way routes read patient data ----

    def patient(self, conn: sqlite3.Connection, org_id: int, patient_id: int):
        return conn.execute(
            "SELECT * FROM patients WHERE id = ? AND org_id = ?", (patient_id, org_id)
        ).fetchone()

    def patients(self, conn: sqlite3.Connection, org_id: int):
        return conn.execute(
            """SELECT p.*,
                      (SELECT a.failed FROM analyses a WHERE a.patient_id = p.id AND a.org_id = p.org_id
                        ORDER BY a.id DESC LIMIT 1) AS last_failed,
                      (SELECT a.unclear FROM analyses a WHERE a.patient_id = p.id AND a.org_id = p.org_id
                        ORDER BY a.id DESC LIMIT 1) AS last_unclear,
                      (SELECT a.passed FROM analyses a WHERE a.patient_id = p.id AND a.org_id = p.org_id
                        ORDER BY a.id DESC LIMIT 1) AS last_passed,
                      (SELECT COUNT(*) FROM documents d WHERE d.patient_id = p.id AND d.org_id = p.org_id
                        AND d.deleted_at IS NULL) AS doc_count
               FROM patients p WHERE p.org_id = ? ORDER BY p.discharge_date DESC, p.id DESC""",
            (org_id,),
        ).fetchall()

    def documents(self, conn: sqlite3.Connection, org_id: int, patient_id: int):
        return conn.execute(
            "SELECT * FROM documents WHERE org_id = ? AND patient_id = ? AND deleted_at IS NULL ORDER BY id",
            (org_id, patient_id),
        ).fetchall()

    def document(self, conn: sqlite3.Connection, org_id: int, patient_id: int, doc_id: int):
        return conn.execute(
            "SELECT * FROM documents WHERE id = ? AND patient_id = ? AND org_id = ? AND deleted_at IS NULL",
            (doc_id, patient_id, org_id),
        ).fetchone()

    def latest_analysis(self, conn: sqlite3.Connection, org_id: int, patient_id: int):
        return conn.execute(
            "SELECT * FROM analyses WHERE org_id = ? AND patient_id = ? ORDER BY id DESC LIMIT 1",
            (org_id, patient_id),
        ).fetchone()

    def audit(self, conn: sqlite3.Connection, org_id, user_id, action: str, target: str = "", ip: str = ""):
        conn.execute(
            "INSERT INTO audit_log (org_id, user_id, action, target, ip) VALUES (?, ?, ?, ?, ?)",
            (org_id, user_id, action, target, ip),
        )
