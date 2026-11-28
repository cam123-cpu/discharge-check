"""SQLite storage. Every query is parameterized, and every read of patient
data goes through a helper that requires the caller's org_id, so one
organization can never read another's records (row-level isolation).

Clinical text is encrypted before it is written. Names, units, attendings,
dispositions and discharge dates are sealed by the caller (see Cipher.encrypt_field).
Rule-level pass/fail lives only inside the sealed analysis blob. The findings
table is kept so older databases still open; new checks do not write it.
The passed/failed/unclear columns are a cache. Screens recompute from the blob.
"""
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
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    expires_at TEXT NOT NULL
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
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
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

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY,
    org_id INTEGER,
    user_id INTEGER,
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


class Database:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(SCHEMA)
        self._restrict()

    def _restrict(self) -> None:
        """Keep the database file owner-readable. A prototype stand-in for disk encryption."""
        if os.name != "posix":
            return
        for path in (self.path, Path(str(self.path) + "-wal"), Path(str(self.path) + "-shm")):
            if path.exists():
                os.chmod(path, 0o600)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
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
            self._restrict()

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
                      (SELECT COUNT(*) FROM documents d WHERE d.patient_id = p.id AND d.org_id = p.org_id) AS doc_count,
                      (SELECT a.result_enc FROM analyses a WHERE a.patient_id = p.id AND a.org_id = p.org_id
                        ORDER BY a.id DESC LIMIT 1) AS result_enc
               FROM patients p WHERE p.org_id = ? ORDER BY p.id DESC""",
            (org_id,),
        ).fetchall()

    def documents(self, conn: sqlite3.Connection, org_id: int, patient_id: int):
        return conn.execute(
            "SELECT * FROM documents WHERE org_id = ? AND patient_id = ? ORDER BY id",
            (org_id, patient_id),
        ).fetchall()

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
