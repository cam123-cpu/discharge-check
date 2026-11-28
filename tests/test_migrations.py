"""Alembic migrations: a fresh database matches app.models, downgrades work,
and SQLite files made by the pre-Alembic code are adopted without data loss.

Runs on SQLite, and on Postgres when TEST_DATABASE_URL is set. The legacy
adoption tests are SQLite-only: the original code only ever wrote SQLite."""
import secrets
import sqlite3

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError

from app.config import Settings
from app.db import Database
from app.main import create_app
from app.models import metadata
from app.security import Cipher, hash_password

from .conftest import PASSWORD, login

APP_TABLES = set(metadata.tables)


def _script_cfg():
    from alembic.config import Config

    from app.db import MIGRATIONS_DIR
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    return cfg


SCRIPT = ScriptDirectory.from_config(_script_cfg())
HEAD = SCRIPT.get_current_head()


@pytest.fixture
def db(database_url, tmp_path):
    database = Database(database_url or tmp_path / "db.sqlite")
    yield database
    database.dispose()


def _diffs(database: Database) -> list:
    """What `alembic revision --autogenerate` would emit, with the options
    migrations/env.py configures."""
    with database.engine.connect() as conn:
        ctx = MigrationContext.configure(conn, opts={
            "target_metadata": metadata,
            "compare_type": True,
            "compare_server_default": True,
        })
        return compare_metadata(ctx, metadata)


def _indexes(database: Database, table: str) -> set[str]:
    with database.engine.connect() as conn:
        return {ix["name"] for ix in inspect(conn).get_indexes(table)}


def _columns(database: Database, table: str) -> set[str]:
    with database.engine.connect() as conn:
        return {c["name"] for c in inspect(conn).get_columns(table)}


def _tables(database: Database) -> set[str]:
    with database.engine.connect() as conn:
        return set(inspect(conn).get_table_names())


# ---- fresh database ----

def test_single_linear_head():
    assert SCRIPT.get_heads() == [HEAD]  # one linear history, no branches
    revs = [r.revision for r in SCRIPT.walk_revisions()]
    assert revs[-1] == "0001" and revs[-2] == "0002"
    assert revs == sorted(revs, reverse=True)


def test_fresh_database_is_at_head(db):
    assert db.current_revision() == HEAD
    assert ScriptDirectory.from_config(db.alembic_config()).get_current_head() == HEAD
    assert APP_TABLES <= _tables(db)
    assert {"idx_sessions_user"} <= _indexes(db, "sessions")
    assert {"idx_findings_analysis", "idx_findings_org"} <= _indexes(db, "findings")


def test_models_match_migrations(db):
    diffs = _diffs(db)
    assert diffs == [], f"migrations and app/models.py disagree: {diffs}"


def test_migrate_twice_is_idempotent(db, database_url, tmp_path):
    with db.connect() as conn:
        conn.execute("INSERT INTO orgs (name) VALUES ('Kept')")
    db.migrate()
    again = Database(database_url or tmp_path / "db.sqlite")
    try:
        assert again.current_revision() == HEAD
        with again.connect() as conn:
            assert conn.execute("SELECT name FROM orgs").fetchall() == [("Kept",)]
        assert _diffs(again) == []
    finally:
        again.dispose()


def test_migrate_false_leaves_database_empty(database_url, tmp_path):
    database = Database(database_url or tmp_path / "empty.sqlite", migrate=False)
    try:
        assert database.current_revision() is None
        assert not (APP_TABLES & _tables(database))
    finally:
        database.dispose()


def _run(database: Database, fn, revision: str) -> None:
    cfg = database.alembic_config()
    with database.engine.begin() as conn:
        cfg.attributes["connection"] = conn
        fn(cfg, revision)


def test_downgrade_to_base_then_upgrade(db):
    with db.connect() as conn:
        conn.execute("INSERT INTO orgs (name) VALUES ('gone')")

    _run(db, command.downgrade, "0001")
    assert db.current_revision() == "0001"
    assert "idx_sessions_user" not in _indexes(db, "sessions")
    assert "idx_findings_analysis" not in _indexes(db, "findings")

    _run(db, command.downgrade, "base")
    assert db.current_revision() is None
    assert not (APP_TABLES & _tables(db))

    _run(db, command.upgrade, "head")
    assert db.current_revision() == HEAD
    assert APP_TABLES <= _tables(db)
    assert _diffs(db) == []
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM orgs").fetchone()[0] == 0
        assert conn.execute("INSERT INTO orgs (name) VALUES ('new')").lastrowid is not None


TEXT_TIMESTAMPS_C = [("sessions", "expires_at"), ("sessions", "last_seen"), ("login_attempts", "at")]


def _collations(database: Database) -> dict:
    with database.connect() as conn:
        rows = conn.execute(
            "SELECT table_name, column_name, collation_name FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name IN ('sessions', 'login_attempts')").fetchall()
    return {(r["table_name"], r["column_name"]): r["collation_name"] for r in rows}


def test_postgres_timestamp_text_uses_c_collation(db):
    if db.url.get_backend_name() != "postgresql":
        pytest.skip("collations are Postgres-only; set TEST_DATABASE_URL")
    coll = _collations(db)
    for col in TEXT_TIMESTAMPS_C:
        assert coll[col] == "C", col
    assert coll[("sessions", "token_hash")] is None  # other text keeps the database default
    # Downgrading 0003 restores the default, upgrading sets "C" again.
    _run(db, command.downgrade, "0002")
    assert all(_collations(db)[col] is None for col in TEXT_TIMESTAMPS_C)
    _run(db, command.upgrade, "head")
    assert all(_collations(db)[col] == "C" for col in TEXT_TIMESTAMPS_C)
    assert _diffs(db) == []


def test_c_collation_orders_iso_timestamps_bytewise(db):
    with db.connect() as conn:
        conn.executemany("INSERT INTO login_attempts (key, at) VALUES (?, ?)",
                         [("k", "2026-11-28T10:00:00+00:00"), ("k", "2026-11-28 09:00:00"), ("k", "2026-11-28T09:30:00Z")])
        got = [r[0] for r in conn.execute("SELECT at FROM login_attempts ORDER BY at").fetchall()]
    assert got == sorted(got, key=lambda v: v.encode())


def test_step_by_step_upgrade_matches_head(db):
    _run(db, command.downgrade, "base")
    _run(db, command.upgrade, "0001")
    assert db.current_revision() == "0001"
    db.migrate()
    assert db.current_revision() == HEAD
    assert _diffs(db) == []


# ---- legacy SQLite files (pre-Alembic) ----

# Verbatim from app/db.py before the SQLAlchemy move (`git show 29a00ca:app/db.py`).
LEGACY_SCHEMA = """
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
    expires_at TEXT NOT NULL,
    last_seen TEXT NOT NULL DEFAULT ''
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

# The same schema without the columns added after the first release
# (sessions.last_seen, documents.deleted_at, documents.deleted_by). Only the
# columns differ; the indexes are those of the last pre-Alembic release.
LEGACY_SCHEMA_NO_LATER_COLUMNS = (
    LEGACY_SCHEMA
    .replace("    expires_at TEXT NOT NULL,\n    last_seen TEXT NOT NULL DEFAULT ''\n", "    expires_at TEXT NOT NULL\n")
    .replace("    created_at TEXT NOT NULL DEFAULT (datetime('now')),\n    deleted_at TEXT,\n"
             "    deleted_by INTEGER REFERENCES users(id)\n", "    created_at TEXT NOT NULL DEFAULT (datetime('now'))\n")
)
assert "last_seen" not in LEGACY_SCHEMA_NO_LATER_COLUMNS and "deleted_" not in LEGACY_SCHEMA_NO_LATER_COLUMNS

# A file the first release (17e1fb3) made and no later pre-Alembic release
# opened: it also lacks the indexes idx_analyses_latest and idx_audit_org,
# which that later release created on start.
FIRST_RELEASE_SCHEMA = (
    LEGACY_SCHEMA_NO_LATER_COLUMNS
    .replace("CREATE INDEX IF NOT EXISTS idx_analyses_latest ON analyses(org_id, patient_id, id);\n", "")
    .replace("CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_log(org_id, id);\n", "")
)
assert "idx_analyses_latest" not in FIRST_RELEASE_SCHEMA and "idx_audit_org" not in FIRST_RELEASE_SCHEMA

DOC_TEXT = "Synthetic discharge summary for LEG-1. Follow up with cardiology in 7 days."


def _make_legacy_file(path, schema: str, data_key: str) -> dict:
    """A SQLite file as the pre-Alembic code left it, with some rows."""
    has_later = "last_seen" in schema
    cipher = Cipher(data_key)
    conn = sqlite3.connect(path)
    conn.executescript(schema)
    conn.execute("PRAGMA journal_mode = WAL")
    ids = {}
    with conn:
        ids["org"] = conn.execute("INSERT INTO orgs (name) VALUES ('Legacy Org')").lastrowid
        other = conn.execute("INSERT INTO orgs (name) VALUES ('Other Org')").lastrowid
        ids["user"] = conn.execute(
            "INSERT INTO users (org_id, email, display_name, role, password_hash) VALUES (?, ?, ?, ?, ?)",
            (ids["org"], "cm@legacy.test", "cm", "compliance", hash_password(PASSWORD))).lastrowid
        conn.execute("INSERT INTO users (org_id, email, display_name, role, password_hash) VALUES (?, ?, ?, ?, ?)",
                     (other, "x@other.test", "x", "nurse", hash_password(PASSWORD)))
        if has_later:
            conn.execute("INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at, last_seen) VALUES (?, ?, ?, ?, ?)",
                         ("oldtoken", ids["user"], "c", "2000-01-01T00:00:00+00:00", "2000-01-01T00:00:00+00:00"))
        else:
            conn.execute("INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)",
                         ("oldtoken", ids["user"], "c", "2000-01-01T00:00:00+00:00"))
        conn.execute("INSERT INTO login_attempts (key) VALUES ('email:nobody@x.test')")
        ids["patient"] = conn.execute(
            "INSERT INTO patients (org_id, label, discharge_date, disposition, created_by) VALUES (?, 'LEG-1', '2026-01-02', 'Home', ?)",
            (ids["org"], ids["user"])).lastrowid
        conn.execute("INSERT INTO patients (org_id, label) VALUES (?, 'OTHER-1')", (other,))
        ids["doc"] = conn.execute(
            "INSERT INTO documents (org_id, patient_id, kind, filename, author, body_enc, uploaded_by) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ids["org"], ids["patient"], "discharge_summary", "legacy.txt", "Dr. Synthetic", cipher.encrypt(DOC_TEXT), ids["user"])).lastrowid
        ids["analysis"] = conn.execute(
            "INSERT INTO analyses (org_id, patient_id, engine, result_enc, passed, failed, unclear, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (ids["org"], ids["patient"], "rules", cipher.encrypt("{}"), 3, 1, 0, ids["user"])).lastrowid
        conn.executemany("INSERT INTO findings (org_id, analysis_id, patient_id, rule_id, status) VALUES (?, ?, ?, ?, ?)",
                         [(ids["org"], ids["analysis"], ids["patient"], f"R{i}", "pass") for i in range(3)])
        conn.execute("INSERT INTO audit_log (org_id, user_id, action, target) VALUES (?, ?, 'login', '')", (ids["org"], ids["user"]))
    conn.close()
    return ids


LEGACY_VARIANTS = [
    pytest.param(LEGACY_SCHEMA, id="last-pre-alembic"),
    pytest.param(LEGACY_SCHEMA_NO_LATER_COLUMNS, id="without-later-columns"),
]


def _legacy_settings(path, data_key) -> Settings:
    return Settings(data_key=data_key, session_pepper=secrets.token_urlsafe(32), anthropic_api_key=None,
                    force_https=False, database_path=path, database_url="")


@pytest.mark.parametrize("schema", LEGACY_VARIANTS)
def test_legacy_sqlite_file_is_adopted(tmp_path, schema):
    path = tmp_path / "legacy.db"
    key = Fernet.generate_key().decode()
    ids = _make_legacy_file(path, schema, key)

    db = Database(path)
    try:
        assert db.current_revision() == HEAD
        assert {"last_seen"} <= _columns(db, "sessions")
        assert {"deleted_at", "deleted_by"} <= _columns(db, "documents")
        assert "idx_sessions_user" in _indexes(db, "sessions")
        assert "idx_findings_analysis" in _indexes(db, "findings")
        assert {"idx_analyses_latest", "idx_analyses_patient"} <= _indexes(db, "analyses")
        assert "idx_audit_org" in _indexes(db, "audit_log")

        with db.connect() as conn:
            counts = {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                      for t in ("orgs", "users", "sessions", "login_attempts", "patients", "documents", "analyses", "findings", "audit_log")}
            assert counts == {"orgs": 2, "users": 2, "sessions": 1, "login_attempts": 1, "patients": 2,
                              "documents": 1, "analyses": 1, "findings": 3, "audit_log": 1}
            assert conn.execute("SELECT last_seen FROM sessions").fetchone()[0] in ("", "2000-01-01T00:00:00+00:00")
            doc = db.document(conn, ids["org"], ids["patient"], ids["doc"])
            assert doc is not None and doc["deleted_at"] is None and doc["deleted_by"] is None
            assert Cipher(key).decrypt(doc["body_enc"]) == DOC_TEXT
            assert [p["label"] for p in db.patients(conn, ids["org"])] == ["LEG-1"]
            # New rows keep numbering after the old ones.
            assert conn.execute("INSERT INTO orgs (name) VALUES ('Third')").lastrowid == 3
            # Foreign keys and cascades from the old DDL still hold.
            conn.execute("DELETE FROM analyses WHERE id = ?", (ids["analysis"],))
            assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0
            conn.execute("UPDATE documents SET deleted_at = ?, deleted_by = ? WHERE id = ?", ("2026-01-01", ids["user"], ids["doc"]))
        with pytest.raises(IntegrityError):
            with db.connect() as conn:
                conn.execute("INSERT INTO patients (org_id, label) VALUES (999, 'orphan')")
    finally:
        db.dispose()

    # Opening it again changes nothing.
    again = Database(path)
    try:
        assert again.current_revision() == HEAD
        with again.connect() as conn:
            assert conn.execute("SELECT COUNT(*) FROM patients").fetchone()[0] == 2
    finally:
        again.dispose()


@pytest.mark.parametrize("schema", LEGACY_VARIANTS)
def test_app_runs_on_legacy_file(tmp_path, schema):
    path = tmp_path / "legacy.db"
    key = Fernet.generate_key().decode()
    ids = _make_legacy_file(path, schema, key)

    app = create_app(_legacy_settings(path, key))  # adopts the file on start
    try:
        assert app.state.db.current_revision() == HEAD
        client = TestClient(app)
        r = login(client, "cm@legacy.test")
        assert r.status_code == 303 and "/login" not in r.headers["location"]
        page = client.get("/patients")
        assert page.status_code == 200 and "LEG-1" in page.text and "OTHER-1" not in page.text
        doc = client.get(f"/patients/{ids['patient']}/documents/{ids['doc']}")
        assert doc.status_code == 200 and "Follow up with cardiology" in doc.text
        with app.state.db.connect() as conn:
            assert conn.execute("SELECT COUNT(*) FROM sessions WHERE token_hash != 'oldtoken'").fetchone()[0] == 1
    finally:
        app.state.db.dispose()


@pytest.mark.parametrize("schema", LEGACY_VARIANTS)
def test_legacy_file_has_no_structural_drift(tmp_path, schema):
    """After adoption nothing is missing that a fresh database would have.
    Differences SQLite reflection cannot see past on the old inline DDL
    (unnamed constraints, PK nullability, inline ON DELETE) are ignored."""
    path = tmp_path / "legacy.db"
    _make_legacy_file(path, schema, Fernet.generate_key().decode())
    db = Database(path)
    try:
        structural = [d for d in _flatten(_diffs(db)) if d[0] in ("add_table", "add_column", "add_index", "remove_column", "modify_type")]
        assert structural == []
    finally:
        db.dispose()


def test_first_release_file_gets_later_indexes(tmp_path):
    path = tmp_path / "first.db"
    _make_legacy_file(path, FIRST_RELEASE_SCHEMA, Fernet.generate_key().decode())
    db = Database(path)
    try:
        assert db.current_revision() == HEAD
        assert "idx_analyses_latest" in _indexes(db, "analyses")
        assert "idx_audit_org" in _indexes(db, "audit_log")
    finally:
        db.dispose()


def test_first_release_file_still_opens(tmp_path):
    path = tmp_path / "first.db"
    key = Fernet.generate_key().decode()
    ids = _make_legacy_file(path, FIRST_RELEASE_SCHEMA, key)
    db = Database(path)
    try:
        assert db.current_revision() == HEAD
        assert {"deleted_at", "deleted_by"} <= _columns(db, "documents")
        with db.connect() as conn:
            assert Cipher(key).decrypt(db.document(conn, ids["org"], ids["patient"], ids["doc"])["body_enc"]) == DOC_TEXT
    finally:
        db.dispose()


def test_alembic_command_line_adopts_legacy_file(tmp_path, monkeypatch):
    """`alembic upgrade head` with alembic.ini and no connection of ours: env.py
    builds the database from DATABASE_PATH and adopts the pre-Alembic file."""
    from alembic.config import Config

    from app.db import ROOT
    path = tmp_path / "cli.db"
    key = Fernet.generate_key().decode()
    ids = _make_legacy_file(path, LEGACY_SCHEMA_NO_LATER_COLUMNS, key)
    monkeypatch.setenv("DATABASE_URL", "")
    monkeypatch.setenv("DATABASE_PATH", str(path))
    cfg = Config(str(ROOT / "alembic.ini"))
    assert cfg.attributes.get("connection") is None
    command.upgrade(cfg, "head")

    db = Database(path, migrate=False)
    try:
        assert db.current_revision() == HEAD
        assert {"last_seen"} <= _columns(db, "sessions")
        assert {"deleted_at", "deleted_by"} <= _columns(db, "documents")
        assert "idx_sessions_user" in _indexes(db, "sessions")
        assert "idx_findings_analysis" in _indexes(db, "findings")
        with db.connect() as conn:
            assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 3
            doc = db.document(conn, ids["org"], ids["patient"], ids["doc"])
            assert Cipher(key).decrypt(doc["body_enc"]) == DOC_TEXT
    finally:
        db.dispose()
    command.upgrade(cfg, "head")  # a second run is a no-op
    db = Database(path)
    try:
        assert db.current_revision() == HEAD
    finally:
        db.dispose()


def _flatten(diffs):
    for d in diffs:
        if isinstance(d, list):
            yield from d
        else:
            yield d
