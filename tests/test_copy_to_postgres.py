"""scripts/sqlite_to_postgres: copy a SQLite install into Postgres.

Runs only when TEST_DATABASE_URL names a Postgres database, which it wipes.
"""
import os
import re
import secrets

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import models as m
from app.config import Settings
from app.db import Database, normalize_url, set_rls_context
from app.main import create_app
from app.security import Cipher, hash_password
from scripts import sqlite_to_postgres as copier
from tests.conftest import PASSWORD, csrf_of, login

TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "").strip()
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL.startswith(("postgres://", "postgresql")),
    reason="set TEST_DATABASE_URL to a disposable Postgres database",
)

SECRET_NOTE = "Ventricular ejection fraction 35 percent (synthetic)"


def _reset_postgres() -> None:
    db = Database(TEST_DATABASE_URL, migrate=False)
    with db.engine.begin() as conn:
        conn.exec_driver_sql("DROP SCHEMA IF EXISTS public CASCADE")
        conn.exec_driver_sql("CREATE SCHEMA public")
    db.dispose()


def _settings(tmp_path, data_key, pepper, database_url=""):
    return Settings(data_key=data_key, session_pepper=pepper, anthropic_api_key=None, force_https=False,
                    database_path=tmp_path / "app.db", database_url=database_url)


def _dump(db: Database) -> dict[str, list[tuple]]:
    out = {}
    with db.engine.connect() as conn:
        set_rls_context(conn, None)  # every organization's rows
        for t in m.metadata.sorted_tables:
            rows = conn.execute(select(t).order_by(*t.primary_key.columns)).fetchall()
            out[t.name] = [tuple(bytes(v) if isinstance(v, memoryview) else v for v in r) for r in rows]
    return out


@pytest.fixture
def keys():
    return Fernet.generate_key().decode(), secrets.token_urlsafe(32)


@pytest.fixture
def sqlite_install(tmp_path, keys):
    """A SQLite install with data in every table, made through the app."""
    data_key, pepper = keys
    app = create_app(_settings(tmp_path, data_key, pepper))
    cipher = Cipher(data_key)
    db = app.state.db
    with db.connect() as conn:
        a = conn.execute("INSERT INTO orgs (name) VALUES ('Org A')").lastrowid
        b = conn.execute("INSERT INTO orgs (name) VALUES ('Org B')").lastrowid
        conn.execute("INSERT INTO users (org_id, email, display_name, role, password_hash) VALUES (?, ?, ?, ?, ?)",
                     (a, "cm@a.test", "cm", "compliance", hash_password(PASSWORD)))
        conn.execute("INSERT INTO users (org_id, email, display_name, role, password_hash) VALUES (?, ?, ?, ?, ?)",
                     (b, "doc@b.test", "doc", "physician", hash_password(PASSWORD)))
        # Gaps in ids, so a copy that renumbers rows would show.
        for i in range(25):
            conn.execute("INSERT INTO patients (org_id, label, discharge_date) VALUES (?, ?, '2026-11-14')", (a, f"BULK-{i}"))
        conn.execute("DELETE FROM patients WHERE label IN ('BULK-3', 'BULK-7')")
        p = conn.execute("INSERT INTO patients (org_id, label) VALUES (?, 'B-1')", (b,)).lastrowid
        conn.execute("INSERT INTO documents (org_id, patient_id, kind, filename, body_enc) VALUES (?, ?, ?, ?, ?)",
                     (b, p, "other", "note.txt", cipher.encrypt(SECRET_NOTE)))
        conn.execute("INSERT INTO audit_log (org_id, user_id, action) VALUES (?, NULL, 'seed')", (a,))

    # A real patient, upload, check and login through the app's own routes.
    client = TestClient(app)
    login(client, "cm@a.test", "wrong password")  # leaves a login_attempts row
    assert login(client, "cm@a.test").status_code == 303
    token = csrf_of(client)
    r = client.post("/patients", data={"csrf": token, "label": "SYN-9", "discharge_date": "2026-11-14",
                                       "disposition": "Home"}, follow_redirects=False)
    pid = int(r.headers["location"].rsplit("/", 1)[1])
    text = (copier.ROOT / "samples" / "syn-0001-summary.txt").read_bytes()
    r = client.post(f"/patients/{pid}/documents", data={"csrf": token, "kind": "discharge_summary", "confirm": "yes"},
                    files={"file": ("summary.txt", text, "text/plain")}, follow_redirects=True)
    assert "Added summary.txt" in r.text
    r = client.post(f"/patients/{pid}/check", data={"csrf": token}, follow_redirects=True)
    assert r.status_code == 200
    db.dispose()

    path = tmp_path / "app.db"
    src = Database(path)
    dump = _dump(src)
    src.dispose()
    for name, rows in dump.items():
        assert rows, f"seed left {name} empty"
    return path, dump


@pytest.fixture
def target():
    _reset_postgres()
    return normalize_url(TEST_DATABASE_URL)


def test_copy_preserves_rows_ids_and_blobs(sqlite_install, target, tmp_path, keys, capsys):
    path, before = sqlite_install
    report = copier.run(path, target, batch=4)  # small batches: several per table
    out = capsys.readouterr().out
    assert SECRET_NOTE not in out and "cm@a.test" not in out
    assert "DATA_KEY" in out

    pg = Database(TEST_DATABASE_URL)
    after = _dump(pg)
    assert after == before  # every row, every id, every blob byte-for-byte
    assert report.source_counts == report.target_counts == {k: len(v) for k, v in before.items()}

    # Sequences continue after the copied ids (and start at 1 on empty tables).
    with pg.connect() as conn:
        pid = conn.execute("INSERT INTO patients (org_id, label) VALUES (1, 'NEW')").lastrowid
        oid = conn.execute("INSERT INTO orgs (name) VALUES ('Org C')").lastrowid
        aid = conn.execute("INSERT INTO audit_log (action) VALUES ('after-copy')").lastrowid
        lid = conn.execute("INSERT INTO login_attempts (key) VALUES ('k')").lastrowid
    assert pid == max(r[0] for r in before["patients"]) + 1
    assert oid == max(r[0] for r in before["orgs"]) + 1
    assert aid == max(r[0] for r in before["audit_log"]) + 1
    assert lid == max(r[0] for r in before["login_attempts"]) + 1
    pg.dispose()

    # The app on Postgres with the same keys signs a copied user in and decrypts copied text.
    data_key, pepper = keys
    app = create_app(_settings(tmp_path, data_key, pepper, database_url=TEST_DATABASE_URL))
    try:
        client = TestClient(app)
        assert login(client, "doc@b.test").status_code == 303
        with app.state.db.connect() as conn:
            doc = conn.execute("SELECT id, patient_id FROM documents WHERE filename = 'note.txt'").fetchone()
        r = client.get(f"/patients/{doc['patient_id']}/documents/{doc['id']}")
        assert r.status_code == 200 and SECRET_NOTE in r.text
        # And a copied analysis decrypts too.
        with app.state.db.connect() as conn:
            blob = conn.execute("SELECT result_enc FROM analyses ORDER BY id LIMIT 1").fetchone()[0]
        assert '"findings"' in Cipher(data_key).decrypt(blob)
    finally:
        app.state.db.dispose()


def test_refuses_non_empty_target(sqlite_install, target, capsys):
    path, _ = sqlite_install
    pg = Database(TEST_DATABASE_URL)
    with pg.connect() as conn:
        conn.execute("INSERT INTO orgs (name) VALUES ('Already here')")
    pg.dispose()
    with pytest.raises(copier.CopyError, match="not empty.*orgs"):
        copier.run(path, target)
    pg = Database(TEST_DATABASE_URL)
    with pg.engine.connect() as conn:
        set_rls_context(conn, None)
        assert conn.exec_driver_sql("SELECT count(*) FROM orgs").scalar() == 1
        assert conn.exec_driver_sql("SELECT count(*) FROM users").scalar() == 0
    pg.dispose()

    # The command line reports it and exits non-zero, with the password masked.
    url = target.render_as_string(hide_password=False)
    assert copier.main(["--from", str(path), "--to", url]) == 1
    captured = capsys.readouterr()
    assert "not empty" in captured.err
    assert ":***@" in captured.out
    if target.password:
        assert f":{target.password}@" not in captured.out + captured.err


def test_dry_run_counts_and_writes_nothing(sqlite_install, target, capsys):
    path, before = sqlite_install
    url = target.render_as_string(hide_password=False)
    assert copier.main(["--from", str(path), "--to", url, "--dry-run"]) == 0
    out = capsys.readouterr().out
    for name, rows in before.items():
        assert re.search(rf"^{name}\s+{len(rows)}\s+-\s*$", out, re.MULTILINE), name
    assert "nothing was migrated or written" in out
    # The target was not even migrated.
    pg = Database(TEST_DATABASE_URL, migrate=False)
    with pg.engine.connect() as conn:
        assert conn.exec_driver_sql("SELECT count(*) FROM pg_tables WHERE schemaname = 'public'").scalar() == 0
    pg.dispose()


def test_missing_source_and_non_postgres_target(tmp_path):
    with pytest.raises(copier.CopyError, match="not found"):
        copier._source_path(str(tmp_path / "nope.db"))
    assert not (tmp_path / "nope.db").exists()
    with pytest.raises(copier.CopyError, match="must be a Postgres URL"):
        copier._target_url("sqlite:///x.db")
