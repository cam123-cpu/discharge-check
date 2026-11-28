"""Automatic logoffs in the access log, and rotating DATA_KEY and AUDIT_KEY."""
import dataclasses
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from app import audit
from app.config import load_settings
from app.main import create_app
from scripts import rotate_data_key, verify_audit

from .conftest import csrf_of, login

DOC = b"Discharge summary. Final diagnosis: community-acquired pneumonia."


def _actions(app, action):
    with app.state.db.connect() as conn:
        return conn.execute("SELECT org_id, user_id, target FROM audit_log WHERE action = ? ORDER BY id", (action,)).fetchall()


def _verify(app, keys=None):
    with app.state.db.connect() as conn:
        return audit.verify(conn, keys or app.state.db.audit_key)


def _age_sessions(app, minutes=0, expire=False):
    past = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
    with sqlite3.connect(app.state.db.path) as conn:
        if minutes:
            conn.execute("UPDATE sessions SET last_seen = ?", (past,))
        if expire:
            conn.execute("UPDATE sessions SET expires_at = ?", ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),))


def _user_id(app, email):
    with app.state.db.connect() as conn:
        return conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()[0]


# ---------- automatic logoff ----------

def test_idle_logoff_is_logged_when_the_browser_comes_back(client, app):
    login(client, "rn@a.test")
    _age_sessions(app, minutes=31)
    r = client.get("/patients", follow_redirects=False)
    assert r.status_code in (302, 303) and "/login" in r.headers["location"]
    rows = _actions(app, "session_timeout")
    assert [(row[0], row[1]) for row in rows] == [(1, _user_id(app, "rn@a.test"))]
    assert _verify(app).ok


def test_session_time_limit_logoff_is_logged(client, app):
    login(client, "rn@a.test")
    _age_sessions(app, expire=True)
    client.get("/patients", follow_redirects=False)
    assert len(_actions(app, "session_expired")) == 1 and not _actions(app, "session_timeout")


def test_abandoned_sessions_are_logged_at_the_next_sign_in(app):
    """A browser that never returns still gets its logoff on record."""
    nurse, other = TestClient(app), TestClient(app)
    login(nurse, "rn@a.test")
    _age_sessions(app, minutes=45)
    login(other, "doc@b.test")
    rows = _actions(app, "session_timeout")
    assert [row[1] for row in rows] == [_user_id(app, "rn@a.test")]
    with app.state.db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1
    # Logged once only: the nurse's later visit finds no session to end.
    nurse.get("/patients", follow_redirects=False)
    assert len(_actions(app, "session_timeout")) == 1


def test_active_sessions_are_not_ended(client, app):
    login(client, "cm@a.test")
    _age_sessions(app, minutes=5)
    assert client.get("/patients").status_code == 200
    login(TestClient(app), "doc@b.test")
    assert client.get("/patients").status_code == 200
    assert not _actions(app, "session_timeout") and not _actions(app, "session_expired")


def test_logoff_events_are_listed_on_the_access_log(client, app):
    login(client, "rn@a.test")
    _age_sessions(app, minutes=31)
    client.get("/patients", follow_redirects=False)
    login(client, "cm@a.test")
    assert "Signed out after inactivity" in client.get("/audit?action=session_timeout").text


# ---------- DATA_KEY rotation ----------

def _upload_and_check(app):
    c = TestClient(app)
    login(c, "cm@a.test")
    c.post("/patients/1/documents", data={"csrf": csrf_of(c), "kind": "discharge_summary", "confirm": "yes"},
           files={"file": ("s.txt", DOC, "text/plain")})
    c.post("/patients/1/check", data={"csrf": csrf_of(c)})
    return c


def _reads_document(app):
    c = TestClient(app)
    login(c, "cm@a.test")
    return "community-acquired pneumonia" in c.get("/patients/1/documents/1").text and \
        c.get("/patients/1").status_code == 200


def test_data_key_rotation_end_to_end(settings):
    old_app = create_app(settings)
    _seed(old_app)
    _upload_and_check(old_app)
    old_key = settings.data_key
    rotated = dataclasses.replace(settings, data_key=Fernet.generate_key().decode(), data_key_previous=(old_key,))

    app = create_app(rotated)
    assert _reads_document(app)  # old rows still readable before re-encryption
    left = rotate_data_key.pending(app.state.db, app_cipher(rotated))
    assert left == {"documents": 1, "analyses": 1}

    assert rotate_data_key.rotate(rotated) == {"documents": 1, "analyses": 1}
    assert rotate_data_key.pending(app.state.db, app_cipher(rotated)) == {"documents": 0, "analyses": 0}
    assert rotate_data_key.rotate(rotated) == {"documents": 0, "analyses": 0}  # safe to run again
    assert [r[2] for r in _actions(app, "data_key_rotated")] == ["documents:1,analyses:1", "documents:0,analyses:0"]

    # Without AUDIT_KEY the access-log key is derived from DATA_KEY, so it rotated too, on the record.
    assert len(_actions(app, "audit_key_rotated")) == 1 and _verify(app).ok

    # Retire the old data key: records stay readable. Keep the old access-log key for its rows.
    old_audit_key = audit.export_key(audit.derive_key("", old_key))
    final = dataclasses.replace(rotated, data_key_previous=(), audit_key_previous=(old_audit_key,))
    app = create_app(final)
    assert _reads_document(app)
    assert _verify(app, final.audit_keyring()).ok
    assert not _verify(app, audit.KeyRing(final.audit_keyring().current)).ok


def test_old_rows_are_unreadable_without_the_previous_key(settings):
    old_app = create_app(settings)
    _seed(old_app)
    _upload_and_check(old_app)
    app = create_app(dataclasses.replace(settings, data_key=Fernet.generate_key().decode(), audit_key="fixed"))
    c = TestClient(app, raise_server_exceptions=False)
    login(c, "cm@a.test")
    assert c.get("/patients/1/documents/1").status_code == 500


def test_rotate_script_check_mode_exit_codes(settings, monkeypatch, capsys):
    old_app = create_app(settings)
    _seed(old_app)
    _upload_and_check(old_app)
    new_key = Fernet.generate_key().decode()
    for k, v in {"DATA_KEY": new_key, "DATA_KEY_PREVIOUS": settings.data_key, "SESSION_PEPPER": settings.session_pepper,
                 "DATABASE_PATH": str(settings.database_path)}.items():
        monkeypatch.setenv(k, v)
    for k in ("AUDIT_KEY", "AUDIT_KEY_PREVIOUS", "FORCE_HTTPS", "ALLOWED_HOSTS"):
        monkeypatch.delenv(k, raising=False)
    assert rotate_data_key.main(["--check"]) == 1
    assert rotate_data_key.main([]) == 0
    assert rotate_data_key.main(["--check"]) == 0
    assert "documents 0, analyses 0" in capsys.readouterr().out
    assert verify_audit.main([]) == 0


def test_data_key_previous_is_validated(monkeypatch, settings):
    monkeypatch.setenv("DATA_KEY", settings.data_key)
    monkeypatch.setenv("SESSION_PEPPER", settings.session_pepper)
    monkeypatch.delenv("FORCE_HTTPS", raising=False)
    monkeypatch.setenv("DATA_KEY_PREVIOUS", "not-a-key")
    with pytest.raises(RuntimeError, match="DATA_KEY_PREVIOUS"):
        load_settings()
    monkeypatch.setenv("DATA_KEY_PREVIOUS", settings.data_key)
    with pytest.raises(RuntimeError, match="must not also be listed"):
        load_settings()
    other = Fernet.generate_key().decode()
    monkeypatch.setenv("DATA_KEY_PREVIOUS", f" {other} , ")
    monkeypatch.setenv("AUDIT_KEY_PREVIOUS", "a,hex:00ff")
    s = load_settings()
    assert s.data_key_previous == (other,) and s.audit_key_previous == ("a", "hex:00ff")
    assert {b"a", b"\x00\xff"} <= set(s.audit_keyring().previous)


# ---------- AUDIT_KEY rotation ----------

def test_audit_key_rotation_keeps_the_chain_verifiable(settings):
    first = dataclasses.replace(settings, audit_key="key-one")
    app = create_app(first)
    _seed(app)
    _upload_and_check(app)
    second = dataclasses.replace(settings, audit_key="key-two", audit_key_previous=("key-one",))
    app = create_app(second)
    _upload_and_check(app)
    rows = _actions(app, "audit_key_rotated")
    one, two = audit.key_id(b"key-one"), audit.key_id(b"key-two")
    assert [r[2] for r in rows] == [f"key:{one}->{two}"]
    assert _verify(app).ok
    create_app(second)  # a plain restart records nothing new
    assert len(_actions(app, "audit_key_rotated")) == 1

    bad = _verify(app, audit.KeyRing(b"key-two"))
    assert not bad.ok and "not configured" in bad.reason


def test_a_retired_audit_key_cannot_come_back(settings):
    app = create_app(dataclasses.replace(settings, audit_key="key-one"))
    _seed(app)
    login(TestClient(app), "cm@a.test")
    create_app(dataclasses.replace(settings, audit_key="key-two", audit_key_previous=("key-one",)))
    with pytest.raises(RuntimeError, match="already retired"):
        create_app(dataclasses.replace(settings, audit_key="key-one", audit_key_previous=("key-two",)))


def test_forged_rows_with_an_old_key_are_detected(settings):
    """Someone holding a leaked old key and the database file still cannot add rows."""
    app = create_app(dataclasses.replace(settings, audit_key="key-one"))
    _seed(app)
    login(TestClient(app), "cm@a.test")
    ring = dataclasses.replace(settings, audit_key="key-two", audit_key_previous=("key-one",)).audit_keyring()
    app = create_app(dataclasses.replace(settings, audit_key="key-two", audit_key_previous=("key-one",)))
    login(TestClient(app), "cm@a.test")
    assert _verify(app, ring).ok

    def forge(key: bytes, action: str):
        with sqlite3.connect(app.state.db.path) as conn:
            conn.executescript("DROP TRIGGER IF EXISTS audit_log_no_update;")
            rid, prev = conn.execute("SELECT id, row_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            values = (rid + 1, "2026-11-28 08:00:00", 1, 1, action, "", "", prev, audit.key_id(key))
            conn.execute("INSERT INTO audit_log (id, at, org_id, user_id, action, target, ip, prev_hash, key_id, row_hash) "
                         "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (*values, audit.row_hash(key, *values)))
            return rid + 1

    forged = forge(b"key-one", audit.ROTATED)
    r = _verify(app, ring)
    assert not r.ok and r.broken_id == forged and "retired" in r.reason


def test_key_switch_needs_a_rotation_entry(settings):
    app = create_app(dataclasses.replace(settings, audit_key="key-one"))
    _seed(app)
    login(TestClient(app), "cm@a.test")
    ring = audit.KeyRing(b"key-two", (b"key-one",))
    with sqlite3.connect(app.state.db.path) as conn:
        rid, prev = conn.execute("SELECT id, row_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        values = (rid + 1, "2026-11-28 08:00:00", 1, 1, "login", "", "", prev, audit.key_id(b"key-two"))
        conn.execute("INSERT INTO audit_log (id, at, org_id, user_id, action, target, ip, prev_hash, key_id, row_hash) "
                     "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (*values, audit.row_hash(b"key-two", *values)))
    r = _verify(app, ring)
    assert not r.ok and r.broken_id == rid + 1 and "without a key rotation entry" in r.reason


def test_export_key_round_trips(settings, monkeypatch, capsys):
    monkeypatch.setenv("DATA_KEY", settings.data_key)
    monkeypatch.setenv("SESSION_PEPPER", settings.session_pepper)
    monkeypatch.delenv("AUDIT_KEY", raising=False)
    monkeypatch.delenv("FORCE_HTTPS", raising=False)
    assert verify_audit.main(["--export-key"]) == 0
    out = capsys.readouterr().out.strip()
    assert audit.parse_key(out) == audit.derive_key("", settings.data_key)


# ---------- helpers ----------

def app_cipher(settings):
    from app.security import Cipher
    return Cipher(settings.data_key, settings.data_key_previous)


def _seed(app):
    from app.security import hash_password
    from .conftest import PASSWORD
    with app.state.db.connect() as conn:
        if conn.execute("SELECT COUNT(*) FROM orgs").fetchone()[0]:
            return
        a = conn.execute("INSERT INTO orgs (name) VALUES ('Org A')").lastrowid
        b = conn.execute("INSERT INTO orgs (name) VALUES ('Org B')").lastrowid
        for email, org, role in [("cm@a.test", a, "compliance"), ("rn@a.test", a, "nurse"), ("doc@b.test", b, "physician")]:
            conn.execute("INSERT INTO users (org_id, email, display_name, role, password_hash) VALUES (?, ?, ?, ?, ?)",
                         (org, email, email.split("@")[0], role, hash_password(PASSWORD)))
        conn.execute("INSERT INTO patients (org_id, label, discharge_date, disposition) VALUES (?, 'A-1', '2026-11-14', 'Home')", (a,))
