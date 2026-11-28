import dataclasses
import json
import sqlite3
import threading

import pytest
from fastapi.testclient import TestClient

from app import audit
from app.db import Database
from app.main import create_app
from scripts import verify_audit

from .conftest import csrf_of, login


def _key(settings):
    return audit.derive_key(settings.audit_key, settings.data_key)


def _verify(app):
    with app.state.db.connect() as conn:
        return audit.verify(conn, app.state.db.audit_key)


def _use_app(client, app):
    login(client, "rn@a.test", "wrong password")
    login(client, "nobody@a.test")
    login(client, "cm@a.test")
    pid = 1
    client.get("/patients")
    client.get(f"/patients/{pid}")
    client.post(f"/patients/{pid}/documents", data={"csrf": csrf_of(client), "kind": "discharge_summary", "confirm": "yes"},
                files={"file": ("s.txt", b"Discharge summary. Final diagnosis: pneumonia.", "text/plain")})
    client.get(f"/patients/{pid}/documents/1")
    client.post(f"/patients/{pid}/check", data={"csrf": csrf_of(client)})
    client.get("/compliance")
    client.get("/api/compliance/summary")
    client.get("/audit")


def _raw(app):
    """A connection with the triggers dropped, as an attacker with file access would."""
    conn = sqlite3.connect(app.state.db.path)
    conn.executescript("DROP TRIGGER audit_log_no_update; DROP TRIGGER audit_log_no_delete;")
    return conn


def test_chain_is_valid_after_normal_use_and_every_access_is_logged(client, app):
    _use_app(client, app)
    r = _verify(app)
    assert r.ok and r.checked > 10 and not r.partial
    with app.state.db.connect() as conn:
        actions = {row[0] for row in conn.execute("SELECT action FROM audit_log")}
        first = conn.execute("SELECT prev_hash FROM audit_log ORDER BY id LIMIT 1").fetchone()[0]
        assert audit.head(conn) == {"id": r.head_id, "at": audit.head(conn)["at"], "row_hash": r.head_hash}
    assert first == audit.GENESIS
    assert {"login", "login_failed", "patient_list", "patient_view", "document_upload", "document_view",
            "check_run", "compliance_view", "compliance_api", "audit_view"} <= actions
    assert "Tamper check passed" in client.get("/audit").text


def test_changed_row_is_detected_at_its_id(client, app):
    _use_app(client, app)
    with _raw(app) as conn:
        conn.execute("UPDATE audit_log SET target = 'patient:999' WHERE id = 5")
    r = _verify(app)
    assert not r.ok and r.broken_id == 5 and "hash does not match" in r.reason and r.checked == 4
    page = client.get("/audit").text
    assert "Tamper check failed at event 5" in page


def test_rehashed_row_breaks_the_next_link(client, app):
    """Recomputing a row's hash without the key is impossible; with a wrong key the row itself fails."""
    _use_app(client, app)
    with _raw(app) as conn:
        r = conn.execute("SELECT id, at, org_id, user_id, action, target, ip, prev_hash, key_id FROM audit_log WHERE id = 3").fetchone()
        forged = audit.row_hash(b"guess", *r[:5], "edited", *r[6:])
        conn.execute("UPDATE audit_log SET target = 'edited', row_hash = ? WHERE id = 3", (forged,))
    res = _verify(app)
    assert not res.ok and res.broken_id == 3


def test_deleted_middle_row_is_detected(client, app):
    _use_app(client, app)
    with _raw(app) as conn:
        conn.execute("DELETE FROM audit_log WHERE id = 4")
    r = _verify(app)
    assert not r.ok and r.broken_id == 5 and "rows 4 to 4 are missing" in r.reason


def test_deleted_first_row_is_detected(client, app):
    _use_app(client, app)
    with _raw(app) as conn:
        conn.execute("DELETE FROM audit_log WHERE id = 1")
    r = _verify(app)
    assert not r.ok and r.broken_id == 2 and "genesis" in r.reason


def test_triggers_block_update_delete_and_unsealed_insert(client, app):
    _use_app(client, app)
    with app.state.db.connect() as conn:
        for sql in ("UPDATE audit_log SET ip = '' WHERE id = 1", "DELETE FROM audit_log WHERE id = 1",
                    "DELETE FROM audit_log", "INSERT INTO audit_log (action) VALUES ('login')"):
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(sql)
    assert _verify(app).ok


def test_partial_verification_checks_only_the_newest_rows(client, app):
    _use_app(client, app)
    with _raw(app) as conn:
        conn.execute("UPDATE audit_log SET ip = 'x' WHERE id = 1")
        total = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    with app.state.db.connect() as conn:
        r = audit.verify(conn, app.state.db.audit_key, last=3)
    assert r.ok and r.partial and r.checked == 3 and r.head_id == total


LEGACY_AUDIT = """CREATE TABLE audit_log (id INTEGER PRIMARY KEY, org_id INTEGER, user_id INTEGER, action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT '', at TEXT NOT NULL DEFAULT (datetime('now')));"""


def test_legacy_rows_are_sealed_once_then_locked(settings, caplog):
    with sqlite3.connect(settings.database_path) as conn:
        conn.executescript(LEGACY_AUDIT)
        for i in range(5):
            conn.execute("INSERT INTO audit_log (org_id, user_id, action, target, ip) VALUES (1, 2, 'patient_view', ?, '1.2.3.4')", (f"patient:{i}",))
    with caplog.at_level("WARNING"):
        app = create_app(settings)
    assert "Sealed 5 earlier access-log rows" in caplog.text
    r = _verify(app)
    assert r.ok and r.checked == 5
    with app.state.db.connect() as conn:
        app.state.db.audit(conn, 1, 2, "login")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE audit_log SET target = '' WHERE id = 1")
    caplog.clear()
    with caplog.at_level("WARNING"):
        app = create_app(settings)  # a restart seals nothing new
    assert "Sealed" not in caplog.text
    assert _verify(app).ok and _verify(app).checked == 6


def test_database_without_key_cannot_write_the_log(settings):
    create_app(settings)
    db = Database(settings.database_path)
    with db.connect() as conn, pytest.raises(RuntimeError):
        db.audit(conn, 1, 1, "login")


def test_concurrent_appends_keep_one_chain(settings):
    create_app(settings)
    key = _key(settings)
    threads_n, per = 8, 40
    errors = []

    def work(n):
        db = Database(settings.database_path, key)  # own connections, like separate workers
        try:
            for i in range(per):
                with db.connect() as conn:
                    if i % 2:
                        conn.execute("INSERT INTO login_attempts (key) VALUES (?)", (f"t{n}",))  # other writes in the same transaction
                    db.audit(conn, 1, n, "patient_view", f"patient:{i}", "127.0.0.1")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    ts = [threading.Thread(target=work, args=(n,)) for n in range(threads_n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert not errors
    db = Database(settings.database_path, key)
    with db.connect() as conn:
        r = audit.verify(conn, key)
        ids = [row[0] for row in conn.execute("SELECT id FROM audit_log ORDER BY id")]
    assert r.ok and r.checked == threads_n * per
    assert ids == list(range(1, threads_n * per + 1))


def test_audit_key_setting_changes_the_chain(settings):
    a = audit.derive_key("", settings.data_key)
    assert a != audit.derive_key("other", settings.data_key) and len(a) == 32
    app = create_app(dataclasses.replace(settings, audit_key="separate-secret"))
    with app.state.db.connect() as conn:
        app.state.db.audit(conn, 1, 1, "login")
        assert audit.verify(conn, b"separate-secret").ok
        assert not audit.verify(conn, a).ok


def test_canonical_encoding_is_unambiguous():
    assert audit.canonical(1, "t", 1, 2, "a", "b,c", "", "p", "k") != audit.canonical(1, "t", 1, 2, "a,b", "c", "", "p", "k")
    assert audit.canonical(1, "t", None, 2, "a", "", "", "p", "k") != audit.canonical(1, "t", "None", 2, "a", "", "", "p", "k")


@pytest.fixture
def script_env(settings, monkeypatch):
    monkeypatch.setenv("DATA_KEY", settings.data_key)
    monkeypatch.setenv("SESSION_PEPPER", settings.session_pepper)
    monkeypatch.setenv("DATABASE_PATH", str(settings.database_path))
    monkeypatch.delenv("AUDIT_KEY", raising=False)
    monkeypatch.delenv("FORCE_HTTPS", raising=False)
    monkeypatch.delenv("ALLOWED_HOSTS", raising=False)


def test_verify_script_exit_codes_and_head(client, app, script_env, capsys):
    _use_app(client, app)
    assert verify_audit.main([]) == 0
    assert capsys.readouterr().out.startswith("OK:")
    assert verify_audit.main(["--head"]) == 0
    h = json.loads(capsys.readouterr().out)
    assert h["id"] == _verify(app).head_id and len(h["row_hash"]) == 64
    with _raw(app) as conn:
        conn.execute("UPDATE audit_log SET action = 'logout' WHERE id = 2")
    assert verify_audit.main([]) == 1
    assert "BROKEN at event 2" in capsys.readouterr().out


# ---------- health check ----------

def test_healthz_needs_no_session_and_writes_nothing(client, app):
    with app.state.db.connect() as conn:
        before = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json() == {"status": "ok"}
    assert r.headers["x-frame-options"] == "DENY" and r.headers["cache-control"] == "no-store"
    assert client.head("/healthz").status_code == 200
    assert client.post("/healthz").status_code in (404, 405)
    assert client.get("/healthz/x").status_code == 404
    with app.state.db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == before


def test_healthz_answers_load_balancer_probe_by_ip_over_http(settings):
    app = create_app(dataclasses.replace(settings, force_https=True, allowed_hosts=("dc.example.test",)))
    probe = TestClient(app, base_url="http://10.0.1.5:8000")
    r = probe.get("/healthz", follow_redirects=False)
    assert r.status_code == 200 and r.json() == {"status": "ok"}
    assert "strict-transport-security" in r.headers
    assert probe.get("/login", follow_redirects=False).status_code == 400  # unknown host still refused
    assert probe.get("/healthz/", follow_redirects=False).status_code == 400
    assert probe.post("/healthz", follow_redirects=False).status_code == 400
    ok_host = TestClient(app, base_url="http://dc.example.test")
    assert ok_host.get("/login", follow_redirects=False).status_code == 308  # and HTTP still redirects
