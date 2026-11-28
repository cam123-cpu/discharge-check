"""The data layer (app/db.py): placeholder rewriting, the `?`-style connection
wrapper, transactions, encryption at rest, org isolation and foreign keys.

Every test runs on SQLite, and on Postgres when TEST_DATABASE_URL is set."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event
from sqlalchemy.exc import IntegrityError

from app.db import Database, Record, qmark_to_format
from app.security import Cipher

from .conftest import csrf_of, login


@pytest.fixture
def db(database_url, tmp_path):
    database = Database(database_url or tmp_path / "db.sqlite")
    yield database
    database.dispose()


def _org(conn, name="Org"):
    return conn.execute("INSERT INTO orgs (name) VALUES (?)", (name,)).lastrowid


def _user(conn, org_id, email):
    return conn.execute(
        "INSERT INTO users (org_id, email, display_name, role, password_hash) VALUES (?, ?, ?, ?, ?)",
        (org_id, email, "x", "nurse", "h"),
    ).lastrowid


def _patient(conn, org_id, label="P-1"):
    return conn.execute("INSERT INTO patients (org_id, label) VALUES (?, ?)", (org_id, label)).lastrowid


def _analysis(conn, org_id, patient_id):
    return conn.execute(
        "INSERT INTO analyses (org_id, patient_id, engine, result_enc, passed, failed, unclear) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (org_id, patient_id, "rules", b"x", 1, 0, 0),
    ).lastrowid


# ---- qmark_to_format ----

@pytest.mark.parametrize("sql, expected", [
    ("SELECT * FROM t WHERE a = ? AND b = ?", "SELECT * FROM t WHERE a = %s AND b = %s"),
    ("SELECT '?' , ?", "SELECT '?' , %s"),
    ('SELECT "we?rd" FROM t WHERE x = ?', 'SELECT "we?rd" FROM t WHERE x = %s'),
    ("SELECT 'it''s ?' , ?", "SELECT 'it''s ?' , %s"),
    ('SELECT "a""?b" , ?', 'SELECT "a""?b" , %s'),
    ("SELECT ? -- why?\nFROM t WHERE a = ?", "SELECT %s -- why?\nFROM t WHERE a = %s"),
    ("SELECT ? -- trailing comment?", "SELECT %s -- trailing comment?"),
    ("SELECT /* is it? */ ?", "SELECT /* is it? */ %s"),
    ("SELECT /* multi\nline ? */ ? /* again? */", "SELECT /* multi\nline ? */ %s /* again? */"),
    ("SELECT ? /* unterminated ?", "SELECT %s /* unterminated ?"),
    ("SELECT 5 % 2, ?", "SELECT 5 %% 2, %s"),
    ("SELECT '100%' WHERE a LIKE ?", "SELECT '100%%' WHERE a LIKE %s"),
    ('SELECT "p%" FROM t', 'SELECT "p%%" FROM t'),
    ("SELECT 1 -- 50% done\n", "SELECT 1 -- 50%% done\n"),
    ("SELECT 1 /* 50% */", "SELECT 1 /* 50%% */"),
    ("SELECT '%s' , ?", "SELECT '%%s' , %s"),
    ("SELECT 'unterminated ?", "SELECT 'unterminated ?"),
    ("SELECT a - b, ?", "SELECT a - b, %s"),
    ("SELECT a / b, ?", "SELECT a / b, %s"),
    ("", ""),
])
def test_qmark_to_format(sql, expected):
    assert qmark_to_format(sql) == expected


def test_literal_percent_and_question_mark_round_trip(db):
    with db.connect() as conn:
        row = conn.execute("SELECT '100%' AS pct, '?' AS q, ? AS p -- really?", (7,)).fetchone()
        assert (row["pct"], row["q"], row["p"]) == ("100%", "?", 7)
        row = conn.execute("SELECT 'it''s 5%' AS s").fetchone()
        assert row["s"] == "it's 5%"


# ---- DBConnection.execute ----

def test_lastrowid_on_insert_for_tables_with_id(db):
    with db.connect() as conn:
        org = _org(conn)
        org2 = _org(conn, "Org 2")
        assert isinstance(org, int) and org2 == org + 1
        user = _user(conn, org, "a@x.test")
        patient = _patient(conn, org)
        doc = conn.execute(
            "INSERT INTO documents (org_id, patient_id, kind, filename, body_enc) VALUES (?, ?, ?, ?, ?);",
            (org, patient, "other", "a.txt", b"enc"),
        ).lastrowid
        analysis = _analysis(conn, org, patient)
        finding = conn.execute(
            "INSERT INTO findings (org_id, analysis_id, patient_id, rule_id, status) VALUES (?, ?, ?, ?, ?)",
            (org, analysis, patient, "R1", "pass"),
        ).lastrowid
        attempt = conn.execute("INSERT INTO login_attempts (key) VALUES (?)", ("k",)).lastrowid
        audit = conn.execute("insert into audit_log (action) values (?)", ("x",)).lastrowid
        for table, rid in [("users", user), ("patients", patient), ("documents", doc), ("analyses", analysis),
                           ("findings", finding), ("login_attempts", attempt), ("audit_log", audit)]:
            assert isinstance(rid, int), table
            assert conn.execute(f"SELECT id FROM {table} WHERE id = ?", (rid,)).fetchone()[0] == rid


def test_insert_with_own_returning_keeps_rows(db):
    with db.connect() as conn:
        res = conn.execute("INSERT INTO orgs (name) VALUES (?) RETURNING id, name", ("R",))
        row = res.fetchone()
        assert row["name"] == "R" and isinstance(row["id"], int)


def test_no_returning_added_for_tables_without_id(db):
    seen = []

    @event.listens_for(db.engine, "before_cursor_execute")
    def _capture(conn, cursor, statement, parameters, context, executemany):
        seen.append(statement)

    with db.connect() as conn:
        org = _org(conn)
        user = _user(conn, org, "s@x.test")
        seen.clear()
        res = conn.execute("INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)",
                           ("tok", user, "c", "2099-01-01"))
        assert res.rowcount == 1
        if db.url.get_backend_name() == "postgresql":
            assert res.lastrowid is None
        assert len(seen) == 1 and "RETURNING" not in seen[0].upper()
        seen.clear()
        _org(conn, "Other")
        if db.url.get_backend_name() == "postgresql":
            assert seen[0].rstrip().endswith("RETURNING id")
        assert conn.execute("SELECT last_seen FROM sessions WHERE token_hash = ?", ("tok",)).fetchone()[0] == ""
    event.remove(db.engine, "before_cursor_execute", _capture)


def test_rowcount_on_update_and_delete(db):
    with db.connect() as conn:
        org = _org(conn)
        for label in ("A", "B", "C"):
            _patient(conn, org, label)
        assert conn.execute("UPDATE patients SET unit = ? WHERE org_id = ?", ("ICU", org)).rowcount == 3
        assert conn.execute("UPDATE patients SET unit = ? WHERE label = ?", ("W", "A")).rowcount == 1
        assert conn.execute("UPDATE patients SET unit = ? WHERE label = ?", ("W", "none")).rowcount == 0
        assert conn.execute("DELETE FROM patients WHERE label IN (?, ?)", ("A", "B")).rowcount == 2
        assert conn.execute("SELECT COUNT(*) FROM patients").fetchone()[0] == 1


def test_executemany(db):
    with db.connect() as conn:
        res = conn.executemany("INSERT INTO login_attempts (key) VALUES (?)", [("a",), ("b",), ("a",)])
        assert res.rowcount == 3
        assert conn.executemany("INSERT INTO login_attempts (key) VALUES (?)", []).rowcount == 0
        rows = conn.execute("SELECT key, COUNT(*) AS n FROM login_attempts GROUP BY key ORDER BY key").fetchall()
        assert [(r["key"], r["n"]) for r in rows] == [("a", 2), ("b", 1)]
        assert conn.executemany("DELETE FROM login_attempts WHERE key = ?", [("a",), ("zz",)]).rowcount == 2
        # Generators work too, as with sqlite3.
        conn.executemany("INSERT INTO login_attempts (key) VALUES (?)", ((k,) for k in "xyz"))
        assert conn.execute("SELECT COUNT(*) FROM login_attempts").fetchone()[0] == 4


def test_record_access(db):
    with db.connect() as conn:
        org = _org(conn, "Acme")
        res = conn.execute("SELECT id, name FROM orgs WHERE id = ?", (org,))
        row = res.fetchone()
        assert isinstance(row, Record)
        assert row["name"] == "Acme" and row[1] == "Acme" and row.name == "Acme" and row[-1] == "Acme"
        assert row["id"] == row[0] == row.id == org
        assert dict(row) == {"id": org, "name": "Acme"}
        assert row.keys() == ["id", "name"]
        assert "name" in row and "nope" not in row
        assert row.get("nope", 5) == 5 and row.get("name") == "Acme"
        assert len(row) == 2 and tuple(row) == (org, "Acme") and row == (org, "Acme")
        with pytest.raises(KeyError):
            row["nope"]
        with pytest.raises(AttributeError):
            row.nope
        assert res.fetchone() is None
        assert res.fetchone() is None
        assert conn.execute("SELECT id FROM orgs WHERE id = -1").fetchone() is None
        assert conn.execute("SELECT id FROM orgs WHERE id = -1").fetchall() == []
        # Writes return no rows.
        assert conn.execute("UPDATE orgs SET name = ? WHERE id = ?", ("B", org)).fetchone() is None


def test_blob_columns_come_back_as_bytes(db):
    with db.connect() as conn:
        org = _org(conn)
        pid = _patient(conn, org)
        doc = conn.execute("INSERT INTO documents (org_id, patient_id, kind, filename, body_enc) VALUES (?, ?, ?, ?, ?)",
                           (org, pid, "other", "a.txt", b"\x00\xffbin")).lastrowid
        assert conn.execute("SELECT body_enc FROM documents WHERE id = ?", (doc,)).fetchone()[0] == b"\x00\xffbin"
        assert db.document(conn, org, pid, doc)["body_enc"] == b"\x00\xffbin"


# ---- transactions ----

def test_exception_rolls_back_whole_transaction(db):
    with db.connect() as conn:
        org = _org(conn)
    with pytest.raises(RuntimeError):
        with db.connect() as conn:
            _patient(conn, org, "ghost")
            conn.execute("UPDATE orgs SET name = ? WHERE id = ?", ("renamed", org))
            raise RuntimeError("boom")
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM patients").fetchone()[0] == 0
        assert conn.execute("SELECT name FROM orgs WHERE id = ?", (org,)).fetchone()[0] == "Org"


def test_failed_statement_rolls_back_earlier_writes(db):
    with pytest.raises(IntegrityError):
        with db.connect() as conn:
            _org(conn, "kept?")
            conn.execute("INSERT INTO orgs (name) VALUES (NULL)")
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM orgs").fetchone()[0] == 0


def test_commit_on_clean_exit_is_visible_to_new_connection(db):
    with db.connect() as conn:
        _org(conn, "Visible")
    with db.connect() as conn:
        assert conn.execute("SELECT name FROM orgs").fetchone()["name"] == "Visible"


# ---- encryption at rest ----

def test_uploaded_document_is_encrypted_at_rest(app, client):
    login(client, "cm@a.test")
    token = csrf_of(client)
    secret = "Synthetic note: patient SYN-ENC reports dyspnea on exertion."
    with app.state.db.connect() as conn:
        pid = conn.execute("SELECT id FROM patients WHERE label = 'A-1'").fetchone()[0]
    r = client.post(f"/patients/{pid}/documents", data={"csrf": token, "kind": "other", "confirm": "yes"},
                    files={"file": ("note.txt", secret.encode(), "text/plain")}, follow_redirects=True)
    assert "Added note.txt" in r.text

    # The raw driver value, below the Record wrapper (Postgres returns bytea).
    with app.state.db.engine.connect() as sa:
        doc_id, blob = sa.exec_driver_sql("SELECT id, body_enc FROM documents WHERE patient_id = %s" if
                                          sa.dialect.name == "postgresql" else
                                          "SELECT id, body_enc FROM documents WHERE patient_id = ?", (pid,)).one()
    blob = bytes(blob) if isinstance(blob, memoryview) else blob
    assert isinstance(blob, bytes)
    assert secret.encode() not in blob and b"dyspnea" not in blob and b"SYN-ENC" not in blob
    assert Cipher(app.state.settings.data_key).decrypt(blob) == secret

    # And the app shows it decrypted.
    page = client.get(f"/patients/{pid}/documents/{doc_id}")
    assert page.status_code == 200 and "dyspnea on exertion" in page.text


def test_wrong_key_cannot_decrypt(app):
    from cryptography.fernet import Fernet
    cipher = Cipher(app.state.settings.data_key)
    with app.state.db.connect() as conn:
        org, pid = conn.execute("SELECT org_id, id FROM patients WHERE label = 'A-1'").fetchone()
        doc = conn.execute("INSERT INTO documents (org_id, patient_id, kind, filename, body_enc) VALUES (?, ?, ?, ?, ?)",
                           (org, pid, "other", "a.txt", cipher.encrypt("hello"))).lastrowid
        blob = conn.execute("SELECT body_enc FROM documents WHERE id = ?", (doc,)).fetchone()[0]
    assert cipher.decrypt(blob) == "hello"
    with pytest.raises(RuntimeError):
        Cipher(Fernet.generate_key().decode()).decrypt(blob)


# ---- org isolation ----

def test_org_scoped_helpers_hide_other_orgs(db):
    with db.connect() as conn:
        a, b = _org(conn, "A"), _org(conn, "B")
        pa, pb = _patient(conn, a, "A-1"), _patient(conn, b, "B-1")
        doc_b = conn.execute("INSERT INTO documents (org_id, patient_id, kind, filename, body_enc) VALUES (?, ?, ?, ?, ?)",
                             (b, pb, "other", "b.txt", b"enc")).lastrowid
        _analysis(conn, b, pb)
    with db.connect() as conn:
        assert db.patient(conn, a, pa)["label"] == "A-1"
        assert db.patient(conn, a, pb) is None
        assert db.patient(conn, b, pa) is None
        assert [r["label"] for r in db.patients(conn, a)] == ["A-1"]
        assert [r["label"] for r in db.patients(conn, b)] == ["B-1"]
        assert db.documents(conn, a, pb) == []
        assert db.document(conn, a, pb, doc_b) is None
        assert db.document(conn, b, pb, doc_b)["filename"] == "b.txt"
        assert db.latest_analysis(conn, a, pb) is None
        assert db.latest_analysis(conn, b, pb) is not None
    for helper in (db.patient, db.documents, db.latest_analysis):
        with db.connect() as conn, pytest.raises(TypeError):
            helper(conn, pb)  # org_id is required


def test_patients_list_counts_live_documents_and_latest_analysis(db):
    with db.connect() as conn:
        org = _org(conn)
        pid = _patient(conn, org)
        for name in ("a.txt", "b.txt"):
            conn.execute("INSERT INTO documents (org_id, patient_id, kind, filename, body_enc) VALUES (?, ?, ?, ?, ?)",
                         (org, pid, "other", name, b"e"))
        conn.execute("UPDATE documents SET deleted_at = ? WHERE filename = ?", ("2026-01-01", "b.txt"))
        _analysis(conn, org, pid)
        conn.execute("INSERT INTO analyses (org_id, patient_id, engine, result_enc, passed, failed, unclear) VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (org, pid, "rules", b"x", 5, 2, 1))
        row = db.patients(conn, org)[0]
        assert (row["doc_count"], row["last_passed"], row["last_failed"], row["last_unclear"]) == (1, 5, 2, 1)
        assert [d["filename"] for d in db.documents(conn, org, pid)] == ["a.txt"]


def test_audit_helper_writes_row(db):
    with db.connect() as conn:
        org = _org(conn)
        db.audit(conn, org, None, "test_action", "patient:1", "127.0.0.1")
        row = conn.execute("SELECT org_id, user_id, action, target, ip, at FROM audit_log").fetchone()
        assert (row["org_id"], row["user_id"], row["action"], row["target"], row["ip"]) == (org, None, "test_action", "patient:1", "127.0.0.1")
        assert len(row["at"]) == 19  # 'YYYY-MM-DD HH:MM:SS' on both databases


# ---- foreign keys ----

def test_foreign_keys_are_enforced(db):
    with pytest.raises(IntegrityError):
        with db.connect() as conn:
            conn.execute("INSERT INTO patients (org_id, label) VALUES (?, ?)", (999_999, "orphan"))
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM patients").fetchone()[0] == 0


def test_check_constraints_are_enforced(db):
    with db.connect() as conn:
        org = _org(conn)
    with pytest.raises(IntegrityError):
        with db.connect() as conn:
            conn.execute("INSERT INTO users (org_id, email, display_name, role, password_hash) VALUES (?, ?, ?, ?, ?)",
                         (org, "x@x.test", "x", "superuser", "h"))


def test_delete_analysis_cascades_to_findings(db):
    with db.connect() as conn:
        org = _org(conn)
        pid = _patient(conn, org)
        keep, gone = _analysis(conn, org, pid), _analysis(conn, org, pid)
        for aid in (keep, gone):
            conn.executemany("INSERT INTO findings (org_id, analysis_id, patient_id, rule_id, status) VALUES (?, ?, ?, ?, ?)",
                             [(org, aid, pid, "R1", "pass"), (org, aid, pid, "R2", "fail")])
    with db.connect() as conn:
        conn.execute("DELETE FROM analyses WHERE id = ?", (gone,))
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM findings WHERE analysis_id = ?", (gone,)).fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM findings WHERE analysis_id = ?", (keep,)).fetchone()[0] == 2


def test_delete_patient_cascades(db):
    with db.connect() as conn:
        org = _org(conn)
        pid = _patient(conn, org)
        aid = _analysis(conn, org, pid)
        conn.execute("INSERT INTO findings (org_id, analysis_id, patient_id, rule_id, status) VALUES (?, ?, ?, ?, ?)",
                     (org, aid, pid, "R1", "pass"))
        conn.execute("INSERT INTO documents (org_id, patient_id, kind, filename, body_enc) VALUES (?, ?, ?, ?, ?)",
                     (org, pid, "other", "a.txt", b"e"))
    with db.connect() as conn:
        conn.execute("DELETE FROM patients WHERE id = ?", (pid,))
        for table in ("documents", "analyses", "findings"):
            assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0, table


def test_delete_user_cascades_to_sessions(db):
    with db.connect() as conn:
        org = _org(conn)
        uid = _user(conn, org, "c@x.test")
        conn.execute("INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)",
                     ("t", uid, "c", "2099-01-01"))
    with db.connect() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (uid,))
        assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0


def test_app_db_works_through_test_client(app):
    # The conftest app is seeded through these same code paths.
    client = TestClient(app)
    assert login(client, "doc@b.test").status_code == 303
    assert "B-1" in client.get("/patients").text and "A-1" not in client.get("/patients").text


def test_concurrent_sqlite_writers_do_not_fail_with_locked(tmp_path):
    """A transaction that reads, then writes after another connection wrote,
    must not fail at once with "database is locked" (a deferred BEGIN would:
    its read snapshot goes stale). With BEGIN IMMEDIATE the second writer waits
    on busy_timeout instead. Every wait here has a timeout, so it cannot hang."""
    import threading

    db = Database(tmp_path / "threads.db")
    a_read = threading.Event()
    b_done = threading.Event()
    errors: list[BaseException] = []
    order: list[str] = []

    def thread_a():
        try:
            with db.connect() as conn:
                conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()
                a_read.set()
                b_done.wait(timeout=1.0)  # B blocks on A's lock, so this times out
                conn.execute("INSERT INTO audit_log (action) VALUES (?)", ("a",))
            order.append("a")
        except BaseException as exc:  # noqa: BLE001 - reported below
            errors.append(exc)

    def thread_b():
        try:
            assert a_read.wait(timeout=5)
            with db.connect() as conn:
                conn.execute("INSERT INTO audit_log (action) VALUES (?)", ("b",))
            order.append("b")
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)
        finally:
            b_done.set()

    ta, tb = threading.Thread(target=thread_a), threading.Thread(target=thread_b)
    try:
        ta.start()
        tb.start()
        ta.join(timeout=20)
        tb.join(timeout=20)
        assert not ta.is_alive() and not tb.is_alive()
        assert errors == []
        assert sorted(order) == ["a", "b"]
        with db.connect() as conn:
            assert sorted(r[0] for r in conn.execute("SELECT action FROM audit_log").fetchall()) == ["a", "b"]
    finally:
        db.dispose()


def test_lastrowid_survives_trailing_comment_and_skipped_conflict(settings):
    from app.db import Database
    db = Database(settings.database)
    with db.connect() as conn:
        oid = conn.execute("INSERT INTO orgs (name) VALUES (?) -- trailing note", ("x",)).lastrowid
        assert isinstance(oid, int)
        if conn.dialect == "postgresql":
            again = conn.execute("INSERT INTO orgs (id, name) VALUES (?, 'y') ON CONFLICT DO NOTHING", (oid,))
            assert again.lastrowid is None
    db.dispose()
