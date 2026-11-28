"""Postgres row-level security: the database itself keeps each hospital's
rows apart, even for a query that forgets its org_id filter."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest
from sqlalchemy.exc import DBAPIError

from app.db import Database, rls_inert_reason, set_rls_context

ROOT = Path(__file__).resolve().parent.parent
PROBE_ROLE = "dc_rls_probe"
TABLES = ["orgs", "users", "patients", "documents", "analyses", "findings", "audit_log"]


def test_routes_always_open_org_scoped_transactions():
    """Only sign-in (no user yet) may open a system transaction in the routes;
    every other db.connect() call in app/main.py must pass an org_id."""
    tree = ast.parse((ROOT / "app" / "main.py").read_text(encoding="utf-8"))
    unscoped = []
    for fn in ast.walk(tree):
        # Routes are nested in create_app; check each route on its own.
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) or fn.name in ("create_app", "login"):
            continue
        for node in ast.walk(fn):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "connect"
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "db"
                    and not node.args and not node.keywords):
                unscoped.append(f"{fn.name}:{node.lineno}")
    assert unscoped == [], "routes must call db.connect(user['org_id'])"


@pytest.fixture
def pg(database_url):
    if not database_url:
        pytest.skip("row-level security exists on Postgres only (set TEST_DATABASE_URL)")
    db = Database(database_url)
    with db.connect() as conn:  # system: seed two hospitals
        ids = {}
        for name in ("A", "B"):
            org = conn.execute("INSERT INTO orgs (name) VALUES (?)", (f"Org {name}",)).lastrowid
            user = conn.execute("INSERT INTO users (org_id, email, display_name, role, password_hash) "
                                "VALUES (?, ?, 'u', 'nurse', 'x')", (org, f"u@{name.lower()}.test")).lastrowid
            pat = conn.execute("INSERT INTO patients (org_id, label) VALUES (?, ?)", (org, f"{name}-1")).lastrowid
            conn.execute("INSERT INTO documents (org_id, patient_id, kind, filename, body_enc) VALUES (?, ?, 'other', 'f', ?)",
                         (org, pat, b"\x01"))
            an = conn.execute("INSERT INTO analyses (org_id, patient_id, engine, result_enc, passed, failed, unclear) "
                              "VALUES (?, ?, 'rules', ?, 1, 0, 0)", (org, pat, b"\x02")).lastrowid
            conn.execute("INSERT INTO findings (org_id, analysis_id, patient_id, rule_id, status) VALUES (?, ?, ?, 'r', 'pass')",
                         (org, an, pat))
            conn.execute("INSERT INTO audit_log (org_id, user_id, action) VALUES (?, ?, 'login')", (org, user))
            ids[name] = {"org": org, "patient": pat}
        conn.execute("INSERT INTO audit_log (org_id, user_id, action) VALUES (NULL, NULL, 'login_blocked')")
    with db.engine.connect() as conn:
        if rls_inert_reason(conn):
            # A superuser (as in CI's Postgres image) skips every policy, so the
            # tests run their queries as an ordinary role, as a deployment should.
            conn.exec_driver_sql(f"DO $$ BEGIN CREATE ROLE {PROBE_ROLE} NOLOGIN; "
                                 "EXCEPTION WHEN duplicate_object THEN NULL; END $$")
            conn.exec_driver_sql(f"GRANT USAGE ON SCHEMA public TO {PROBE_ROLE}")
            conn.exec_driver_sql(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {PROBE_ROLE}")
            conn.exec_driver_sql(f"GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO {PROBE_ROLE}")
            conn.commit()
            db.probe_role = PROBE_ROLE
        else:
            db.probe_role = None
    db.ids = ids
    yield db
    db.dispose()


def _scoped(db, org_id):
    """db.connect(org_id), run as a role that row-level security applies to."""
    cm = db.connect(org_id)
    conn = cm.__enter__()
    if db.probe_role:
        conn.execute(f"SET LOCAL ROLE {db.probe_role}")
    return cm, conn


def _counts(conn) -> dict[str, int]:
    return {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in TABLES}


def test_hospital_sees_only_its_own_rows_even_without_a_filter(pg):
    a = pg.ids["A"]["org"]
    cm, conn = _scoped(pg, a)
    try:
        assert _counts(conn) == {t: 1 for t in TABLES}
        assert [r["label"] for r in conn.execute("SELECT label FROM patients").fetchall()] == ["A-1"]
        assert conn.execute("SELECT DISTINCT org_id FROM documents").fetchall() == [(a,)]
        # The org-scoped helper asked for the other hospital's patient by id.
        assert pg.patient(conn, pg.ids["B"]["org"], pg.ids["B"]["patient"]) is None
    finally:
        cm.__exit__(None, None, None)


def test_hospital_cannot_write_into_another(pg):
    a, b = pg.ids["A"]["org"], pg.ids["B"]["org"]
    for sql, params in [
        ("INSERT INTO patients (org_id, label) VALUES (?, 'sneaky')", (b,)),
        ("UPDATE patients SET org_id = ? WHERE id = ?", (b, pg.ids["A"]["patient"])),
        ("INSERT INTO audit_log (org_id, action) VALUES (?, 'x')", (b,)),
    ]:
        cm, conn = _scoped(pg, a)
        with pytest.raises(DBAPIError, match="row-level security"):
            try:
                conn.execute(sql, params)
            finally:
                cm.__exit__(*__import__("sys").exc_info())
    cm, conn = _scoped(pg, a)
    try:  # Updates and deletes aimed at the other hospital touch nothing.
        assert conn.execute("UPDATE patients SET label = 'x' WHERE id = ?", (pg.ids["B"]["patient"],)).rowcount == 0
        assert conn.execute("DELETE FROM documents WHERE org_id = ?", (b,)).rowcount == 0
    finally:
        cm.__exit__(None, None, None)
    with pg.connect() as conn:
        assert conn.execute("SELECT label FROM patients WHERE org_id = ?", (b,)).fetchone()["label"] == "B-1"
        assert conn.execute("SELECT COUNT(*) FROM documents WHERE org_id = ?", (b,)).fetchone()[0] == 1


def test_a_transaction_with_no_context_fails_closed(pg):
    with pg.engine.connect() as sa:
        if pg.probe_role:
            sa.exec_driver_sql(f"SET LOCAL ROLE {pg.probe_role}")
        for t in TABLES:
            assert sa.exec_driver_sql(f"SELECT COUNT(*) FROM {t}").scalar() == 0
        with pytest.raises(DBAPIError, match="row-level security"):
            sa.exec_driver_sql("INSERT INTO orgs (name) VALUES ('x')")


def test_system_context_sees_every_hospital(pg):
    with pg.connect() as conn:
        counts = _counts(conn)
    assert counts == {**{t: 2 for t in TABLES}, "audit_log": 3}


def test_context_does_not_outlive_its_transaction(pg):
    """Settings are transaction-local, so a pooled connection handed to the
    next request carries no organization over."""
    cm, conn = _scoped(pg, pg.ids["A"]["org"])
    cm.__exit__(None, None, None)
    with pg.engine.connect() as sa:
        if pg.probe_role:
            sa.exec_driver_sql(f"SET LOCAL ROLE {pg.probe_role}")
        assert sa.exec_driver_sql("SELECT COUNT(*) FROM patients").scalar() == 0
        assert sa.exec_driver_sql("SELECT current_setting('app.org_id', true)").scalar() in (None, "")


def test_policies_exist_at_head_and_go_away_on_downgrade(pg):
    from alembic import command

    def policies():
        with pg.engine.connect() as sa:
            return {r[0] for r in sa.exec_driver_sql(
                "SELECT tablename FROM pg_policies WHERE policyname = 'org_isolation'")}

    def forced():
        with pg.engine.connect() as sa:
            return {r[0] for r in sa.exec_driver_sql(
                "SELECT relname FROM pg_class WHERE relrowsecurity AND relforcerowsecurity AND relkind = 'r'")}

    assert policies() == set(TABLES) and forced() == set(TABLES)
    cfg = pg.alembic_config()
    with pg.engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.downgrade(cfg, "0003")
    assert policies() == set() and forced() == set()
    pg.migrate()
    assert policies() == set(TABLES)

