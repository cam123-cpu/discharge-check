"""First-run setup must work however .env was made, including by Windows
PowerShell 5.1, whose `>>` writes UTF-16."""
from cryptography.fernet import Fernet

from app.config import parse_env, read_env_text
from scripts.setup import ensure_env

KEY = Fernet.generate_key().decode()

EXAMPLE = "# comment\nDATA_KEY=\nSESSION_PEPPER=\nANTHROPIC_API_KEY=\nFORCE_HTTPS=0\n"


def _example(tmp_path):
    ex = tmp_path / ".env.example"
    ex.write_text(EXAMPLE, encoding="utf-8")
    return ex


def test_creates_env_with_keys(tmp_path):
    env = tmp_path / ".env"
    made = ensure_env(env, _example(tmp_path))
    vals = parse_env(read_env_text(env))
    assert set(made) == {"DATA_KEY", "SESSION_PEPPER"}
    assert len(vals["DATA_KEY"]) == 44 and len(vals["SESSION_PEPPER"]) > 40
    assert env.read_text().count("DATA_KEY=") == 1


def test_appended_values_win_over_empty_placeholders(tmp_path):
    env = tmp_path / ".env"
    env.write_text(EXAMPLE + f"DATA_KEY={KEY}\nSESSION_PEPPER=xyz\n", encoding="utf-8")
    assert parse_env(read_env_text(env))["DATA_KEY"] == KEY
    assert ensure_env(env, _example(tmp_path)) == []
    text = env.read_text()
    assert f"DATA_KEY={KEY}" in text and "DATA_KEY=\n" not in text


def test_powershell_utf16_file_is_read_and_repaired(tmp_path):
    env = tmp_path / ".env"
    env.write_bytes(EXAMPLE.encode("utf-8") + f"DATA_KEY={KEY}\r\n".encode("utf-16"))  # what `>>` in PS 5.1 produces
    assert ensure_env(env, _example(tmp_path)) == ["SESSION_PEPPER"]
    vals = parse_env(env.read_text(encoding="utf-8"))
    assert vals["DATA_KEY"] == KEY and vals["SESSION_PEPPER"]
    whole_utf16 = tmp_path / ".env2"
    whole_utf16.write_text("DATA_KEY=abc\nSESSION_PEPPER=xyz\n", encoding="utf-16")
    assert parse_env(read_env_text(whole_utf16)) == {"DATA_KEY": "abc", "SESSION_PEPPER": "xyz"}


def test_existing_keys_are_never_replaced(tmp_path):
    env = tmp_path / ".env"
    ensure_env(env, _example(tmp_path))
    first = env.read_text()
    assert ensure_env(env, _example(tmp_path)) == []
    assert env.read_text() == first


def test_invalid_key_is_replaced_only_while_the_database_is_empty(tmp_path):
    import sqlite3
    import pytest
    env = tmp_path / ".env"
    env.write_text("DATA_KEY=not-a-key\nSESSION_PEPPER=xyz\n", encoding="utf-8")
    assert ensure_env(env, _example(tmp_path)) == ["DATA_KEY"]
    assert parse_env(env.read_text())["DATA_KEY"] != "not-a-key"

    env.write_text("DATA_KEY=not-a-key\nSESSION_PEPPER=xyz\n", encoding="utf-8")
    (tmp_path / "data").mkdir()
    with sqlite3.connect(tmp_path / "data" / "app.db") as conn:
        conn.execute("CREATE TABLE documents (id INTEGER)")
        conn.execute("INSERT INTO documents VALUES (1)")
    with pytest.raises(SystemExit):
        ensure_env(env, _example(tmp_path))  # records exist: never swap the key under them


def _sqlite_with_documents(path, rows: int):
    import sqlite3
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE documents (id INTEGER)")
        conn.executemany("INSERT INTO documents VALUES (?)", [(i,) for i in range(rows)])


def test_db_has_data_on_sqlite_path(tmp_path):
    from scripts.setup import db_has_data
    assert db_has_data(tmp_path, {}) is False  # no file yet
    assert not (tmp_path / "data" / "app.db").exists()  # and checking did not create one
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "app.db").touch()
    assert db_has_data(tmp_path, {}) is False  # file but no documents table: nothing encrypted
    (tmp_path / "data" / "app.db").write_bytes(b"not a database at all" * 100)
    assert db_has_data(tmp_path, {}) is True  # unreadable: assume it matters


def test_db_has_data_follows_database_url(tmp_path):
    from scripts.setup import db_has_data
    url_db = tmp_path / "other.db"
    env = {"DATABASE_URL": f"sqlite:///{url_db}", "DATABASE_PATH": str(tmp_path / "ignored.db")}
    _sqlite_with_documents(tmp_path / "ignored.db", 1)
    assert db_has_data(tmp_path, env) is False  # DATABASE_URL wins; its file does not exist
    _sqlite_with_documents(url_db, 0)
    assert db_has_data(tmp_path, env) is False
    _sqlite_with_documents(tmp_path / "full.db", 2)
    assert db_has_data(tmp_path, {"DATABASE_URL": f"sqlite:///{tmp_path / 'full.db'}"}) is True


def test_db_has_data_unreachable_postgres_assumes_data(tmp_path):
    import time
    from scripts.setup import db_has_data
    start = time.monotonic()
    assert db_has_data(tmp_path, {"DATABASE_URL": "postgresql://x:y@127.0.0.1:1/none"}) is True
    assert time.monotonic() - start < 10
    assert db_has_data(tmp_path, {"DATABASE_URL": "not a url"}) is True


def test_db_has_data_on_postgres(tmp_path, database_url):
    import pytest
    if not database_url:
        pytest.skip("set TEST_DATABASE_URL to run against Postgres")
    from app.db import Database
    from scripts.setup import db_has_data
    env = {"DATABASE_URL": database_url}
    assert db_has_data(tmp_path, env) is False  # empty schema, no documents table
    db = Database(database_url)
    try:
        assert db_has_data(tmp_path, env) is False  # migrated, no rows
        with db.connect() as conn:
            org = conn.execute("INSERT INTO orgs (name) VALUES ('O')").lastrowid
            pid = conn.execute("INSERT INTO patients (org_id, label) VALUES (?, 'P')", (org,)).lastrowid
            conn.execute("INSERT INTO documents (org_id, patient_id, kind, filename, author, body_enc) VALUES (?, ?, ?, ?, ?, ?)",
                         (org, pid, "discharge_summary", "f.txt", "a", b"x"))
        assert db_has_data(tmp_path, env) is True
    finally:
        db.dispose()


def test_describe_database_hides_password(tmp_path):
    from scripts.setup import describe_database
    assert describe_database(tmp_path / "app.db") == f"Database: SQLite file {tmp_path / 'app.db'}"
    line = describe_database("postgresql://dc:s3cret@db.example:5432/app?sslmode=require")
    assert "s3cret" not in line and "db.example" in line
