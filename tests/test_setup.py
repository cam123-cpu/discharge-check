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
