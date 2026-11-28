"""One-step first run: creates .env with fresh keys, then seeds the demo data.

Usage (any OS, from the repository folder, with the virtual environment active):
    python -m scripts.setup                 # safe to run again; never overwrites keys
    python -m scripts.setup --new-passwords # print new passwords for the demo accounts
"""
from __future__ import annotations

import argparse
import os
import secrets
import sys
from pathlib import Path

# Taken before anything imports app.config, which copies .env into the
# environment: values set by the user's shell must keep winning.
_SHELL_ENV = set(os.environ)

ROOT = Path(__file__).resolve().parent.parent
ENV = ROOT / ".env"
EXAMPLE = ROOT / ".env.example"


def _fernet_key() -> str:
    from cryptography.fernet import Fernet
    return Fernet.generate_key().decode()


GENERATED = {"DATA_KEY": _fernet_key, "SESSION_PEPPER": lambda: secrets.token_urlsafe(48)}


def ensure_env(path: Path = ENV, example: Path = EXAMPLE) -> list[str]:
    """Create or repair .env so DATA_KEY and SESSION_PEPPER have values.
    Returns the keys it generated. Existing values are never changed: a new
    DATA_KEY would make already-stored records unreadable."""
    sys.path.insert(0, str(ROOT))
    from app.config import parse_env, read_env_text

    from app.config import valid_data_key

    text = read_env_text(path) if path.is_file() else (example.read_text(encoding="utf-8") if example.is_file() else "")
    have = parse_env(text)
    if "DATA_KEY" in have and not valid_data_key(have["DATA_KEY"]):
        # DATABASE_URL / DATABASE_PATH set in the shell win over .env, as in the app.
        shell = {k: os.environ[k] for k in ("DATABASE_URL", "DATABASE_PATH")
                 if path == ENV and k in _SHELL_ENV and os.environ.get(k)}
        target_env = {**have, **shell}
        if db_has_data(path.parent, target_env):
            raise SystemExit("DATA_KEY in .env is not a valid key, and the database already holds records encrypted "
                             "with some key. Restore the original DATA_KEY, or delete the database to start over.")
        print("DATA_KEY in .env was not a valid key; replacing it (the database is empty).")
        del have["DATA_KEY"]
        text = "\n".join(ln for ln in text.splitlines() if ln.split("=", 1)[0].strip() != "DATA_KEY")
    made = []
    lines = []
    for raw in text.replace("\x00", "").splitlines():
        key = raw.split("=", 1)[0].strip()
        if "=" in raw and not raw.lstrip().startswith("#") and key in GENERATED:
            if key in made or key in have:
                # Keep the line that holds the value; drop empty duplicates.
                if raw.split("=", 1)[1].strip() == "":
                    continue
                lines.append(raw)
                continue
            lines.append(f"{key}={GENERATED[key]()}")
            made.append(key)
            continue
        lines.append(raw)
    for key, make in GENERATED.items():
        if key not in have and key not in made:
            lines.append(f"{key}={make()}")
            made.append(key)
    # Always rewrite as plain UTF-8 so a PowerShell-written file is repaired too.
    path.write_text("\n".join(lines).rstrip("\n") + "\n", encoding="utf-8")
    return made


def db_has_data(root: Path, env: dict[str, str]) -> bool:
    """Whether the database (DATABASE_URL, else the SQLite file at
    DATABASE_PATH) holds any documents, which are encrypted with DATA_KEY."""
    sys.path.insert(0, str(ROOT))
    from sqlalchemy import create_engine, func, inspect, select, table
    from sqlalchemy.exc import SQLAlchemyError
    from sqlalchemy.pool import NullPool

    from app.config import database_target
    from app.db import _sqlite_file, normalize_url, set_rls_context

    try:
        url = normalize_url(database_target(env, root))
    except SQLAlchemyError:
        return True  # a malformed DATABASE_URL: assume it matters
    is_sqlite = url.get_backend_name() == "sqlite"
    if is_sqlite:
        path = _sqlite_file(url)
        if path is not None and not path.is_file():
            return False  # never created, so nothing is encrypted yet
    try:
        # A short timeout so an unreachable server fails fast instead of hanging.
        args = {"timeout": 5} if is_sqlite else {"connect_timeout": 5}
        engine = create_engine(url, poolclass=NullPool, connect_args=args)
    except (SQLAlchemyError, ImportError, ValueError):
        return True  # unusable URL: assume it matters
    try:
        with engine.connect() as conn:
            # Count every hospital's documents: row-level security would
            # otherwise hide them all, and a "no data" answer lets setup
            # replace DATA_KEY under records it can no longer decrypt.
            set_rls_context(conn, None)
            if not inspect(conn).has_table("documents"):
                return False  # an empty or never-migrated database holds no records
            return conn.execute(select(func.count()).select_from(table("documents"))).scalar_one() > 0
    except SQLAlchemyError:
        return True  # unreadable or unreachable: assume it matters
    finally:
        engine.dispose()


def describe_database(target: str | Path) -> str:
    """A line for the console naming the database, never its password."""
    from app.db import _sqlite_file, normalize_url, redact
    url = normalize_url(target)
    path = _sqlite_file(url) if url.get_backend_name() == "sqlite" else None
    if path is not None:
        return f"Database: SQLite file {path}"
    return f"Database: {redact(url)}"


def new_passwords() -> None:
    from app.config import load_settings
    from app.db import Database
    from app.security import hash_password
    from scripts.seed import USERS

    db = Database(load_settings().database)
    print("New demo passwords (save these; they are not shown again):")
    with db.connect() as conn:
        for email, _, role in USERS:
            pw = secrets.token_urlsafe(12)
            if conn.execute("UPDATE users SET password_hash = ? WHERE email = ?", (hash_password(pw), email)).rowcount:
                print(f"  {role:13} {email:24} {pw}")
        conn.execute("DELETE FROM sessions")
        conn.execute("DELETE FROM login_attempts")


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--new-passwords", action="store_true", help="reset the demo accounts' passwords and print them")
    args = ap.parse_args(argv)

    made = ensure_env()
    print(f"Created keys in .env: {', '.join(made)}" if made else ".env already has its keys.")
    # app.config copied .env into the environment when first imported, before
    # the repair above. Copy the repaired values over, except shell-set ones.
    from app.config import parse_env, read_env_text
    for key, value in parse_env(read_env_text(ENV)).items():
        if key not in _SHELL_ENV:
            os.environ[key] = value
    from app.config import database_target
    print(describe_database(database_target()))
    if args.new_passwords:
        new_passwords()
    else:
        from scripts.seed import main as seed
        seed()
    print("\nStart the app:  uvicorn app.main:get_app --factory --port 8000 --no-server-header")
    print("Then open:      http://localhost:8000")


if __name__ == "__main__":
    main()
