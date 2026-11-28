"""One-step first run: creates .env with fresh keys, then seeds the demo data.

Usage (any OS, from the repository folder, with the virtual environment active):
    python -m scripts.setup                 # safe to run again; never overwrites keys
    python -m scripts.setup --new-passwords # print new passwords for the demo accounts
    python -m scripts.setup --reset-2fa EMAIL  # someone lost their phone and recovery codes
    python -m scripts.setup --issue-2fa-code EMAIL  # one-time code to set up two-factor
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
        if db_has_data(path.parent, have):
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
    import sqlite3
    db = Path(env.get("DATABASE_PATH", "data/app.db"))
    db = db if db.is_absolute() else root / db
    if not db.is_file():
        return False
    try:
        with sqlite3.connect(db) as conn:
            return conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0] > 0
    except sqlite3.Error:
        return True  # unreadable: assume it matters


def new_passwords() -> None:
    from app.config import load_settings
    from app.db import Database
    from app.security import hash_password
    from scripts.seed import USERS

    db = Database(load_settings().database_path)
    print("New demo passwords (save these; they are not shown again):")
    with db.connect() as conn:
        for email, _, role in USERS:
            pw = secrets.token_urlsafe(12)
            if conn.execute("UPDATE users SET password_hash = ? WHERE email = ?", (hash_password(pw), email)).rowcount:
                print(f"  {role:13} {email:24} {pw}")
        conn.execute("DELETE FROM sessions")
        conn.execute("DELETE FROM login_attempts")


def reset_2fa(email: str, db=None) -> bool:
    """Turn two-factor off for one account so its owner can sign in with the
    password alone and set it up again. Also ends their sessions and any
    half-finished sign-in. Returns False when no such account exists."""
    from app.mfa import clear_two_factor

    if db is None:
        from app.config import load_settings
        from app.db import Database
        db = Database(load_settings().database_path)
    with db.connect() as conn:
        user = conn.execute("SELECT id, org_id FROM users WHERE email = ?", (email.strip().lower(),)).fetchone()
        if user is None:
            return False
        clear_two_factor(conn, user["id"])
        conn.execute("DELETE FROM pending_logins WHERE user_id = ?", (user["id"],))
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))
        # No signed-in actor: the change came from the server console.
        db.audit(conn, user["org_id"], None, "mfa_reset", f"user:{user['id']}", "console")
    return True


def issue_2fa_code(email: str, db=None, settings=None) -> str | None:
    """A one-time setup code for one account (roles in MFA_REQUIRED_ROLES need
    it to turn on two-factor). Returns None when no such account exists."""
    from app.mfa import issue_setup_code

    if settings is None:
        from app.config import load_settings
        settings = load_settings()
    if db is None:
        from app.db import Database
        db = Database(settings.database_path)
    with db.connect() as conn:
        user = conn.execute("SELECT id, org_id FROM users WHERE email = ?", (email.strip().lower(),)).fetchone()
        if user is None:
            return None
        code = issue_setup_code(conn, settings.session_pepper, user["id"], settings.mfa_setup_code_hours)
        db.audit(conn, user["org_id"], None, "mfa_setup_code_issued", f"user:{user['id']}", "console")
    return code


def _print_setup_code(email: str) -> None:
    from app.config import load_settings
    code = issue_2fa_code(email)
    if code is None:
        raise SystemExit(f"No account with the email {email}.")
    print(f"One-time setup code for {email} (valid {load_settings().mfa_setup_code_hours} hours): {code}")
    print("Give it to them in person or by phone, not by email. They enter it under Security.")


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--new-passwords", action="store_true", help="reset the demo accounts' passwords and print them")
    ap.add_argument("--reset-2fa", metavar="EMAIL", help="turn off two-factor sign-in for one account")
    ap.add_argument("--issue-2fa-code", metavar="EMAIL", help="print a one-time code that lets this account set up two-factor")
    args = ap.parse_args(argv)

    made = ensure_env()
    print(f"Created keys in .env: {', '.join(made)}" if made else ".env already has its keys.")
    # app.config copied .env into the environment when first imported, before
    # the repair above. Copy the repaired values over, except shell-set ones.
    from app.config import parse_env, read_env_text
    for key, value in parse_env(read_env_text(ENV)).items():
        if key not in _SHELL_ENV:
            os.environ[key] = value
    if args.reset_2fa:
        if not reset_2fa(args.reset_2fa):
            raise SystemExit(f"No account with the email {args.reset_2fa}.")
        print(f"Two-factor sign-in is off for {args.reset_2fa}; their sessions were ended. "
              "They can sign in with their password and set it up again.")
        _print_setup_code(args.reset_2fa)
        return
    if args.issue_2fa_code:
        _print_setup_code(args.issue_2fa_code)
        return
    if args.new_passwords:
        new_passwords()
    else:
        from scripts.seed import main as seed
        seed()
    print("\nStart the app:  uvicorn app.main:get_app --factory --port 8000 --no-server-header")
    print("Then open:      http://localhost:8000")


if __name__ == "__main__":
    main()
