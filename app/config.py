"""Settings are read from the environment only. Secrets never live in code."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def read_env_text(path: Path) -> str:
    """Read a .env file whatever wrote it. Windows PowerShell 5.1 writes UTF-16
    with `>>` and `Out-File`, and Notepad may add a UTF-8 byte-order mark."""
    raw = path.read_bytes()
    if raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")
    # `>>` onto a UTF-8 file appends a UTF-16 chunk that starts with its own
    # byte-order mark, so decode each chunk on its own.
    first, *rest = raw.split(b"\xff\xfe")
    parts = [first.decode("utf-8-sig", errors="replace")]
    parts += [chunk.decode("utf-16-le", errors="replace") for chunk in rest]
    return "\n".join(parts)


def parse_env(text: str) -> dict[str, str]:
    """KEY=value lines. Blank values are skipped, and a later non-blank value
    for the same key wins, so a key appended below an empty placeholder works."""
    out: dict[str, str] = {}
    for raw in text.replace("\x00", "").splitlines():
        line = raw.strip()
        if line.startswith("export "):
            line = line[7:].strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip('"').strip("'")
        if value:
            out[key.strip()] = value
    return out


def valid_data_key(key: str) -> bool:
    try:
        from cryptography.fernet import Fernet
        Fernet(key.encode())
        return True
    except (ValueError, TypeError):
        return False


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader so local runs work without extra dependencies.
    Variables already set in the environment always win."""
    if not path.is_file():
        return
    for key, value in parse_env(read_env_text(path)).items():
        if not os.environ.get(key):
            os.environ[key] = value


ROOT = Path(__file__).resolve().parent.parent
_load_dotenv(ROOT / ".env")


def sqlite_path(env: dict[str, str] | None = None, root: Path | None = None) -> Path:
    env = os.environ if env is None else env
    db = Path(env.get("DATABASE_PATH") or "data/app.db")
    return db if db.is_absolute() else (root or ROOT) / db


def database_target(env: dict[str, str] | None = None, root: Path | None = None) -> str | Path:
    """DATABASE_URL when set (Postgres in any deployment), else the SQLite
    file at DATABASE_PATH. Needs no secrets, so migrations can call it."""
    env = os.environ if env is None else env
    return (env.get("DATABASE_URL") or "").strip() or sqlite_path(env, root)


@dataclass(frozen=True)
class Settings:
    data_key: str
    session_pepper: str
    anthropic_api_key: str | None
    force_https: bool
    database_path: Path
    # Postgres or SQLite, as a SQLAlchemy URL. Empty means the SQLite file at
    # database_path, which is the local-development default.
    database_url: str = ""
    model: str = "claude-opus-5-5"
    max_upload_bytes: int = 2 * 1024 * 1024
    session_hours: int = 8
    idle_minutes: int = 30  # HIPAA 164.312(a)(2)(iii): automatic logoff
    login_max_attempts: int = 5  # per email
    login_max_attempts_per_ip: int = 50  # a hospital puts many staff behind one IP
    login_window_minutes: int = 15
    checks_per_hour: int = 30  # per user; each model review costs money
    uploads_per_hour: int = 120  # per user
    allowed_hosts: tuple[str, ...] = ("*",)
    model_timeout_seconds: float = 180.0

    @property
    def database(self) -> str | Path:
        return self.database_url or self.database_path


def load_settings() -> Settings:
    data_key = os.environ.get("DATA_KEY", "")
    pepper = os.environ.get("SESSION_PEPPER", "")
    if not data_key or not pepper:
        raise RuntimeError(
            "DATA_KEY and SESSION_PEPPER are not set. Run `python -m scripts.setup` "
            "once; it creates .env with both values."
        )
    if not valid_data_key(data_key):
        raise RuntimeError("DATA_KEY in .env is not a valid key (it must be 44 characters from Fernet.generate_key()). "
                           "If the database is new, delete the DATA_KEY line and run `python -m scripts.setup`.")
    force_https = os.environ.get("FORCE_HTTPS", "0") == "1"
    hosts = tuple(h.strip() for h in os.environ.get("ALLOWED_HOSTS", "").split(",") if h.strip())
    if force_https and (not hosts or "*" in hosts):
        raise RuntimeError("Set ALLOWED_HOSTS (comma-separated host names) when FORCE_HTTPS=1.")
    db = sqlite_path()
    return Settings(
        data_key=data_key,
        session_pepper=pepper,
        anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY") or None,
        force_https=force_https,
        database_path=db,
        database_url=os.environ.get("DATABASE_URL", "").strip(),
        allowed_hosts=hosts or ("*",),
    )
