"""Settings are read from the environment only. Secrets never live in code."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader so local runs work without extra dependencies.
    Existing environment variables always win."""
    if not path.is_file():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


ROOT = Path(__file__).resolve().parent.parent
_load_dotenv(ROOT / ".env")


@dataclass(frozen=True)
class Settings:
    data_key: str
    session_pepper: str
    anthropic_api_key: str | None
    force_https: bool
    database_path: Path
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


def load_settings() -> Settings:
    data_key = os.environ.get("DATA_KEY", "")
    pepper = os.environ.get("SESSION_PEPPER", "")
    if not data_key or not pepper:
        raise RuntimeError(
            "DATA_KEY and SESSION_PEPPER must be set. Copy .env.example to .env "
            "and generate both values (see the comments in that file)."
        )
    force_https = os.environ.get("FORCE_HTTPS", "0") == "1"
    hosts = tuple(h.strip() for h in os.environ.get("ALLOWED_HOSTS", "").split(",") if h.strip())
    if force_https and (not hosts or "*" in hosts):
        raise RuntimeError("Set ALLOWED_HOSTS (comma-separated host names) when FORCE_HTTPS=1.")
    db = Path(os.environ.get("DATABASE_PATH", "data/app.db"))
    if not db.is_absolute():
        db = ROOT / db
    return Settings(
        data_key=data_key,
        session_pepper=pepper,
        anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY") or None,
        force_https=force_https,
        database_path=db,
        allowed_hosts=hosts or ("*",),
    )
