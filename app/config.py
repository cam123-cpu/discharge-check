"""Settings are read from the environment only. Secrets never live in code."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

# Hostname, or hostname:port. No scheme, path, or userinfo, so a redirect
# cannot be pointed at an attacker-controlled host.
_HOST_RE = re.compile(
    r"\A(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*"
    r"(?::[0-9]{1,5})?\Z"
)


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
    login_max_attempts: int = 5
    login_window_minutes: int = 15
    public_host: str = ""
    trust_proxy: bool = False
    # X-Forwarded-Proto is honored only from these peers when trust_proxy is on.
    trusted_proxy_ips: tuple[str, ...] = ("127.0.0.1", "::1")


def _valid_public_host(host: str) -> bool:
    if not _HOST_RE.match(host):
        return False
    if ":" in host:
        port = int(host.rsplit(":", 1)[1])
        if not 1 <= port <= 65535:
            return False
    return True


def load_settings() -> Settings:
    data_key = os.environ.get("DATA_KEY", "")
    pepper = os.environ.get("SESSION_PEPPER", "")
    if not data_key or not pepper:
        raise RuntimeError(
            "DATA_KEY and SESSION_PEPPER must be set. Copy .env.example to .env "
            "and generate both values (see the comments in that file)."
        )
    db = Path(os.environ.get("DATABASE_PATH", "data/app.db"))
    if not db.is_absolute():
        db = ROOT / db
    public_host = os.environ.get("PUBLIC_HOST", "").strip()
    if public_host and not _valid_public_host(public_host):
        raise RuntimeError("PUBLIC_HOST must be a hostname, optionally with a port. No scheme or path.")
    trust_proxy = os.environ.get("TRUST_PROXY", "0") == "1"
    if trust_proxy and not public_host:
        raise RuntimeError("TRUST_PROXY=1 requires PUBLIC_HOST, so an HTTPS redirect cannot follow the Host header.")
    extras = tuple(part.strip() for part in os.environ.get("TRUSTED_PROXY_IPS", "").split(",") if part.strip())
    for ip in extras:
        if len(ip) > 64 or any(ch in ip for ch in " /\\\n\r"):
            raise RuntimeError("TRUSTED_PROXY_IPS must be a comma-separated list of IP addresses.")
    peers: list[str] = []
    for ip in ("127.0.0.1", "::1", *extras):
        if ip not in peers:
            peers.append(ip)
    return Settings(
        data_key=data_key,
        session_pepper=pepper,
        anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY") or None,
        force_https=os.environ.get("FORCE_HTTPS", "0") == "1",
        database_path=db,
        public_host=public_host,
        trust_proxy=trust_proxy,
        trusted_proxy_ips=tuple(peers),
    )
