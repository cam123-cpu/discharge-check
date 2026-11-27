"""Passwords, sessions, CSRF, login rate limiting, encryption at rest, and
security headers."""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from .config import Settings
from .db import Database

SESSION_COOKIE = "dc_session"
_hasher = PasswordHasher()  # argon2id with library defaults
# A real hash of a random password, so unknown emails cost the same time as known ones.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def burn_password_check(password: str) -> None:
    verify_password(_DUMMY_HASH, password)


class Cipher:
    """Field-level encryption for clinical text (Fernet: AES-128-CBC + HMAC)."""

    def __init__(self, key: str):
        self._f = Fernet(key.encode())

    def encrypt(self, text: str) -> bytes:
        return self._f.encrypt(text.encode("utf-8"))

    def decrypt(self, blob: bytes) -> str:
        try:
            return self._f.decrypt(blob).decode("utf-8")
        except InvalidToken as exc:  # wrong key or tampered row
            raise RuntimeError("Stored record could not be decrypted") from exc


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Sessions:
    """Opaque random session tokens. Only a keyed hash is stored, so a leaked
    database cannot be replayed as live sessions."""

    def __init__(self, db: Database, settings: Settings):
        self.db = db
        self.settings = settings

    def _hash(self, token: str) -> str:
        return hmac.new(self.settings.session_pepper.encode(), token.encode(), hashlib.sha256).hexdigest()

    def create(self, user_id: int) -> str:
        token = secrets.token_urlsafe(32)
        expires = (_now() + timedelta(hours=self.settings.session_hours)).isoformat()
        with self.db.connect() as conn:
            conn.execute("DELETE FROM sessions WHERE user_id = ? OR expires_at < ?", (user_id, _now().isoformat()))
            conn.execute(
                "INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)",
                (self._hash(token), user_id, secrets.token_urlsafe(32), expires),
            )
        return token

    def lookup(self, token: str | None):
        if not token or len(token) > 128:
            return None
        with self.db.connect() as conn:
            row = conn.execute(
                """SELECT s.csrf_token, s.expires_at, u.id AS user_id, u.org_id, u.email,
                          u.display_name, u.role, o.name AS org_name
                   FROM sessions s JOIN users u ON u.id = s.user_id JOIN orgs o ON o.id = u.org_id
                   WHERE s.token_hash = ?""",
                (self._hash(token),),
            ).fetchone()
        if row is None or row["expires_at"] < _now().isoformat():
            return None
        return row

    def destroy(self, token: str | None) -> None:
        if token:
            with self.db.connect() as conn:
                conn.execute("DELETE FROM sessions WHERE token_hash = ?", (self._hash(token),))


class LoginLimiter:
    """At most N failed attempts per key (email and IP separately) per window."""

    def __init__(self, db: Database, settings: Settings):
        self.db = db
        self.max = settings.login_max_attempts
        self.window = timedelta(minutes=settings.login_window_minutes)

    def _since(self) -> str:
        return (datetime.now(timezone.utc) - self.window).strftime("%Y-%m-%d %H:%M:%S")

    def blocked(self, *keys: str) -> bool:
        with self.db.connect() as conn:
            for key in keys:
                n = conn.execute(
                    "SELECT COUNT(*) FROM login_attempts WHERE key = ? AND at > ?", (key, self._since())
                ).fetchone()[0]
                if n >= self.max:
                    return True
        return False

    def record_failure(self, *keys: str) -> None:
        with self.db.connect() as conn:
            conn.executemany("INSERT INTO login_attempts (key) VALUES (?)", [(k,) for k in keys])

    def clear(self, *keys: str) -> None:
        with self.db.connect() as conn:
            conn.executemany("DELETE FROM login_attempts WHERE key = ?", [(k,) for k in keys])


def csrf_ok(expected: str, provided: str | None) -> bool:
    return bool(provided) and hmac.compare_digest(expected, provided)


CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; "
    "object-src 'none'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, force_https: bool):
        super().__init__(app)
        self.force_https = force_https

    async def dispatch(self, request: Request, call_next):
        if self.force_https:
            proto = request.headers.get("x-forwarded-proto", request.url.scheme)
            if proto != "https":
                return RedirectResponse(str(request.url.replace(scheme="https")), status_code=308)
        response: Response = await call_next(request)
        h = response.headers
        h["Content-Security-Policy"] = CSP
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["Referrer-Policy"] = "no-referrer"
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        h["Cross-Origin-Opener-Policy"] = "same-origin"
        h["Cross-Origin-Resource-Policy"] = "same-origin"
        if not request.url.path.startswith("/static/"):
            h["Cache-Control"] = "no-store"  # patient pages must not sit in shared caches
        if self.force_https:
            h["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response
