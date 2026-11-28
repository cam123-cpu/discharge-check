"""Passwords, sessions, CSRF, login rate limiting, encryption at rest, and
security headers."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .config import Settings
from .db import Database

log = logging.getLogger(__name__)
SESSION_COOKIE = "dc_session"
FLASH_COOKIE = "dc_flash"
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

    def create(self, user_id: int, auth_method: str = "password", mfa_setup_required: bool = False) -> str:
        token = secrets.token_urlsafe(32)
        expires = (_now() + timedelta(hours=self.settings.session_hours)).isoformat()
        with self.db.connect() as conn:
            conn.execute("DELETE FROM sessions WHERE user_id = ? OR expires_at < ?", (user_id, _now().isoformat()))
            conn.execute(
                "INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at, last_seen, auth_method, mfa_setup_required)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (self._hash(token), user_id, secrets.token_urlsafe(32), expires, _now().isoformat(), auth_method,
                 int(mfa_setup_required)),
            )
        return token

    def destroy_user(self, user_id: int) -> None:
        """End every session of one user, e.g. after two-factor is turned off."""
        with self.db.connect() as conn:
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))

    def mark_mfa_set_up(self, user_id: int) -> None:
        with self.db.connect() as conn:
            conn.execute("UPDATE sessions SET mfa_setup_required = 0 WHERE user_id = ?", (user_id,))

    def lookup(self, token: str | None):
        if not token or len(token) > 128:
            return None
        with self.db.connect() as conn:
            row = conn.execute(
                """SELECT s.token_hash, s.csrf_token, s.expires_at, s.last_seen, s.auth_method, s.mfa_setup_required,
                          u.id AS user_id, u.org_id, u.email, u.display_name, u.role, o.name AS org_name,
                          (u.totp_enabled_at IS NOT NULL) AS mfa_enabled
                   FROM sessions s JOIN users u ON u.id = s.user_id JOIN orgs o ON o.id = u.org_id
                   WHERE s.token_hash = ?""",
                (self._hash(token),),
            ).fetchone()
            if row is None:
                return None
            now = _now()
            idle_limit = (now - timedelta(minutes=self.settings.idle_minutes)).isoformat()
            if row["expires_at"] < now.isoformat() or (row["last_seen"] or "") < idle_limit:
                conn.execute("DELETE FROM sessions WHERE token_hash = ?", (row["token_hash"],))
                return None
            # Sliding idle timeout; write at most once a minute.
            if row["last_seen"] < (now - timedelta(minutes=1)).isoformat():
                conn.execute("UPDATE sessions SET last_seen = ? WHERE token_hash = ?", (now.isoformat(), row["token_hash"]))
        return row

    def destroy(self, token: str | None) -> None:
        if token:
            with self.db.connect() as conn:
                conn.execute("DELETE FROM sessions WHERE token_hash = ?", (self._hash(token),))


class RateLimiter:
    """Sliding-window counters kept in the database, so limits hold across
    worker processes. Keys are namespaced, e.g. 'email:x@y', 'ip:1.2.3.4',
    'check:user:7'."""

    def __init__(self, db: Database):
        self.db = db

    @staticmethod
    def _since(window: timedelta) -> str:
        return (datetime.now(timezone.utc) - window).strftime("%Y-%m-%d %H:%M:%S")

    def count(self, key: str, window: timedelta) -> int:
        with self.db.connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM login_attempts WHERE key = ? AND at > ?", (key, self._since(window))).fetchone()[0]

    def hit(self, *keys: str) -> None:
        with self.db.connect() as conn:
            conn.executemany("INSERT INTO login_attempts (key) VALUES (?)", [(k,) for k in keys])
            # Keep the table small: nothing older than a day matters.
            conn.execute("DELETE FROM login_attempts WHERE at < ?", (self._since(timedelta(days=1)),))

    def clear(self, *keys: str) -> None:
        with self.db.connect() as conn:
            conn.executemany("DELETE FROM login_attempts WHERE key = ?", [(k,) for k in keys])

    def allow(self, key: str, limit: int, window: timedelta) -> bool:
        """Count one use of an action and say whether it is within the limit."""
        if self.count(key, window) >= limit:
            return False
        self.hit(key)
        return True


class LoginLimiter:
    """Failed sign-ins: a tight limit per email (stops password guessing on one
    account) and a looser one per IP (a hospital puts many staff behind one
    address, so 5 per IP would lock out a whole ward)."""

    def __init__(self, db: Database, settings: Settings):
        self.rl = RateLimiter(db)
        self.window = timedelta(minutes=settings.login_window_minutes)
        self.per_email = settings.login_max_attempts
        self.per_ip = settings.login_max_attempts_per_ip

    def blocked(self, ip: str, email: str) -> bool:
        return self.rl.count(f"email:{email}", self.window) >= self.per_email or self.rl.count(f"ip:{ip}", self.window) >= self.per_ip

    def record_failure(self, ip: str, email: str) -> None:
        self.rl.hit(f"ip:{ip}", f"email:{email}")

    def clear(self, email: str) -> None:
        # Only the account's own counter. Clearing the IP counter on success
        # would let one valid account reset the limit for guesses on others.
        self.rl.clear(f"email:{email}")


class PendingLogins:
    """The step between a correct password and a session. The browser holds a
    random token; the database holds its keyed hash, the user id, an expiry
    and an attempt counter. A pending sign-in grants no access by itself."""

    def __init__(self, db: Database, settings: Settings):
        self.db = db
        self.settings = settings

    def _hash(self, token: str) -> str:
        return hmac.new(self.settings.session_pepper.encode(), b"pending:" + token.encode(), hashlib.sha256).hexdigest()

    def create(self, user_id: int) -> str:
        token = secrets.token_urlsafe(32)
        expires = (_now() + timedelta(minutes=self.settings.pending_login_minutes)).isoformat()
        with self.db.connect() as conn:
            conn.execute("DELETE FROM pending_logins WHERE user_id = ? OR expires_at < ?", (user_id, _now().isoformat()))
            conn.execute("INSERT INTO pending_logins (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                         (self._hash(token), user_id, expires))
        return token

    def lookup(self, token: str | None):
        """The row (token_hash, user_id, attempts), or None when missing,
        expired or out of attempts."""
        if not token or len(token) > 128:
            return None
        with self.db.connect() as conn:
            row = conn.execute("SELECT token_hash, user_id, expires_at, attempts FROM pending_logins WHERE token_hash = ?",
                               (self._hash(token),)).fetchone()
            if row is None:
                return None
            if row["expires_at"] < _now().isoformat() or row["attempts"] >= self.settings.mfa_max_attempts:
                conn.execute("DELETE FROM pending_logins WHERE token_hash = ?", (row["token_hash"],))
                return None
        return row

    def fail(self, token_hash: str) -> None:
        with self.db.connect() as conn:
            conn.execute("UPDATE pending_logins SET attempts = attempts + 1 WHERE token_hash = ?", (token_hash,))

    def consume(self, token_hash: str) -> bool:
        """Single use: True only for the one request that deletes the row."""
        with self.db.connect() as conn:
            return conn.execute("DELETE FROM pending_logins WHERE token_hash = ?", (token_hash,)).rowcount == 1


def csrf_ok(expected: str, provided) -> bool:
    # `provided` comes straight from a form and may be a file upload, not text.
    return isinstance(provided, str) and bool(provided) and bool(expected) and hmac.compare_digest(expected.encode(), provided.encode())


class Flash:
    """One-time messages carried across a redirect in a signed cookie, so no
    page ever shows text taken from the URL (which anyone can craft and send
    as a link: "Your session expired, call 555-0100 with your password")."""

    def __init__(self, secret: str, secure: bool):
        self.key = hashlib.sha256(b"flash:" + secret.encode()).digest()
        self.secure = secure

    def _sig(self, body: bytes) -> str:
        return base64.urlsafe_b64encode(hmac.new(self.key, body, hashlib.sha256).digest()[:16]).decode()

    def set(self, resp, notice: str = "", warnings: list[str] | None = None, error: str = ""):
        data = {"n": notice[:300], "w": [w[:300] for w in (warnings or [])][:5], "e": error[:300]}
        body = base64.urlsafe_b64encode(json.dumps(data).encode())
        resp.set_cookie(FLASH_COOKIE, body.decode() + "." + self._sig(body), max_age=120, httponly=True,
                        secure=self.secure, samesite="strict", path="/")
        return resp

    def read(self, raw: str | None) -> dict:
        empty = {"n": "", "w": [], "e": ""}
        if not raw or "." not in raw or len(raw) > 4096:
            return empty
        body, sig = raw.rsplit(".", 1)
        if not hmac.compare_digest(sig, self._sig(body.encode())):
            return empty
        try:
            data = json.loads(base64.urlsafe_b64decode(body.encode()))
            return {"n": str(data.get("n", "")), "w": [str(w) for w in data.get("w", [])][:5], "e": str(data.get("e", ""))}
        except (ValueError, TypeError, AttributeError):
            return empty


CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; "
    "object-src 'none'"
)

_ERROR_PAGE = (b"<!doctype html><html lang=en><meta charset=utf-8><title>Error</title>"
               b"<link rel=stylesheet href=/static/app.css><main class=page><h1>Something went wrong</h1>"
               b"<p>The error was logged. Nothing you entered was shown or sent anywhere. "
               b"<a href=/>Back to discharges</a></p></main>")


class SecurityMiddleware:
    """Pure ASGI (so it also wraps error responses):
    - HTTP -> HTTPS redirect and HSTS when force_https is on;
    - refuses request bodies over max_body bytes before any parsing, including
      for signed-out callers (multipart parsing happens before the auth check);
    - security headers on every response;
    - a plain 500 page for unhandled errors, with no stack trace."""

    def __init__(self, app: ASGIApp, force_https: bool, max_body: int):
        self.app = app
        self.force_https = force_https
        self.max_body = max_body

    async def _plain(self, send: Send, status: int, body: bytes, extra: list | None = None):
        headers = [(b"content-type", b"text/html; charset=utf-8"), (b"content-length", str(len(body)).encode())]
        headers += self._security_headers(b"/") + (extra or [])
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    def _security_headers(self, path: bytes) -> list[tuple[bytes, bytes]]:
        h = [
            (b"content-security-policy", CSP.encode()),
            (b"x-content-type-options", b"nosniff"),
            (b"x-frame-options", b"DENY"),
            (b"referrer-policy", b"no-referrer"),
            (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()"),
            (b"cross-origin-opener-policy", b"same-origin"),
            (b"cross-origin-resource-policy", b"same-origin"),
            (b"x-permitted-cross-domain-policies", b"none"),
        ]
        if not path.startswith(b"/static/"):
            h.append((b"cache-control", b"no-store"))  # patient pages must not sit in shared caches
        if self.force_https:
            h.append((b"strict-transport-security", b"max-age=63072000; includeSubDomains"))
        return h

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope.get("path", "/").encode()
        if self.force_https and scope.get("scheme") != "https":
            host = dict(scope["headers"]).get(b"host", b"").decode("latin-1")
            qs = scope.get("query_string", b"").decode("latin-1")
            url = f"https://{host}{scope.get('path', '/')}" + (f"?{qs}" if qs else "")
            return await self._plain(send, 308, b"", [(b"location", url.encode("latin-1"))])

        length = dict(scope["headers"]).get(b"content-length")
        if length is not None:
            try:
                too_big = int(length) > self.max_body
            except ValueError:
                return await self._plain(send, 400, b"Bad request")
            if too_big:
                return await self._plain(send, 413, b"<p>The upload is too large.</p>", [(b"connection", b"close")])

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            msg = await receive()
            if msg["type"] == "http.request":
                received += len(msg.get("body", b""))
                if received > self.max_body:  # chunked bodies with no Content-Length
                    raise _BodyTooLarge()
            return msg

        started = False

        async def send_wrapper(msg: Message):
            nonlocal started
            if msg["type"] == "http.response.start":
                started = True
                headers = MutableHeaders(scope=msg)
                for k, v in self._security_headers(path):
                    headers[k.decode()] = v.decode()
                if "server" in headers:
                    del headers["server"]
            await send(msg)

        try:
            await self.app(scope, limited_receive, send_wrapper)
        except _BodyTooLarge:
            if not started:
                await self._plain(send, 413, b"<p>The upload is too large.</p>", [(b"connection", b"close")])
        except Exception:
            log.exception("Unhandled error on %s %s", scope.get("method"), scope.get("path"))
            if not started:
                await self._plain(send, 500, _ERROR_PAGE)


class _BodyTooLarge(Exception):
    pass
