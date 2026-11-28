"""Two-factor sign-in: TOTP (RFC 6238) authenticator apps and single-use
recovery codes. Routes are added by register(app, ctx)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import struct
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import segno
from fastapi import Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .security import SESSION_COOKIE, csrf_ok, verify_password

AUDIT_ACTIONS: dict[str, str] = {
    "login_password_ok": "Password accepted, second step owed",
    "mfa_enabled": "Two-factor turned on",
    "mfa_disabled": "Two-factor turned off",
    "mfa_failed": "Two-factor code rejected",
    "recovery_code_used": "Recovery code used",
    "recovery_codes_regenerated": "Recovery codes replaced",
    "mfa_reset": "Two-factor reset by an administrator",
    "mfa_setup_code_issued": "Two-factor setup code issued",
}

STEP = 30  # seconds per code (RFC 6238 default; what every authenticator app assumes)
DIGITS = 6
DRIFT = 1  # accept one step either side: phone clocks and slow typists
RECOVERY_COUNT = 10
# No 0/o, 1/i/l: codes are read off paper and typed by hand.
RECOVERY_ALPHABET = "23456789abcdefghjkmnpqrstuvwxyz"
RECOVERY_GROUPS, RECOVERY_GROUP_LEN = 3, 4  # xxxx-xxxx-xxxx, about 59 bits
_DIGITS_RE = re.compile(r"^\d{6}$")


def _clock() -> float:
    # A seam for tests; production always reads the system clock.
    return time.time()


# ---------- TOTP (RFC 6238 / RFC 4226) ----------

def new_secret() -> str:
    """160 random bits, base32 without padding (the length RFC 4226 recommends)."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _key(secret_b32: str) -> bytes:
    s = secret_b32.upper().replace(" ", "")
    return base64.b32decode(s + "=" * (-len(s) % 8))


def hotp(key: bytes, counter: int, digits: int = DIGITS, digest=hashlib.sha1) -> str:
    mac = hmac.new(key, struct.pack(">Q", counter), digest).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** digits).zfill(digits)


def step_at(now: float) -> int:
    return int(now // STEP)


def totp_at(secret_b32: str, now: float) -> str:
    return hotp(_key(secret_b32), step_at(now))


def matching_step(secret_b32: str, code: str, now: float | None = None) -> int | None:
    """The newest step within the drift window whose code equals `code`, or
    None. Every candidate is compared so timing does not reveal which matched."""
    if not _DIGITS_RE.match(code or ""):
        return None
    key, current = _key(secret_b32), step_at(_clock() if now is None else now)
    found = None
    for step in range(current - DRIFT, current + DRIFT + 1):
        if hmac.compare_digest(hotp(key, step).encode(), code.encode()):
            found = step
    return found


def otpauth_uri(secret_b32: str, issuer: str, email: str) -> str:
    label = quote(f"{issuer}:{email}", safe=":@")
    return (f"otpauth://totp/{label}?secret={secret_b32}&issuer={quote(issuer, safe='')}"
            f"&algorithm=SHA1&digits={DIGITS}&period={STEP}")


def qr_data_uri(uri: str) -> str:
    # Rendered on the server as a data: image, which the CSP allows; no script needed.
    return segno.make(uri, error="m").svg_data_uri(scale=5, border=2, dark="#1b1c1e", light="#ffffff")


def group_secret(secret_b32: str) -> str:
    return " ".join(secret_b32[i:i + 4] for i in range(0, len(secret_b32), 4))


# ---------- recovery codes ----------

def new_recovery_code() -> str:
    chars = "".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(RECOVERY_GROUPS * RECOVERY_GROUP_LEN))
    return "-".join(chars[i:i + RECOVERY_GROUP_LEN] for i in range(0, len(chars), RECOVERY_GROUP_LEN))


def normalize_recovery(code: str) -> str:
    return re.sub(r"[\s\-]", "", (code or "").lower())


def recovery_hash(pepper: str, user_id: int, code: str) -> str:
    """Keyed, so a copied database cannot be brute-forced offline without the
    pepper; the user id is mixed in so equal codes on two accounts differ."""
    key = hmac.new(pepper.encode(), b"recovery-code-key", hashlib.sha256).digest()
    return hmac.new(key, f"{user_id}:{normalize_recovery(code)}".encode(), hashlib.sha256).hexdigest()


def replace_recovery_codes(conn, pepper: str, user_id: int) -> list[str]:
    codes = [new_recovery_code() for _ in range(RECOVERY_COUNT)]
    conn.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user_id,))
    conn.executemany("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)",
                     [(user_id, recovery_hash(pepper, user_id, c)) for c in codes])
    return codes


def setup_code_hash(pepper: str, user_id: int, code: str) -> str:
    key = hmac.new(pepper.encode(), b"mfa-setup-code-key", hashlib.sha256).digest()
    return hmac.new(key, f"{user_id}:{normalize_recovery(code)}".encode(), hashlib.sha256).hexdigest()


def issue_setup_code(conn, pepper: str, user_id: int, hours: int) -> str:
    """A one-time code an administrator hands to one person (in person or by
    phone, not by email), which roles that require two-factor must enter to
    set it up. Replaces any earlier code for that account."""
    code = new_recovery_code()
    expires = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()
    conn.execute("UPDATE users SET mfa_setup_code_hash = ?, mfa_setup_code_expires = ? WHERE id = ?",
                 (setup_code_hash(pepper, user_id, code), expires, user_id))
    return code


def consume_setup_code(conn, pepper: str, user_id: int, code: str) -> bool:
    """Single use, in one statement, and only before it expires."""
    now = datetime.now(timezone.utc).isoformat()
    return conn.execute(
        "UPDATE users SET mfa_setup_code_hash = NULL, mfa_setup_code_expires = NULL"
        " WHERE id = ? AND mfa_setup_code_hash = ? AND mfa_setup_code_expires > ?",
        (user_id, setup_code_hash(pepper, user_id, code), now)).rowcount == 1


def clear_two_factor(conn, user_id: int) -> None:
    """Everything two-factor for one account. Shared with scripts/setup.py --reset-2fa."""
    conn.execute("UPDATE users SET totp_secret_enc = NULL, totp_pending_enc = NULL, totp_enabled_at = NULL,"
                 " totp_pending_session = NULL WHERE id = ?", (user_id,))
    conn.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user_id,))


# ---------- routes ----------

def register(app, ctx) -> None:
    settings, db, cipher = ctx.settings, ctx.db, ctx.cipher
    window = timedelta(minutes=settings.login_window_minutes)
    form_key = hmac.new(settings.session_pepper.encode(), b"mfa-form", hashlib.sha256).digest()

    def load_user(conn, user_id: int):
        return conn.execute(
            """SELECT id, org_id, email, role, totp_secret_enc, totp_pending_enc, totp_enabled_at, totp_last_step,
                      totp_pending_session FROM users WHERE id = ?""", (user_id,)).fetchone()

    def needs_setup_code(user) -> bool:
        return user["role"] in settings.mfa_required_roles

    def my_pending(row, user) -> bool:
        # A pending key belongs to the session that started setup. Signing in
        # again ends that session (one session per account), so someone who
        # signs in with a stolen password cannot read or confirm the new key.
        return bool(row["totp_pending_enc"]) and bool(row["totp_pending_session"]) and hmac.compare_digest(
            row["totp_pending_session"], user["token_hash"])

    def use_totp(user, code: str) -> str:
        """'ok', 'replay' or 'wrong'. Moving totp_last_step forward is a single
        conditional UPDATE, so two requests racing with one code cannot both win."""
        if not user["totp_secret_enc"]:
            return "wrong"
        step = matching_step(cipher.decrypt(user["totp_secret_enc"]), code)
        if step is None:
            return "wrong"
        with db.connect() as conn:
            won = conn.execute("UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?",
                               (step, user["id"], step)).rowcount == 1
        return "ok" if won else "replay"

    def use_recovery(user_id: int, code: str) -> bool:
        if len(normalize_recovery(code)) != RECOVERY_GROUPS * RECOVERY_GROUP_LEN:
            return False
        with db.connect() as conn:
            return conn.execute(
                "UPDATE recovery_codes SET used_at = datetime('now') WHERE user_id = ? AND code_hash = ? AND used_at IS NULL",
                (user_id, recovery_hash(settings.session_pepper, user_id, code))).rowcount == 1

    def check_code(user, code: str, allow_recovery: bool) -> tuple[str, str]:
        """(result, method) where result is 'ok', 'replay' or 'wrong' and
        method is 'totp' or 'recovery'."""
        code = (code or "").strip().replace(" ", "")
        if _DIGITS_RE.match(code):
            return use_totp(user, code), "totp"
        if allow_recovery and use_recovery(user["id"], code):
            return "ok", "recovery"
        return "wrong", "recovery" if allow_recovery else "totp"

    def remaining_codes(user_id: int) -> int:
        with db.connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used_at IS NULL",
                                (user_id,)).fetchone()[0]

    def audit(user, action: str, target: str, request: Request) -> None:
        with db.connect() as conn:
            db.audit(conn, user["org_id"], user["id"], action, target, ctx.client_ip(request))

    def failure_message(result: str, recovery: bool = True) -> str:
        if result == "replay":
            return "That code was already used. Wait for the next code in your app and try again."
        return "That code is not right. Check the six-digit code in your app" + (", or enter a recovery code." if recovery else ".")

    # --- second step of sign-in ---

    def form_token(token_hash: str) -> str:
        # The CSRF value is derived from the pending row, so only the browser
        # that holds the dc_mfa cookie can produce it.
        return hmac.new(form_key, token_hash.encode(), hashlib.sha256).hexdigest()

    def back_to_login(error: str):
        resp = ctx.go("/login", error=error)
        resp.delete_cookie(ctx.MFA_COOKIE, path="/")
        return resp

    expired = "Your sign-in timed out or had too many wrong codes. Sign in again."

    @app.get("/login/2fa", response_class=HTMLResponse)
    def login_2fa_page(request: Request):
        row = ctx.pending.lookup(request.cookies.get(ctx.MFA_COOKIE))
        if row is None:
            return back_to_login(expired)
        return ctx.render(request, "login_2fa.html", {"user": None, "form_token": form_token(row["token_hash"])})

    @app.post("/login/2fa")
    def login_2fa(request: Request, code: str = Form("", max_length=64), csrf: str = Form("", max_length=128)):
        row = ctx.pending.lookup(request.cookies.get(ctx.MFA_COOKIE))
        if row is None:
            return back_to_login(expired)
        if not csrf_ok(form_token(row["token_hash"]), csrf):
            return ctx.go("/login/2fa", error="The form expired. Enter the code again.")
        with db.connect() as conn:
            user = load_user(conn, row["user_id"])
        if user is None or not user["totp_enabled_at"]:
            ctx.pending.consume(row["token_hash"])
            return back_to_login("Sign in again.")
        # Per account as well as per pending sign-in: someone who knows the
        # password could otherwise start fresh sign-ins for unlimited guesses.
        # Both counters are taken before the code is checked, so parallel guesses
        # are counted too.
        limit_key = f"mfa:user:{user['id']}"
        if not ctx.pending.take_attempt(row["token_hash"]):
            ctx.pending.consume(row["token_hash"])
            return back_to_login(expired)
        if not ctx.rate.reserve(limit_key, settings.mfa_max_attempts, window):
            ctx.pending.consume(row["token_hash"])
            audit(user, "mfa_failed", "blocked", request)
            return back_to_login(f"Too many wrong codes. Wait {settings.login_window_minutes} minutes and sign in again.")
        result, method = check_code(user, code, allow_recovery=True)
        if result != "ok":
            audit(user, "mfa_failed", f"method:{method}", request)
            return ctx.go("/login/2fa", error=failure_message(result))
        if not ctx.pending.consume(row["token_hash"]):  # a parallel request already finished this sign-in
            return back_to_login("Sign in again.")
        ctx.rate.clear(limit_key)
        resp = ctx.start_session(request, user, f"password+{method}")
        if method == "recovery":
            left = remaining_codes(user["id"])
            audit(user, "recovery_code_used", f"remaining:{left}", request)
            ctx.flash.set(resp, notice=f"You signed in with a recovery code. {left} of {RECOVERY_COUNT} codes are left. "
                                       "Generate new codes under Security if you are running low.")
        return resp

    # --- account security page ---

    def account_key(user_id: int) -> str:
        # Separate from the sign-in counter so mistakes on this page cannot lock
        # someone out of signing in, but limited the same way.
        return f"mfa:account:{user_id}"

    def account_blocked(user_id: int) -> bool:
        # Counts this attempt before any check runs (see login_2fa); a success clears it.
        return not ctx.rate.reserve(account_key(user_id), settings.mfa_max_attempts, window)

    def too_many():
        return ctx.go("/account/security", error=f"Too many wrong attempts. Wait {settings.login_window_minutes} minutes and try again.")

    @app.get("/account/security", response_class=HTMLResponse)
    def security_page(request: Request, user=Depends(ctx.current_user)):
        with db.connect() as conn:
            row = load_user(conn, user["user_id"])
        setup = None
        if not row["totp_enabled_at"] and my_pending(row, user):
            secret = cipher.decrypt(row["totp_pending_enc"])
            uri = otpauth_uri(secret, settings.mfa_issuer, row["email"])
            setup = {"secret": group_secret(secret), "uri": uri, "qr": qr_data_uri(uri)}
        return ctx.render(request, "security.html", {
            "user": user, "nav": "security", "enabled_at": row["totp_enabled_at"], "setup": setup,
            "remaining": remaining_codes(row["id"]) if row["totp_enabled_at"] else 0, "total": RECOVERY_COUNT,
            "required": user["role"] in settings.mfa_required_roles,
            "needs_code": needs_setup_code(user),
        })

    @app.post("/account/security/2fa/start")
    async def start(request: Request, user=Depends(ctx.check_csrf)):
        uid = user["user_id"]
        with db.connect() as conn:
            row = load_user(conn, uid)
        if row["totp_enabled_at"]:
            return ctx.go("/account/security")
        # "Start over" from the session that already proved the setup code
        # does not need another code.
        if needs_setup_code(user) and not my_pending(row, user):
            setup_code = str((await request.form()).get("setup_code", ""))[:64]
            if account_blocked(uid):
                return too_many()
            with db.connect() as conn:
                ok = consume_setup_code(conn, settings.session_pepper, uid, setup_code)
            if not ok:
                audit(row, "mfa_failed", "stage:setup-code", request)
                return ctx.go("/account/security", error="That setup code is not right or has expired. "
                                                         "Ask your administrator for a new one.")
            ctx.rate.clear(account_key(uid))
        # The secret is only ever in the database and the page body, never a URL.
        with db.connect() as conn:
            conn.execute("UPDATE users SET totp_pending_enc = ?, totp_pending_session = ? WHERE id = ? AND totp_enabled_at IS NULL",
                         (cipher.encrypt(new_secret()), user["token_hash"], uid))
        return RedirectResponse("/account/security", status_code=303)

    def show_codes(request: Request, user, codes: list[str], heading: str):
        return ctx.render(request, "security_codes.html", {"user": user, "nav": "security", "codes": codes, "heading": heading})

    @app.post("/account/security/2fa/confirm")
    async def confirm(request: Request, user=Depends(ctx.check_csrf)):
        code = str((await request.form()).get("code", ""))[:64].strip().replace(" ", "")
        uid = user["user_id"]
        if account_blocked(uid):
            return too_many()
        with db.connect() as conn:
            row = load_user(conn, uid)
        if row["totp_enabled_at"] or not my_pending(row, user):
            return ctx.go("/account/security")
        step = matching_step(cipher.decrypt(row["totp_pending_enc"]), code)
        if step is None:
            audit(row, "mfa_failed", "stage:setup", request)
            return ctx.go("/account/security", error="That code is not right. Check the time on your phone and try the newest code.")
        with db.connect() as conn:
            # The WHERE makes a double-submitted form enable it once only.
            done = conn.execute(
                """UPDATE users SET totp_secret_enc = totp_pending_enc, totp_pending_enc = NULL,
                          totp_pending_session = NULL, totp_enabled_at = datetime('now'), totp_last_step = ?
                   WHERE id = ? AND totp_enabled_at IS NULL AND totp_pending_enc = ?""",
                (step, uid, row["totp_pending_enc"])).rowcount  # the key that was checked, not a newer one
            if not done:
                return ctx.go("/account/security")
            codes = replace_recovery_codes(conn, settings.session_pepper, uid)
            db.audit(conn, row["org_id"], uid, "mfa_enabled", ip=ctx.client_ip(request))
        ctx.rate.clear(account_key(uid))
        ctx.sessions.mark_mfa_set_up(uid)
        return show_codes(request, user, codes, "Two-factor sign-in is on")

    @app.post("/account/security/2fa/disable")
    async def disable(request: Request, user=Depends(ctx.check_csrf)):
        form = await request.form()
        password, code = str(form.get("password", ""))[:256], str(form.get("code", ""))[:64]
        uid = user["user_id"]
        if user["role"] in settings.mfa_required_roles:
            return ctx.go("/account/security", error="Your role requires two-factor sign-in, so it cannot be turned off.")
        if account_blocked(uid):
            return too_many()
        with db.connect() as conn:
            row = conn.execute("SELECT password_hash FROM users WHERE id = ?", (uid,)).fetchone()
            full = load_user(conn, uid)
        if not full["totp_enabled_at"]:
            return ctx.go("/account/security")
        # Password first, so a wrong password does not burn a recovery code.
        ok = verify_password(row["password_hash"], password) and check_code(full, code, allow_recovery=True)[0] == "ok"
        if not ok:
            audit(full, "mfa_failed", "stage:disable", request)
            return ctx.go("/account/security", error="The password or code is not right. Two-factor sign-in is still on.")
        with db.connect() as conn:
            clear_two_factor(conn, uid)
            db.audit(conn, full["org_id"], uid, "mfa_disabled", ip=ctx.client_ip(request))
        # Sessions signed in with the old factor should not outlive it.
        ctx.sessions.destroy_user(uid)
        resp = ctx.go("/login", notice="Two-factor sign-in is off. You were signed out everywhere; sign in again.")
        resp.delete_cookie(SESSION_COOKIE, path="/")
        return resp

    @app.post("/account/security/recovery-codes")
    async def regenerate(request: Request, user=Depends(ctx.check_csrf)):
        code = str((await request.form()).get("code", ""))[:64]
        uid = user["user_id"]
        if account_blocked(uid):
            return too_many()
        with db.connect() as conn:
            row = load_user(conn, uid)
        if not row["totp_enabled_at"]:
            return ctx.go("/account/security")
        result, _ = check_code(row, code, allow_recovery=False)
        if result != "ok":
            audit(row, "mfa_failed", "stage:recovery-codes", request)
            return ctx.go("/account/security", error=failure_message(result, recovery=False))
        with db.connect() as conn:
            codes = replace_recovery_codes(conn, settings.session_pepper, uid)
            db.audit(conn, row["org_id"], uid, "recovery_codes_regenerated", ip=ctx.client_ip(request))
        ctx.rate.clear(account_key(uid))
        return show_codes(request, user, codes, "New recovery codes")
