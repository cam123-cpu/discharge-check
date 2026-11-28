"""Two-factor sign-in: TOTP maths, enrolment, the second sign-in step,
recovery codes, turning it off, role policy and the admin reset."""
import base64
import dataclasses
import hashlib
import re
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import mfa
from app.main import create_app
from app.security import SESSION_COOKIE
from tests.conftest import PASSWORD, csrf_of, login

# ---------- RFC 6238 test vectors (Appendix B, SHA-1, 8 digits) ----------

RFC_SECRET = b"12345678901234567890"


@pytest.mark.parametrize("t, expected", [
    (59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
    (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130"),
])
def test_rfc6238_vectors(t, expected):
    assert mfa.hotp(RFC_SECRET, t // 30, digits=8, digest=hashlib.sha1) == expected
    b32 = base64.b32encode(RFC_SECRET).decode()
    assert mfa.totp_at(b32, t) == expected[-6:]


def test_secret_and_window():
    s = mfa.new_secret()
    assert len(base64.b32decode(s + "=" * (-len(s) % 8))) == 20
    now = 1_700_000_000
    assert mfa.matching_step(s, mfa.totp_at(s, now - 30), now) == mfa.step_at(now) - 1
    assert mfa.matching_step(s, mfa.totp_at(s, now + 30), now) == mfa.step_at(now) + 1
    assert mfa.matching_step(s, mfa.totp_at(s, now + 90), now) is None
    assert mfa.matching_step(s, "12345", now) is None and mfa.matching_step(s, "abcdef", now) is None


def test_recovery_code_format_and_normalisation():
    code = mfa.new_recovery_code()
    assert re.fullmatch(r"[23456789a-hjkmnp-z]{4}-[23456789a-hjkmnp-z]{4}-[23456789a-hjkmnp-z]{4}", code)
    assert mfa.recovery_hash("p", 1, code) == mfa.recovery_hash("p", 1, " " + code.upper().replace("-", " ") + " ")
    assert mfa.recovery_hash("p", 1, code) != mfa.recovery_hash("p", 2, code)
    assert mfa.recovery_hash("p", 1, code) != hashlib.sha256(code.encode()).hexdigest()


# ---------- helpers ----------

class Clock:
    def __init__(self, start=1_800_000_000.0):
        self.t = start

    def __call__(self):
        return self.t


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(mfa, "_clock", c)
    return c


def enrol(client, email="rn@a.test", setup_code=""):
    """Sign in, set up two-factor, return (secret, recovery codes)."""
    assert login(client, email).status_code == 303
    client.post("/account/security/2fa/start", data={"csrf": csrf_of(client, "/account/security"), "setup_code": setup_code})
    page = client.get("/account/security").text
    secret = re.search(r'class="secret mono">([A-Z2-7 ]+)<', page).group(1).replace(" ", "")
    assert "otpauth://totp/" in page and "data:image/svg+xml" in page
    r = client.post("/account/security/2fa/confirm",
                    data={"csrf": csrf_of(client, "/account/security"), "code": mfa.totp_at(secret, mfa._clock())})
    assert r.status_code == 200 and "shown only once" in r.text
    codes = re.findall(r"<li>([a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})</li>", r.text)
    assert len(codes) == 10
    client.cookies.clear()
    return secret, codes


def second_step(client, code):
    page = client.get("/login/2fa", follow_redirects=False)
    assert page.status_code == 200, page.headers
    token = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    return client.post("/login/2fa", data={"code": code, "csrf": token}, follow_redirects=False)


def audit_actions(app):
    with app.state.db.connect() as conn:
        return [r[0] for r in conn.execute("SELECT action FROM audit_log ORDER BY id")]


# ---------- enrolment and sign-in ----------

def test_enrol_then_sign_in_with_totp(app, client, clock):
    secret, _ = enrol(client)
    assert "mfa_enabled" in audit_actions(app)
    r = login(client, "rn@a.test")
    assert r.headers["location"] == "/login/2fa" and SESSION_COOKIE not in r.cookies
    clock.t += 30
    r = second_step(client, mfa.totp_at(secret, clock.t))
    assert r.status_code == 303 and r.headers["location"] == "/patients"
    assert client.get("/patients").status_code == 200
    with app.state.db.connect() as conn:
        assert conn.execute("SELECT auth_method FROM sessions").fetchone()[0] == "password+totp"
    assert "Security" in client.get("/patients").text


def test_setup_page_never_puts_secret_in_url(client, clock):
    login(client, "rn@a.test")
    r = client.post("/account/security/2fa/start", data={"csrf": csrf_of(client, "/account/security")},
                    follow_redirects=False)
    assert r.headers["location"] == "/account/security"
    page = client.get("/account/security").text
    assert 'style="' not in page and "<script>" not in page


def test_wrong_code_at_setup_keeps_it_off(app, client, clock):
    login(client, "rn@a.test")
    client.post("/account/security/2fa/start", data={"csrf": csrf_of(client, "/account/security")})
    r = client.post("/account/security/2fa/confirm", data={"csrf": csrf_of(client, "/account/security"), "code": "000000"})
    assert "not right" in r.text
    with app.state.db.connect() as conn:
        assert conn.execute("SELECT totp_enabled_at FROM users WHERE email = 'rn@a.test'").fetchone()[0] is None


def test_replayed_code_is_rejected(app, client, clock):
    secret, _ = enrol(client)
    clock.t += 30
    code = mfa.totp_at(secret, clock.t)
    login(client, "rn@a.test")
    assert second_step(client, code).headers["location"] == "/patients"
    client.cookies.clear()
    login(client, "rn@a.test")
    r = second_step(client, code)
    assert r.headers["location"] == "/login/2fa"
    assert "already used" in client.get("/login/2fa").text
    assert "mfa_failed" in audit_actions(app)


def test_wrong_codes_end_the_pending_sign_in(client, clock):
    enrol(client)
    login(client, "rn@a.test")
    for _ in range(5):
        r = second_step(client, "000000")
        assert r.headers["location"] == "/login/2fa"
    r = client.get("/login/2fa", follow_redirects=False)
    assert r.headers["location"] == "/login"


def test_per_account_limit_spans_fresh_pending_sign_ins(client, clock):
    secret, _ = enrol(client)
    login(client, "rn@a.test")
    for _ in range(3):
        second_step(client, "000000")
    login(client, "rn@a.test")
    for _ in range(2):
        second_step(client, "000000")
    login(client, "rn@a.test")
    clock.t += 30
    r = second_step(client, mfa.totp_at(secret, clock.t))
    assert r.headers["location"] == "/login" and SESSION_COOKIE not in r.cookies


def test_csrf_on_second_step_is_required(client, clock):
    secret, _ = enrol(client)
    login(client, "rn@a.test")
    clock.t += 30
    r = client.post("/login/2fa", data={"code": mfa.totp_at(secret, clock.t), "csrf": "x"}, follow_redirects=False)
    assert r.headers["location"] == "/login/2fa" and SESSION_COOKIE not in r.cookies
    r = client.post("/login/2fa", data={"code": mfa.totp_at(secret, clock.t)}, follow_redirects=False)
    assert SESSION_COOKIE not in r.cookies


def test_no_pending_cookie_goes_back_to_login(client):
    r = client.get("/login/2fa", follow_redirects=False)
    assert r.headers["location"] == "/login"
    r = client.post("/login/2fa", data={"code": "123456", "csrf": "x"}, follow_redirects=False)
    assert r.headers["location"] == "/login"


def test_pending_token_is_not_a_session(client, clock):
    enrol(client)
    login(client, "rn@a.test")
    pending = client.cookies.get("dc_mfa")
    assert pending
    for path in ("/patients", "/account/security", "/rules"):
        assert client.get(path, follow_redirects=False).headers["location"] == "/login"
    client.cookies.set(SESSION_COOKIE, pending)
    assert client.get("/patients", follow_redirects=False).headers["location"] == "/login"
    assert client.get("/api/compliance/summary").status_code == 401


def test_pending_sign_in_expires(app, client, clock):
    enrol(client)
    login(client, "rn@a.test")
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    with app.state.db.connect() as conn:
        conn.execute("UPDATE pending_logins SET expires_at = ?", (past,))
    clock.t += 30
    page = client.get("/login/2fa", follow_redirects=False)
    assert page.headers["location"] == "/login"


def test_recovery_code_works_once(app, client, clock):
    _, codes = enrol(client)
    login(client, "rn@a.test")
    r = second_step(client, codes[0].upper().replace("-", " "))
    assert r.headers["location"] == "/patients"
    assert "9 of 10" in client.get("/patients").text
    assert "recovery_code_used" in audit_actions(app)
    with app.state.db.connect() as conn:
        assert conn.execute("SELECT auth_method FROM sessions").fetchone()[0] == "password+recovery"
        assert codes[0] not in str([tuple(r) for r in conn.execute("SELECT code_hash FROM recovery_codes")])
    client.cookies.clear()
    login(client, "rn@a.test")
    assert second_step(client, codes[0]).headers["location"] == "/login/2fa"
    assert second_step(client, codes[1]).headers["location"] == "/patients"


def test_regenerate_recovery_codes_needs_totp(app, client, clock):
    secret, codes = enrol(client)
    login(client, "rn@a.test")
    clock.t += 30
    second_step(client, mfa.totp_at(secret, clock.t))
    r = client.post("/account/security/recovery-codes", data={"csrf": csrf_of(client, "/account/security"), "code": codes[0]})
    assert "shown only once" not in r.text
    clock.t += 30
    r = client.post("/account/security/recovery-codes",
                    data={"csrf": csrf_of(client, "/account/security"), "code": mfa.totp_at(secret, clock.t)})
    new = re.findall(r"<li>([a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})</li>", r.text)
    assert len(new) == 10 and not set(new) & set(codes)
    assert "recovery_codes_regenerated" in audit_actions(app)
    client.cookies.clear()
    login(client, "rn@a.test")
    assert second_step(client, codes[1]).headers["location"] == "/login/2fa"
    assert second_step(client, new[0]).headers["location"] == "/patients"


def test_disable_needs_password_and_code_and_ends_sessions(app, client, clock):
    secret, codes = enrol(client)
    other = TestClient(app)
    login(other, "rn@a.test")
    clock.t += 30
    second_step(other, mfa.totp_at(secret, clock.t))
    assert other.get("/patients").status_code == 200

    login(client, "rn@a.test")
    second_step(client, codes[0])
    csrf = csrf_of(client, "/account/security")
    clock.t += 30
    r = client.post("/account/security/2fa/disable", data={"csrf": csrf, "password": "wrong", "code": mfa.totp_at(secret, clock.t)},
                    follow_redirects=False)
    assert r.headers["location"] == "/account/security"
    r = client.post("/account/security/2fa/disable", data={"csrf": csrf, "password": PASSWORD, "code": "000000"},
                    follow_redirects=False)
    assert r.headers["location"] == "/account/security"
    r = client.post("/account/security/2fa/disable", data={"csrf": csrf, "password": PASSWORD, "code": mfa.totp_at(secret, clock.t)},
                    follow_redirects=False)
    assert r.headers["location"] == "/login"
    assert "mfa_disabled" in audit_actions(app)
    assert other.get("/patients", follow_redirects=False).headers["location"] == "/login"
    with app.state.db.connect() as conn:
        row = conn.execute("SELECT totp_secret_enc, totp_enabled_at FROM users WHERE email = 'rn@a.test'").fetchone()
        assert tuple(row) == (None, None)
        assert conn.execute("SELECT COUNT(*) FROM recovery_codes").fetchone()[0] == 0
    client.cookies.clear()
    assert login(client, "rn@a.test").headers["location"] == "/patients"


# ---------- role policy ----------

def test_required_role_must_set_up_and_cannot_disable(settings, clock):
    app = create_app(dataclasses.replace(settings, mfa_required_roles=("nurse",)))
    from tests.conftest import hash_password
    with app.state.db.connect() as conn:
        org = conn.execute("INSERT INTO orgs (name) VALUES ('Org A')").lastrowid
        conn.execute("INSERT INTO users (org_id, email, display_name, role, password_hash) VALUES (?, 'rn@a.test', 'rn', 'nurse', ?)",
                     (org, hash_password(PASSWORD)))
    client = TestClient(app)
    r = login(client, "rn@a.test")
    assert r.headers["location"] == "/account/security"
    assert client.get("/patients", follow_redirects=False).headers["location"] == "/account/security"
    assert client.get("/account/security").status_code == 200
    client.cookies.clear()
    secret, _ = enrol(client, setup_code=_issue(app))  # setup is reachable while locked out of everything else
    login(client, "rn@a.test")
    clock.t += 30
    assert second_step(client, mfa.totp_at(secret, clock.t)).headers["location"] == "/patients"
    assert client.get("/patients").status_code == 200
    page = client.get("/account/security").text
    assert "cannot be turned off" in page and "2fa/disable" not in page
    clock.t += 30
    r = client.post("/account/security/2fa/disable", data={"csrf": csrf_of(client, "/account/security"), "password": PASSWORD,
                                                         "code": mfa.totp_at(secret, clock.t)}, follow_redirects=False)
    assert r.headers["location"] == "/account/security"
    with app.state.db.connect() as conn:
        assert conn.execute("SELECT totp_enabled_at FROM users").fetchone()[0] is not None


def test_session_unlocks_right_after_setup(settings, clock):
    app = create_app(dataclasses.replace(settings, mfa_required_roles=("nurse",)))
    from tests.conftest import hash_password
    with app.state.db.connect() as conn:
        org = conn.execute("INSERT INTO orgs (name) VALUES ('Org A')").lastrowid
        conn.execute("INSERT INTO users (org_id, email, display_name, role, password_hash) VALUES (?, 'rn@a.test', 'rn', 'nurse', ?)",
                     (org, hash_password(PASSWORD)))
    client = TestClient(app)
    login(client, "rn@a.test")
    client.post("/account/security/2fa/start", data={"csrf": csrf_of(client, "/account/security"), "setup_code": _issue(app)})
    secret = re.search(r'class="secret mono">([A-Z2-7 ]+)<', client.get("/account/security").text).group(1).replace(" ", "")
    client.post("/account/security/2fa/confirm", data={"csrf": csrf_of(client, "/account/security"), "code": mfa.totp_at(secret, clock.t)})
    assert client.get("/patients", follow_redirects=False).status_code == 200


# ---------- admin reset ----------

def test_setup_reset_2fa(app, client, clock, capsys):
    from scripts.setup import reset_2fa
    enrol(client)
    login(client, "rn@a.test")
    assert client.cookies.get("dc_mfa")
    assert reset_2fa("RN@a.test", app.state.db) is True
    assert reset_2fa("nobody@a.test", app.state.db) is False
    with app.state.db.connect() as conn:
        assert conn.execute("SELECT totp_enabled_at FROM users WHERE email = 'rn@a.test'").fetchone()[0] is None
        assert conn.execute("SELECT COUNT(*) FROM recovery_codes").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM pending_logins").fetchone()[0] == 0
    assert "mfa_reset" in audit_actions(app)
    assert client.get("/login/2fa", follow_redirects=False).headers["location"] == "/login"
    client.cookies.clear()
    assert login(client, "rn@a.test").headers["location"] == "/patients"


def test_real_clock_is_used_by_default():
    assert abs(mfa._clock() - time.time()) < 5


def test_code_used_at_setup_cannot_sign_in(client, clock):
    secret, _ = enrol(client)
    login(client, "rn@a.test")
    assert second_step(client, mfa.totp_at(secret, clock.t)).headers["location"] == "/login/2fa"


# ---------- regressions from the security review ----------

def _enrol_secret(client):
    assert login(client, "rn@a.test").status_code == 303
    client.post("/account/security/2fa/start", data={"csrf": csrf_of(client, "/account/security")})
    page = client.get("/account/security").text
    secret = re.search(r'class="secret mono">([A-Z2-7 ]+)<', page).group(1).replace(" ", "")
    r = client.post("/account/security/2fa/confirm",
                    data={"csrf": csrf_of(client, "/account/security"), "code": mfa.totp_at(secret, mfa._clock())})
    assert r.status_code == 200
    client.cookies.clear()
    return secret


def test_parallel_guesses_are_all_counted(app, clock, monkeypatch):
    """The limit was checked before failures were recorded, so 20 parallel
    guesses on one pending sign-in were all checked against a limit of 5."""
    import threading
    _enrol_secret(TestClient(app))
    clock.t += 300
    c = TestClient(app)
    assert login(c, "rn@a.test").headers["location"] == "/login/2fa"
    tok = re.search(r'name="csrf" value="([^"]+)"', c.get("/login/2fa").text).group(1)
    pending_cookie = c.cookies.get("dc_mfa")
    n, reached = 20, []
    barrier = threading.Barrier(n, timeout=3)
    orig = mfa.matching_step

    def slow(s, code, now=None):
        reached.append(code)
        try:
            barrier.wait()
        except threading.BrokenBarrierError:
            pass
        return orig(s, code, now)
    monkeypatch.setattr(mfa, "matching_step", slow)

    def guess(i):
        cl = TestClient(app)
        cl.cookies.set("dc_mfa", pending_cookie)
        cl.post("/login/2fa", data={"code": f"{i:06d}", "csrf": tok}, follow_redirects=False)
    threads = [threading.Thread(target=guess, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(reached) <= app.state.settings.mfa_max_attempts


def test_confirm_stores_only_the_key_that_was_checked(app, clock, monkeypatch):
    """'Start over' in a second tab between checking the code and saving used
    to enable a key the person never scanned, locking them out."""
    c = TestClient(app)
    assert login(c, "rn@a.test").status_code == 303
    csrf = csrf_of(c, "/account/security")
    c.post("/account/security/2fa/start", data={"csrf": csrf})
    secret_a = re.search(r'class="secret mono">([A-Z2-7 ]+)<', c.get("/account/security").text).group(1).replace(" ", "")
    orig = mfa.matching_step

    def interleave(s, code, now=None):
        monkeypatch.setattr(mfa, "matching_step", orig)
        c2 = TestClient(app)
        c2.cookies.update(c.cookies)
        c2.post("/account/security/2fa/start", data={"csrf": csrf})
        return orig(s, code, now)
    monkeypatch.setattr(mfa, "matching_step", interleave)
    c.post("/account/security/2fa/confirm", data={"csrf": csrf, "code": mfa.totp_at(secret_a, clock.t)})
    with app.state.db.connect() as conn:
        row = conn.execute("SELECT totp_enabled_at FROM users WHERE email = 'rn@a.test'").fetchone()
    assert row["totp_enabled_at"] is None  # not enabled with the unseen key


def test_required_role_applies_to_sessions_already_open(app, settings):
    """The policy was fixed at sign-in, so adding a role to MFA_REQUIRED_ROLES
    left open sessions with full access."""
    c = TestClient(app)
    assert login(c, "rn@a.test").headers["location"] == "/patients"
    object.__setattr__(app.state.settings, "mfa_required_roles", ("nurse",))
    try:
        r = c.get("/patients", follow_redirects=False)
        assert r.headers["location"] == "/account/security"
        assert c.get("/account/security-x", follow_redirects=False).status_code in (303, 404)
    finally:
        object.__setattr__(app.state.settings, "mfa_required_roles", ())


# ---------- administrator-issued setup code (roles that require two-factor) ----------

def _issue(app, email="rn@a.test"):
    from scripts.setup import issue_2fa_code
    return issue_2fa_code(email, app.state.db, app.state.settings)


@pytest.fixture
def required_app(settings):
    app = create_app(dataclasses.replace(settings, mfa_required_roles=("nurse",)))
    from tests.conftest import hash_password
    with app.state.db.connect() as conn:
        org = conn.execute("INSERT INTO orgs (name) VALUES ('Org A')").lastrowid
        conn.execute("INSERT INTO users (org_id, email, display_name, role, password_hash) VALUES (?, 'rn@a.test', 'rn', 'nurse', ?)",
                     (org, hash_password(PASSWORD)))
    return app


def _start(client, code=""):
    return client.post("/account/security/2fa/start",
                       data={"csrf": csrf_of(client, "/account/security"), "setup_code": code}, follow_redirects=True)


def _pending_secret(client):
    m = re.search(r'class="secret mono">([A-Z2-7 ]+)<', client.get("/account/security").text)
    return m.group(1).replace(" ", "") if m else None


def test_required_role_cannot_set_up_with_only_a_password(required_app, clock):
    """Someone with a stolen password could enrol their own authenticator
    before the real owner, then hold the account."""
    c = TestClient(required_app)
    login(c, "rn@a.test")
    assert "Setup code from your administrator" in c.get("/account/security").text
    assert "setup code is not right" in _start(c).text
    assert "setup code is not right" in _start(c, "aaaa-bbbb-cccc").text
    assert _pending_secret(c) is None
    with required_app.state.db.connect() as conn:
        assert conn.execute("SELECT totp_pending_enc FROM users").fetchone()[0] is None


def test_setup_code_is_single_use_and_expires(required_app, clock):
    code = _issue(required_app)
    c = TestClient(required_app)
    login(c, "rn@a.test")
    _start(c, code.upper().replace("-", " "))  # typed loosely still works
    first = _pending_secret(c)
    assert first
    _start(c)  # "start over" from the same session needs no new code
    assert _pending_secret(c) not in (None, first)
    c2 = TestClient(required_app)
    login(c2, "rn@a.test")  # a new sign-in: the code was used already
    assert "setup code is not right" in _start(c2, code).text
    expired = _issue(required_app)
    with required_app.state.db.connect() as conn:
        conn.execute("UPDATE users SET mfa_setup_code_expires = '2000-01-01T00:00:00+00:00'")
    assert "setup code is not right" in _start(c2, expired).text


def test_new_setup_code_replaces_the_old_one(required_app, clock):
    old = _issue(required_app)
    new = _issue(required_app)
    c = TestClient(required_app)
    login(c, "rn@a.test")
    assert "setup code is not right" in _start(c, old).text
    _start(c, new)
    assert _pending_secret(c)


def test_pending_key_is_hidden_from_a_second_sign_in(required_app, clock):
    """The owner is mid-setup; someone signs in with the stolen password. They
    must not see or confirm the key the owner is scanning."""
    owner = TestClient(required_app)
    login(owner, "rn@a.test")
    _start(owner, _issue(required_app))
    secret = _pending_secret(owner)
    thief = TestClient(required_app)
    login(thief, "rn@a.test")
    page = thief.get("/account/security").text
    assert secret.lower() not in page.lower().replace(" ", "") and _pending_secret(thief) is None
    r = thief.post("/account/security/2fa/confirm", data={"csrf": csrf_of(thief, "/account/security"),
                                                         "code": mfa.totp_at(secret, clock.t)}, follow_redirects=False)
    assert r.headers["location"] == "/account/security"
    with required_app.state.db.connect() as conn:
        assert conn.execute("SELECT totp_enabled_at FROM users").fetchone()[0] is None
    assert "setup code is not right" in _start(thief).text


def test_setup_code_guesses_are_limited(required_app, clock):
    code = _issue(required_app)
    c = TestClient(required_app)
    login(c, "rn@a.test")
    for _ in range(required_app.state.settings.mfa_max_attempts):
        _start(c, "wrong-code-xx")
    assert "Too many wrong attempts" in _start(c, code).text


def test_optional_users_need_no_setup_code(client, clock):
    secret, _ = enrol(client)
    assert secret


def test_cli_issue_2fa_code(required_app, settings, monkeypatch, capsys):
    from scripts import setup
    monkeypatch.setenv("DATA_KEY", settings.data_key)
    monkeypatch.setenv("SESSION_PEPPER", settings.session_pepper)
    monkeypatch.setenv("DATABASE_PATH", str(settings.database_path))
    code = setup.issue_2fa_code("RN@a.test")
    assert re.fullmatch(r"[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", code)
    assert setup.issue_2fa_code("nobody@a.test") is None
    with required_app.state.db.connect() as conn:
        row = conn.execute("SELECT mfa_setup_code_hash FROM users").fetchone()
        assert row[0] and code not in row[0]  # only a keyed hash is stored
        assert conn.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'mfa_setup_code_issued'").fetchone()[0] == 1
