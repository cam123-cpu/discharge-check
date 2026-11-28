"""Hospital SSO against a fake OIDC IdP served in-process through the injected
transport: no network."""
from __future__ import annotations

import base64
import hashlib
import html
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app import sso
from app.security import SESSION_COOKIE, verify_password
from tests.conftest import PASSWORD, login

ISSUER = "https://idp.test/tenant"
CLIENT_ID = "dc-client"
SECRET = "s3cret: with/odd chars"


class FakeIdP:
    """Discovery, JWKS, token and userinfo endpoints behind the Transport interface."""

    def __init__(self, issuer: str = ISSUER):
        self.issuer = issuer
        self.keys: dict[str, rsa.RSAPrivateKey] = {}
        self.published: list[str] = []
        self.add_key("k1")
        self.signing_kid = "k1"
        self.codes: dict[str, dict] = {}
        self.calls: list[str] = []
        self.discovery_overrides: dict = {}
        self.token_override = None  # callable(claims) -> str

    def add_key(self, kid: str, publish: bool = True):
        self.keys[kid] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if publish:
            self.published.append(kid)

    def jwks(self) -> dict:
        out = []
        for kid in self.published:
            jwk = jwt.algorithms.RSAAlgorithm.to_jwk(self.keys[kid].public_key(), as_dict=True)
            out.append({**jwk, "kid": kid, "use": "sig", "alg": "RS256"})
        return {"keys": out}

    # -- Transport

    def get_json(self, url, headers=None):
        self.calls.append("GET " + url)
        if url == self.issuer + "/.well-known/openid-configuration":
            return {"issuer": self.issuer, "authorization_endpoint": self.issuer + "/authorize",
                    "token_endpoint": self.issuer + "/token", "jwks_uri": self.issuer + "/jwks",
                    "userinfo_endpoint": self.issuer + "/userinfo",
                    "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
                    **self.discovery_overrides}
        if url == self.issuer + "/jwks":
            return self.jwks()
        raise sso.TransportError(f"fake idp: no route {url}")

    def post_form(self, url, data, headers=None):
        self.calls.append("POST " + url)
        assert url == self.issuer + "/token"
        user, _, pw = base64.b64decode(headers["Authorization"].split()[1]).decode().partition(":")
        from urllib.parse import unquote
        if (unquote(user), unquote(pw)) != (CLIENT_ID, SECRET):
            raise sso.TransportError("fake idp: HTTP 401 invalid_client")
        grant = self.codes.pop(data["code"], None)
        if grant is None or data["redirect_uri"] != grant["redirect_uri"]:
            raise sso.TransportError("fake idp: HTTP 400 invalid_grant")
        challenge = base64.urlsafe_b64encode(hashlib.sha256(data["code_verifier"].encode()).digest()).rstrip(b"=")
        if challenge.decode() != grant["challenge"]:
            raise sso.TransportError("fake idp: HTTP 400 invalid_grant (pkce)")
        claims = grant["claims"]
        token = self.token_override(claims) if self.token_override else self.sign(claims)
        return {"id_token": token, "access_token": "at-" + secrets.token_hex(4), "token_type": "Bearer"}

    # -- helpers

    def sign(self, claims: dict, kid: str | None = None, key=None) -> str:
        kid = kid or self.signing_kid
        return jwt.encode(claims, key or self.keys[kid], algorithm="RS256", headers={"kid": kid})

    def authorize(self, auth_url: str, **overrides) -> tuple[str, str]:
        """What the IdP does after the user signs in: returns (code, state)."""
        q = {k: v[0] for k, v in parse_qs(urlsplit(auth_url).query).items()}
        assert q["code_challenge_method"] == "S256" and q["client_id"] == CLIENT_ID
        now = int(time.time())
        claims = {"iss": self.issuer, "aud": CLIENT_ID, "sub": "sub-rn", "email": "rn@a.test", "email_verified": True,
                  "name": "Rae Nurse", "nonce": q["nonce"], "iat": now, "exp": now + 300}
        claims.update(overrides)
        claims = {k: v for k, v in claims.items() if v is not None}
        code = secrets.token_urlsafe(16)
        self.codes[code] = {"claims": claims, "challenge": q["code_challenge"], "redirect_uri": q["redirect_uri"]}
        return code, q["state"]


@pytest.fixture
def idp(app):
    fake = FakeIdP()
    app.state.sso_transport = fake
    return fake


def add_provider(app, org="Org A", slug="a-idp", domains="a.test", protocol="oidc", issuer=ISSUER, **flags) -> int:
    ctx = app.state.auth
    with app.state.db.connect() as conn:
        org_id = conn.execute("SELECT id FROM orgs WHERE name = ?", (org,)).fetchone()[0]
        return conn.execute(
            "INSERT INTO sso_providers (org_id, slug, display_name, protocol, issuer, client_id, client_secret_enc,"
            " email_domains, default_role, auto_provision, enforce, enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (org_id, slug, "Org A SSO", protocol, issuer, CLIENT_ID, ctx.cipher.encrypt(SECRET), domains,
             flags.get("default_role", ""), int(flags.get("auto_provision", False)), int(flags.get("enforce", False)),
             int(flags.get("enabled", True)))).lastrowid


def pre_token(client) -> str:
    return re.search(r'name="pre" value="([^"]+)"', client.get("/login").text).group(1)


def start(client, email="rn@a.test") -> str:
    r = client.post("/sso/start", data={"email": email, "pre": pre_token(client)}, follow_redirects=False)
    assert r.status_code == 200, r.text
    return html.unescape(re.search(r'http-equiv="refresh" content="0;url=([^"]+)"', r.text).group(1))


def callback(client, code, state):
    return client.get("/sso/callback", params={"code": code, "state": state}, follow_redirects=False)


def is_signed_in(client) -> bool:
    return client.get("/patients", follow_redirects=False).status_code == 200


def audits(app, action):
    with app.state.db.connect() as conn:
        return conn.execute("SELECT * FROM audit_log WHERE action = ?", (action,)).fetchall()


def sso_flow(client, idp, start_email="rn@a.test", **claims):
    url = start(client, start_email)
    code, state = idp.authorize(url, **claims)
    return callback(client, code, state)


# ------------------------------------------------------------------ happy path


def test_happy_path_end_to_end(app, client, idp):
    add_provider(app)  # (an account with two-factor on is covered in test_cli_link)
    url = start(client)
    parts = urlsplit(url)
    q = {k: v[0] for k, v in parse_qs(parts.query).items()}
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == ISSUER + "/authorize"
    assert q["response_type"] == "code" and q["code_challenge_method"] == "S256"
    assert len(q["code_challenge"]) == 43 and q["state"] and q["nonce"] and q["state"] != q["nonce"]
    assert q["redirect_uri"] == "http://localhost:8000/sso/callback" and "openid" in q["scope"].split()
    assert q["login_hint"] == "rn@a.test"
    with app.state.db.connect() as conn:  # only a keyed hash of the state is stored
        row = conn.execute("SELECT * FROM sso_states").fetchone()
    assert row["state_hash"] != q["state"] and q["state"] not in row["state_hash"]

    code, state = idp.authorize(url)
    r = callback(client, code, state)
    assert r.status_code == 200 and 'content="0;url=/patients"' in r.text
    assert SESSION_COOKIE in r.headers.get("set-cookie", "")
    assert is_signed_in(client)
    with app.state.db.connect() as conn:
        s = conn.execute("SELECT s.auth_method FROM sessions s JOIN users u ON u.id = s.user_id"
                         " WHERE u.email = 'rn@a.test'").fetchone()
        assert s["auth_method"] == "sso"
        assert conn.execute("SELECT COUNT(*) FROM sso_states").fetchone()[0] == 0
    assert audits(app, "sso_linked") and audits(app, "sso_login")
    assert audits(app, "login")[-1]["target"] == "provider:a-idp"


def test_slug_start_redirects_to_idp(app, client, idp):
    add_provider(app)
    r = client.get("/sso/a-idp/start", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith(ISSUER + "/authorize?")
    assert "samesite=lax" in r.headers["set-cookie"].lower() and "httponly" in r.headers["set-cookie"].lower()
    code, state = idp.authorize(r.headers["location"])
    assert callback(client, code, state).status_code == 200 and is_signed_in(client)
    assert client.get("/sso/nope/start", follow_redirects=False).status_code == 404


def test_start_needs_pre_token_and_known_domain(app, client, idp):
    add_provider(app)
    client.get("/login")
    r = client.post("/sso/start", data={"email": "rn@a.test", "pre": "forged"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    r = client.post("/sso/start", data={"email": "x@unknown.test", "pre": pre_token(client)}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    # Domain match is exact: a look-alike subdomain does not match.
    r = client.post("/sso/start", data={"email": "x@evil.a.test", "pre": pre_token(client)}, follow_redirects=False)
    assert r.status_code == 303
    assert start(client, "RN@A.TEST")  # case-insensitive


def test_start_is_rate_limited(app, client, idp):
    add_provider(app)
    for _ in range(30):
        assert client.get("/sso/a-idp/start", follow_redirects=False).status_code == 303
    assert client.get("/sso/a-idp/start", follow_redirects=False).status_code == 429


# ------------------------------------------------------------------ state handling


def test_state_reuse_rejected(app, client, idp):
    add_provider(app)
    url = start(client)
    code, state = idp.authorize(url)
    assert callback(client, code, state).status_code == 200
    client.cookies.clear()
    code2, _ = idp.authorize(url)
    r = callback(client, code2, state)
    assert r.status_code == 400 and "expired or was already used" in r.text
    assert not is_signed_in(client)


def test_wrong_browser_rejected_and_state_burnt(app, client, idp):
    add_provider(app)
    url = start(client)
    code, state = idp.authorize(url)
    other = TestClient(app)
    r = callback(other, code, state)
    assert r.status_code == 400 and "different browser" in r.text
    assert not is_signed_in(other)
    # The legitimate browser cannot use it afterwards either: single use.
    assert "already used" in callback(client, code, state).text


def test_expired_state_rejected(app, client, idp):
    add_provider(app)
    url = start(client)
    with app.state.db.connect() as conn:
        conn.execute("UPDATE sso_states SET expires_at = ?",
                     ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),))
    code, state = idp.authorize(url)
    r = callback(client, code, state)
    assert r.status_code == 400 and "expired" in r.text and not is_signed_in(client)


def test_idp_error_param_handled(app, client, idp):
    add_provider(app)
    url = start(client)
    _, state = idp.authorize(url)
    r = client.get("/sso/callback", params={"state": state, "error": "access_denied",
                                            "error_description": "<script>alert(1)</script> call 555-0100"},
                   follow_redirects=False)
    assert r.status_code == 400 and "cancelled or refused" in r.text
    assert "555-0100" not in r.text and "<script>alert" not in r.text and "access_denied" not in r.text
    assert audits(app, "sso_failed")[-1]["target"] == "provider:a-idp idp_error"
    with app.state.db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM sso_states").fetchone()[0] == 0
    assert client.get("/sso/callback", follow_redirects=False).status_code == 400


# ------------------------------------------------------------------ ID token checks


def _refused(app, client, idp, **claims):
    r = sso_flow(client, idp, **claims)
    assert r.status_code == 400, r.text
    assert not is_signed_in(client)
    return r


def test_bad_signature_rejected(app, client, idp):
    add_provider(app)
    forger = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    idp.token_override = lambda c: idp.sign(c, kid="k1", key=forger)
    r = _refused(app, client, idp)
    assert "did not complete" in r.text and "Signature" not in r.text


@pytest.mark.parametrize("claims", [
    {"aud": "someone-else"},
    {"aud": [CLIENT_ID, "other"]},  # several audiences and no azp
    {"azp": "other-client"},
    {"iss": "https://evil.test/tenant"},
    {"nonce": "not-the-nonce"},
    {"nonce": None},
    {"exp": int(time.time()) - 3600},
    {"iat": int(time.time()) - 7200, "exp": int(time.time()) + 300},
    {"sub": None},
])
def test_claim_checks(app, client, idp, claims):
    add_provider(app)
    _refused(app, client, idp, **claims)


def test_alg_none_rejected(app, client, idp):
    add_provider(app)
    idp.token_override = lambda c: jwt.encode(c, None, algorithm="none")
    _refused(app, client, idp)


@pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning")
def test_hs256_with_client_secret_rejected(app, client, idp):
    add_provider(app)
    idp.token_override = lambda c: jwt.encode(c, SECRET, algorithm="HS256", headers={"kid": "k1"})
    _refused(app, client, idp)


def test_email_not_verified_rejected(app, client, idp):
    add_provider(app)
    r = _refused(app, client, idp, email_verified=False)
    assert "verified email" in r.text
    _refused(app, client, idp, email_verified=None)


def test_unknown_kid_triggers_one_jwks_refresh(app, client, idp):
    add_provider(app)
    assert sso_flow(client, idp).status_code == 200  # JWKS fetched and cached
    jwks_calls = lambda: sum(c == f"GET {ISSUER}/jwks" for c in idp.calls)
    assert jwks_calls() == 1
    app.state.sso_cache.jwks_refresh_cooldown = 0
    idp.add_key("k2")  # key rotation
    idp.signing_kid = "k2"
    client.cookies.clear()
    assert sso_flow(client, idp).status_code == 200
    assert jwks_calls() == 2
    # A kid the IdP never published: exactly one refetch, then refusal.
    idp.add_key("ghost", publish=False)
    idp.signing_kid = "ghost"
    client.cookies.clear()
    _refused(app, client, idp)
    assert jwks_calls() == 3
    # Within the cooldown, made-up kids do not trigger more refetches.
    app.state.sso_cache.jwks_refresh_cooldown = 60
    _refused(app, client, idp)
    assert jwks_calls() == 3


def test_discovery_is_cached(app, client, idp):
    add_provider(app)
    sso_flow(client, idp)
    client.cookies.clear()
    sso_flow(client, idp)
    assert sum("openid-configuration" in c for c in idp.calls) == 1


def test_discovery_issuer_must_match(app, client, idp):
    add_provider(app)
    idp.discovery_overrides = {"issuer": "https://idp.test/other"}
    r = client.post("/sso/start", data={"email": "rn@a.test", "pre": pre_token(client)}, follow_redirects=False)
    assert r.status_code == 502 and "did not complete" in r.text


def test_http_issuer_refused_except_localhost():
    cache = sso.MetadataCache()
    with pytest.raises(sso.SSOError):
        sso.OIDCProvider(sso.ProviderConfig("x", "oidc", "http://idp.test", "c"), FakeIdP(), cache)
    sso.OIDCProvider(sso.ProviderConfig("x", "oidc", "http://localhost:8080/realms/dev", "c"), FakeIdP(), cache)


def test_client_secret_post_when_basic_unsupported(app, client, idp):
    add_provider(app)
    idp.discovery_overrides = {"token_endpoint_auth_methods_supported": ["client_secret_post"]}
    seen = {}
    orig = idp.post_form

    def post_form(url, data, headers=None):
        seen.update(data=dict(data), headers=dict(headers or {}))
        creds = base64.b64encode(f"{CLIENT_ID}:{SECRET}".encode()).decode()
        return orig(url, {k: v for k, v in data.items() if k != "client_secret"}, {"Authorization": "Basic " + creds})

    idp.post_form = post_form
    assert sso_flow(client, idp).status_code == 200
    assert seen["data"]["client_secret"] == SECRET and "Authorization" not in seen["headers"]


# ------------------------------------------------------------------ account mapping


def test_links_existing_user_by_email_then_by_subject(app, client, idp):
    add_provider(app)
    assert sso_flow(client, idp, sub="stable-1").status_code == 200
    with app.state.db.connect() as conn:
        link = conn.execute("SELECT u.email FROM sso_identities i JOIN users u ON u.id = i.user_id"
                            " WHERE i.subject = 'stable-1'").fetchone()
    assert link["email"] == "rn@a.test"
    client.cookies.clear()
    # Later sign-ins match on the subject even if the IdP's email changes.
    assert sso_flow(client, idp, sub="stable-1", email="rae.nurse@a.test").status_code == 200
    assert len(audits(app, "sso_linked")) == 1
    # A different subject claiming the same email is not silently re-linked.
    client.cookies.clear()
    _refused(app, client, idp, sub="intruder")


def test_refuses_user_from_another_org(app, client, idp):
    # Misconfigured: Org A's provider also claims b.test, where doc@b.test is an Org B user.
    add_provider(app, domains="a.test,b.test")
    r = _refused(app, client, idp, email="doc@b.test", sub="sub-doc")
    assert "not set up" in r.text
    with app.state.db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM sso_identities").fetchone()[0] == 0
    assert audits(app, "sso_failed")[-1]["target"].endswith("email_in_other_org")


def test_existing_link_to_other_org_user_refused(app, client, idp):
    pid = add_provider(app)
    with app.state.db.connect() as conn:
        doc = conn.execute("SELECT id FROM users WHERE email = 'doc@b.test'").fetchone()[0]
        conn.execute("INSERT INTO sso_identities (provider_id, subject, user_id) VALUES (?, 'sub-x', ?)", (pid, doc))
    _refused(app, client, idp, sub="sub-x")


def test_email_outside_provider_domains_refused(app, client, idp):
    add_provider(app)
    _refused(app, client, idp, email="someone@elsewhere.test", sub="s-else")


def test_auto_provision_with_default_role(app, client, idp):
    add_provider(app, auto_provision=True, default_role="nurse")
    assert sso_flow(client, idp, email="new.rn@a.test", sub="sub-new", name="New Nurse").status_code == 200
    assert is_signed_in(client)
    with app.state.db.connect() as conn:
        u = conn.execute("SELECT * FROM users WHERE email = 'new.rn@a.test'").fetchone()
        org_a = conn.execute("SELECT id FROM orgs WHERE name = 'Org A'").fetchone()[0]
    assert u["role"] == "nurse" and u["org_id"] == org_a and u["display_name"] == "New Nurse"
    assert u["password_hash"] == "!sso" and not verify_password(u["password_hash"], "!sso")
    assert audits(app, "sso_provisioned")
    # The provisioned account cannot sign in with any password.
    fresh = TestClient(app)
    assert login(fresh, "new.rn@a.test", "!sso").headers["location"] == "/login"


def test_admin_is_never_a_provisioning_role(app, client, idp):
    add_provider(app, auto_provision=True, default_role="admin")
    _refused(app, client, idp, email="boss@a.test", sub="sub-boss")


def test_no_provision_when_off(app, client, idp):
    add_provider(app, auto_provision=False, default_role="nurse")
    r = _refused(app, client, idp, email="new.rn@a.test", sub="sub-new")
    assert "not set up" in r.text
    with app.state.db.connect() as conn:
        assert conn.execute("SELECT 1 FROM users WHERE email = 'new.rn@a.test'").fetchone() is None


def test_disabled_provider_not_offered(app, client, idp):
    add_provider(app, enabled=False)
    r = client.post("/sso/start", data={"email": "rn@a.test", "pre": pre_token(client)}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


# ------------------------------------------------------------------ enforce


def test_enforce_blocks_password_login_for_domain_only(app, client, idp):
    add_provider(app, enforce=True)
    r = login(client, "rn@a.test")
    assert r.headers["location"] == "/login" and not is_signed_in(client)
    assert "hospital" in client.get("/login").text.lower()
    other = TestClient(app)
    assert login(other, "doc@b.test").headers["location"] == "/patients"
    # SSO itself still works for the enforced domain.
    assert sso_flow(client, idp).status_code == 200 and is_signed_in(client)


def test_enforce_off_keeps_password_login(app, client, idp):
    add_provider(app, enforce=False)
    assert login(client, "rn@a.test", PASSWORD).headers["location"] == "/patients"


# ------------------------------------------------------------------ SAML and pluggability


def test_saml_stub_gives_clear_message(app, client, idp):
    add_provider(app, protocol="saml")
    r = client.post("/sso/start", data={"email": "rn@a.test", "pre": pre_token(client)}, follow_redirects=False)
    assert r.status_code == 501 and "not connected" in r.text
    assert client.get("/sso/a-idp/start", follow_redirects=False).status_code == 501
    with pytest.raises(NotImplementedError, match="OIDC broker"):
        sso.SAMLProvider(sso.ProviderConfig("x", "saml", ISSUER, "c"), idp, sso.MetadataCache()).complete("", "", "", "")


def test_provider_registry_is_pluggable(app, client, idp, monkeypatch):
    class FakeSAML:
        def __init__(self, config, transport, cache):
            self.config = config

        def authorization_url(self, state, nonce, code_challenge, redirect_uri, login_hint=""):
            return f"https://saml.test/sso?RelayState={state}"

        def complete(self, code, code_verifier, nonce, redirect_uri):
            assert code == "assertion-ok"
            return sso.Identity("name-id-1", "rn@a.test", True, "Rae", {})

    monkeypatch.setitem(sso.PROVIDER_FACTORIES, "saml", FakeSAML)
    add_provider(app, protocol="saml")
    url = start(client)
    state = parse_qs(urlsplit(url).query)["RelayState"][0]
    assert callback(client, "assertion-ok", state).status_code == 200 and is_signed_in(client)


# ------------------------------------------------------------------ CLI


def test_cli_add_list_disable(app, settings, monkeypatch, capsys):
    from scripts import sso as cli
    monkeypatch.setenv("DATA_KEY", settings.data_key)
    monkeypatch.setenv("SESSION_PEPPER", settings.session_pepper)
    monkeypatch.setenv("DATABASE_PATH", str(settings.database_path))
    monkeypatch.setenv("CLI_SSO_SECRET", "top-secret-value")
    base = ["add", "--org", "Org A", "--slug", "cli-idp", "--name", "CLI SSO", "--issuer", ISSUER,
            "--client-id", CLIENT_ID, "--client-secret-env", "CLI_SSO_SECRET", "--domains", "A.test"]
    assert cli.main(base + ["--auto-provision", "--default-role", "nurse", "--enforce"]) == 0
    assert cli.main(base) == 2  # slug exists
    assert cli.main([*base[:4], "other", *base[5:]]) == 2  # domain already claimed
    assert cli.main([*base[:8], "http://idp.test", *base[9:]]) == 2  # http issuer
    monkeypatch.delenv("CLI_SSO_SECRET")
    assert cli.main([*base[:4], "x2", *base[5:-1], "x.test"]) == 2  # secret env missing
    with app.state.db.connect() as conn:
        row = conn.execute("SELECT * FROM sso_providers WHERE slug = 'cli-idp'").fetchone()
    assert row["email_domains"] == "a.test" and row["enforce"] == 1 and row["default_role"] == "nurse"
    assert app.state.auth.cipher.decrypt(row["client_secret_enc"]) == "top-secret-value"
    capsys.readouterr()
    assert cli.main(["list"]) == 0
    out = capsys.readouterr().out
    assert "cli-idp" in out and "top-secret-value" not in out
    assert cli.main(["disable", "cli-idp"]) == 0 and cli.main(["disable", "nope"]) == 1
    with app.state.db.connect() as conn:
        assert conn.execute("SELECT enabled FROM sso_providers WHERE slug = 'cli-idp'").fetchone()[0] == 0


# ------------------------------------------------------------------ security review regressions


def test_unicode_lookalike_email_does_not_link(app, client, idp):
    """'Kate' (Kelvin sign) lowercased to 'kate' and linked to that account."""
    add_provider(app)
    r = sso_flow(client, idp, email="rɴ@a.test")  # small-capital N
    assert r.status_code == 400 and not is_signed_in(client)
    r = sso_flow(client, idp, email="K@a.test")
    assert r.status_code == 400 and not is_signed_in(client)
    with app.state.db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM sso_identities").fetchone()[0] == 0


def test_two_factor_and_admin_accounts_are_not_linked_by_email(app, client, idp):
    add_provider(app)
    with app.state.db.connect() as conn:
        conn.execute("UPDATE users SET totp_enabled_at = datetime('now') WHERE email = 'rn@a.test'")
    assert sso_flow(client, idp).status_code == 400 and not is_signed_in(client)
    assert any("link_needs_admin" in a["target"] for a in audits(app, "sso_failed"))


def test_junk_callback_does_not_cancel_a_sign_in_in_progress(app, client, idp):
    """Any site could send the browser to /sso/callback?state=junk, which
    deleted the binding cookie and broke the real sign-in."""
    add_provider(app)
    url = start(client)
    r = client.get("/sso/callback", params={"state": "junk", "code": "x"}, follow_redirects=False)
    assert "dc_sso" not in r.headers.get("set-cookie", "")
    client.cookies.set("dc_sso", client.cookies.get("dc_sso"))
    code, state = idp.authorize(url)
    assert callback(client, code, state).status_code == 200 and is_signed_in(client)


@pytest.mark.parametrize("bad", [["https://idp.test/a"], 7, None])
def test_malformed_discovery_is_a_clean_failure(app, client, idp, bad):
    add_provider(app)
    idp.discovery_overrides = {"authorization_endpoint": bad}
    r = client.post("/sso/start", data={"email": "rn@a.test", "pre": pre_token(client)}, follow_redirects=False)
    assert r.status_code in (400, 502)


def test_plain_http_localhost_refused_when_https_is_forced(monkeypatch):
    monkeypatch.setattr(sso, "ALLOW_LOCAL_HTTP", False)
    with pytest.raises(sso.SSOError):
        sso.check_url("http://127.0.0.1:8080/token", "token_endpoint")
    sso.check_url("https://idp.example.org/token", "token_endpoint")


def test_transport_caps_size_and_total_time():
    import httpx

    def big(request):
        return httpx.Response(200, content=b"{" + b" " * (sso.MAX_RESPONSE_BYTES + 10) + b"}")
    t = sso.HttpxTransport(httpx.Client(transport=httpx.MockTransport(big)))
    with pytest.raises(sso.TransportError):
        t.get_json("https://idp.test/x")

    def slow_stream():
        for _ in range(5):
            time.sleep(0.05)
            yield b" "
    t = sso.HttpxTransport(httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=slow_stream()))),
                           total_seconds=0.1)
    with pytest.raises(sso.TransportError):
        t.get_json("https://idp.test/x")
    ok = sso.HttpxTransport(httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"a": 1}))))
    assert ok.get_json("https://idp.test/x") == {"a": 1}


def test_cli_link(app, settings, monkeypatch, client, idp):
    from scripts import sso as cli
    monkeypatch.setenv("DATA_KEY", settings.data_key)
    monkeypatch.setenv("SESSION_PEPPER", settings.session_pepper)
    monkeypatch.setenv("DATABASE_PATH", str(settings.database_path))
    add_provider(app)
    with app.state.db.connect() as conn:
        conn.execute("UPDATE users SET totp_enabled_at = datetime('now') WHERE email = 'rn@a.test'")
    assert cli.main(["link", "a-idp", "doc@b.test", "sub-x"]) == 1  # other org
    assert cli.main(["link", "a-idp", "rn@a.test", "sub-rn"]) == 0
    # Linked explicitly, and SSO trusts the IdP's MFA, so no local code is asked.
    assert sso_flow(client, idp).status_code == 200 and is_signed_in(client)
