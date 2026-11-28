"""Hospital single sign-on (OIDC now, SAML pluggable). Routes are added by
register(app, ctx).

Flow (OpenID Connect authorization code + PKCE S256, state and nonce):

1. POST /sso/start (work email) or GET /sso/{slug}/start (bookmark) picks the
   enabled provider for the email's domain, stores a single-use state row
   (keyed hash of the state, the nonce, the PKCE verifier and a hash of a
   per-browser random value held in a cookie) and sends the browser to the IdP.
2. GET /sso/callback consumes the state atomically, checks the browser binding
   and expiry, exchanges the code, verifies the ID token against the IdP's JWKS
   and maps the identity to a local user in the provider's org only.

Two-factor: an SSO sign-in does NOT ask for the local TOTP code. The hospital's
IdP is trusted to enforce its own MFA policy (Entra ID / Okta conditional
access, Epic-adjacent IdPs, ...). Sessions are created with auth_method 'sso'
so the access log shows which way someone signed in. A hospital that sets
`enforce` on its provider also blocks password sign-in for its email domains,
so staff cannot side-step the IdP's MFA by falling back to a password.

Two browser-navigation details shape the responses:
- The app's CSP has `form-action 'self'`, which browsers also apply to
  redirects that follow a form POST. POST /sso/start therefore answers with a
  small page that moves on to the IdP by meta refresh instead of a 302.
- The session cookie is SameSite=Strict, and a redirect chain that began on the
  IdP's site counts as cross-site, so a 303 from the callback straight to
  /patients would arrive without the cookie. The callback likewise answers with
  a same-origin page that continues by meta refresh.

Nothing the IdP sends (error text, claims) is shown to the user verbatim; the
details go to the server log and a short safe message goes to the page.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Protocol
from urllib.parse import quote, urlencode, urlsplit

import httpx
import jwt
from fastapi import Form, Request
from fastapi.responses import RedirectResponse

from .security import csrf_ok

log = logging.getLogger(__name__)

AUDIT_ACTIONS: dict[str, str] = {
    "sso_start": "Hospital sign-in started",
    "sso_login": "Signed in with hospital sign-in",
    "sso_failed": "Hospital sign-in failed",
    "sso_linked": "Hospital sign-in linked to account",
    "sso_provisioned": "Account created by hospital sign-in",
}

BROWSER_COOKIE = "dc_sso"
# With HTTPS the __Host- prefix stops a sibling subdomain from planting its
# own binding cookie (which would log a victim into the attacker's account).
# Browsers only accept __Host- cookies that are Secure with Path=/.
SECURE_BROWSER_COOKIE = "__Host-dc_sso"
STATE_MINUTES = 10
# Mirrors the users.role CHECK in app/db.py, without 'admin': an IdP should
# never mint administrators on first sign-in.
PROVISION_ROLES = ("physician", "nurse", "case_manager", "compliance")
ALLOWED_ALGS = ("RS256", "ES256")
LEEWAY_SECONDS = 60
MAX_TOKEN_AGE_SECONDS = 600  # an ID token's iat older than this is refused
LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")
MAX_RESPONSE_BYTES = 512 * 1024


# ---------------------------------------------------------------- errors


class SSOError(Exception):
    """A sign-in that must not complete. `public` is safe to show; `detail`
    goes to the server log only."""

    def __init__(self, public: str, detail: str = ""):
        super().__init__(detail or public)
        self.public = public
        self.detail = detail or public


class TransportError(SSOError):
    def __init__(self, detail: str):
        super().__init__("Your hospital's sign-in service could not be reached. Try again in a few minutes.", detail)


GENERIC_FAIL = "Hospital sign-in did not complete. Start again, or ask your administrator."


# ---------------------------------------------------------------- HTTP transport


class Transport(Protocol):
    """All IdP HTTP goes through this, so tests can serve a fake IdP in-process."""

    def get_json(self, url: str, headers: dict[str, str] | None = None) -> dict: ...

    def post_form(self, url: str, data: dict[str, str], headers: dict[str, str] | None = None) -> dict: ...


class HttpxTransport:
    """Short timeouts, no redirects, bounded JSON bodies."""

    def __init__(self, client: httpx.Client | None = None, timeout: float = 5.0, total_seconds: float = 10.0):
        self.client = client or httpx.Client(timeout=httpx.Timeout(timeout), follow_redirects=False,
                                             headers={"Accept": "application/json"})
        # httpx timeouts are per read, so an IdP sending one byte at a time
        # could hold a worker thread for minutes. This caps the whole request.
        self.total_seconds = total_seconds

    def _send(self, method: str, url: str, **kw) -> tuple[int, bytes]:
        """Streams the body so an oversized response is cut off at the cap
        instead of being read into memory first."""
        deadline = time.monotonic() + self.total_seconds
        with self.client.stream(method, url, **kw) as resp:
            chunks, size = [], 0
            for chunk in resp.iter_bytes():
                size += len(chunk)
                if size > MAX_RESPONSE_BYTES:
                    raise TransportError(f"{url}: response too large")
                if time.monotonic() > deadline:
                    raise TransportError(f"{url}: too slow")
                chunks.append(chunk)
            return resp.status_code, b"".join(chunks)

    def _json(self, sent: tuple[int, bytes], url: str) -> dict:
        status, raw = sent
        try:
            body = json.loads(raw)
        except ValueError:
            body = None
        if status >= 400:
            code = body.get("error", "") if isinstance(body, dict) else ""
            raise TransportError(f"{url}: HTTP {status} {str(code)[:80]}")
        if not isinstance(body, dict):
            raise TransportError(f"{url}: response is not a JSON object")
        return body

    def get_json(self, url, headers=None):
        try:
            return self._json(self._send("GET", url, headers=headers), url)
        except httpx.HTTPError as exc:
            raise TransportError(f"{url}: {type(exc).__name__}") from exc

    def post_form(self, url, data, headers=None):
        try:
            return self._json(self._send("POST", url, data=data, headers=headers), url)
        except httpx.HTTPError as exc:
            raise TransportError(f"{url}: {type(exc).__name__}") from exc


class MetadataCache:
    """In-memory discovery documents and JWKS, per issuer / URL, with a TTL.
    One per app (app.state.sso_cache)."""

    def __init__(self, ttl: float = 3600.0, jwks_refresh_cooldown: float = 30.0):
        self.ttl = ttl
        # Minimum gap between forced JWKS refetches (unknown kid), so a flood of
        # tokens with made-up kids cannot turn us into a JWKS hammer.
        self.jwks_refresh_cooldown = jwks_refresh_cooldown
        self._data: dict[str, tuple[float, dict]] = {}
        self._lock = threading.Lock()

    def get(self, key: str, fetch: Callable[[], dict], force: bool = False) -> tuple[dict, bool]:
        """(value, fetched_now)."""
        now = time.monotonic()
        with self._lock:
            hit = self._data.get(key)
        if hit and not force and now - hit[0] < self.ttl:
            return hit[1], False
        if hit and force and now - hit[0] < self.jwks_refresh_cooldown:
            return hit[1], False
        value = fetch()
        with self._lock:
            self._data[key] = (time.monotonic(), value)
        return value, True

    def drop(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)


# ---------------------------------------------------------------- provider interface


@dataclass(frozen=True)
class Identity:
    subject: str
    email: str
    email_verified: bool
    name: str
    raw_claims: dict = field(repr=False, default_factory=dict)


@dataclass(frozen=True)
class ProviderConfig:
    slug: str
    protocol: str
    issuer: str
    client_id: str
    client_secret: str = field(repr=False, default="")


class IdentityProvider(Protocol):
    def authorization_url(self, state: str, nonce: str, code_challenge: str, redirect_uri: str,
                          login_hint: str = "") -> str: ...

    def complete(self, code: str, code_verifier: str, nonce: str, redirect_uri: str) -> Identity: ...


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def pkce_challenge(verifier: str) -> str:
    return _b64url(hashlib.sha256(verifier.encode("ascii")).digest())


# Plain http to localhost is a development convenience only. register() turns
# it off when FORCE_HTTPS=1, so a discovery document cannot send the token
# request (which carries the client secret) to a local plain-http service.
ALLOW_LOCAL_HTTP = True


def check_url(url, what: str) -> None:
    """https only, except localhost while developing."""
    if not isinstance(url, str):  # a malformed discovery document
        raise SSOError(GENERIC_FAIL, f"{what} is not a URL")
    parts = urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return
    if ALLOW_LOCAL_HTTP and parts.scheme == "http" and parts.hostname in LOCAL_HOSTS:
        return
    raise SSOError(GENERIC_FAIL, f"{what} must be an https URL: {url[:120]!r}")


class OIDCProvider:
    """OpenID Connect authorization code flow with PKCE S256."""

    def __init__(self, config: ProviderConfig, transport: Transport, cache: MetadataCache):
        check_url(config.issuer, "issuer")
        self.config = config
        self.transport = transport
        self.cache = cache

    # -- metadata

    def discovery(self) -> dict:
        issuer = self.config.issuer
        url = issuer.rstrip("/") + "/.well-known/openid-configuration"
        doc, fresh = self.cache.get("discovery:" + issuer, lambda: self.transport.get_json(url))
        if fresh:
            if doc.get("issuer") != issuer:  # exact match, OIDC Discovery 4.3
                self.cache.drop("discovery:" + issuer)
                raise SSOError(GENERIC_FAIL, f"discovery issuer {str(doc.get('issuer'))[:120]!r} != {issuer!r}")
            for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                try:
                    check_url(doc.get(key, ""), key)
                except SSOError:
                    self.cache.drop("discovery:" + issuer)
                    raise
        return doc

    def _jwks(self, force: bool = False) -> tuple[dict, bool]:
        uri = self.discovery()["jwks_uri"]
        return self.cache.get("jwks:" + uri, lambda: self.transport.get_json(uri), force=force)

    def _signing_key(self, kid: str | None, alg: str):
        def find(keys: dict):
            matches = [k for k in keys.get("keys", []) if isinstance(k, dict)
                       and k.get("use", "sig") == "sig" and (kid is None or k.get("kid") == kid)]
            return matches[0] if len(matches) == 1 else None

        jwks, fresh = self._jwks()
        jwk = find(jwks)
        if jwk is None and not fresh:  # key rotation: refetch once
            jwks, _ = self._jwks(force=True)
            jwk = find(jwks)
        if jwk is None:
            raise SSOError(GENERIC_FAIL, f"no signing key for kid {str(kid)[:60]!r}")
        if jwk.get("alg") and jwk["alg"] != alg:
            raise SSOError(GENERIC_FAIL, f"key alg {jwk['alg']!r} does not match token alg {alg!r}")
        try:
            return jwt.PyJWK(jwk, algorithm=alg).key
        except (jwt.exceptions.PyJWKError, ValueError, TypeError) as exc:
            raise SSOError(GENERIC_FAIL, f"unusable JWK: {type(exc).__name__}") from exc

    # -- flow

    def authorization_url(self, state, nonce, code_challenge, redirect_uri, login_hint=""):
        endpoint = self.discovery()["authorization_endpoint"]
        params = {
            "response_type": "code", "client_id": self.config.client_id, "redirect_uri": redirect_uri,
            "scope": "openid email profile", "state": state, "nonce": nonce,
            "code_challenge": code_challenge, "code_challenge_method": "S256",
        }
        if login_hint:
            params["login_hint"] = login_hint
        return endpoint + ("&" if "?" in endpoint else "?") + urlencode(params)

    def _token_request(self, code: str, code_verifier: str, redirect_uri: str) -> dict:
        doc = self.discovery()
        data = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
                "code_verifier": code_verifier, "client_id": self.config.client_id}
        headers = {}
        methods = doc.get("token_endpoint_auth_methods_supported") or ["client_secret_basic"]
        if self.config.client_secret:
            if "client_secret_basic" in methods:
                # RFC 6749 2.3.1: form-urlencode each part before base64.
                pair = f"{quote(self.config.client_id, safe='')}:{quote(self.config.client_secret, safe='')}"
                headers["Authorization"] = "Basic " + base64.b64encode(pair.encode()).decode()
            elif "client_secret_post" in methods:
                data["client_secret"] = self.config.client_secret
            else:
                raise SSOError(GENERIC_FAIL, f"no supported client auth method in {methods!r}")
        return self.transport.post_form(doc["token_endpoint"], data, headers)

    def verify_id_token(self, token: str, nonce: str) -> dict:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.exceptions.DecodeError as exc:
            raise SSOError(GENERIC_FAIL, "ID token is not a JWT") from exc
        alg = header.get("alg")
        if alg not in ALLOWED_ALGS:  # never 'none' or HS* (a client secret is not a signing key here)
            raise SSOError(GENERIC_FAIL, f"ID token alg {str(alg)[:20]!r} not allowed")
        key = self._signing_key(header.get("kid"), alg)
        try:
            claims = jwt.decode(
                token, key, algorithms=[alg], audience=self.config.client_id, issuer=self.config.issuer,
                leeway=LEEWAY_SECONDS, options={"require": ["iss", "aud", "sub", "exp", "iat"]},
            )
        except jwt.exceptions.InvalidTokenError as exc:
            raise SSOError(GENERIC_FAIL, f"ID token rejected: {type(exc).__name__}: {str(exc)[:120]}") from exc
        aud = claims["aud"]
        auds = aud if isinstance(aud, list) else [aud]
        azp = claims.get("azp")
        if azp is not None and azp != self.config.client_id:
            raise SSOError(GENERIC_FAIL, "ID token azp is another client")
        if len(auds) > 1 and azp is None:
            raise SSOError(GENERIC_FAIL, "ID token has several audiences and no azp")
        iat = claims.get("iat")
        if not isinstance(iat, (int, float)) or iat < time.time() - MAX_TOKEN_AGE_SECONDS - LEEWAY_SECONDS:
            raise SSOError(GENERIC_FAIL, "ID token is too old")
        got = claims.get("nonce")
        if not isinstance(got, str) or not hmac.compare_digest(got.encode(), nonce.encode()):
            raise SSOError(GENERIC_FAIL, "ID token nonce mismatch")
        if not isinstance(claims["sub"], str) or not 0 < len(claims["sub"]) <= 255:
            raise SSOError(GENERIC_FAIL, "ID token sub is not a usable string")
        return claims

    def complete(self, code, code_verifier, nonce, redirect_uri):
        tokens = self._token_request(code, code_verifier, redirect_uri)
        id_token = tokens.get("id_token")
        if not isinstance(id_token, str) or str(tokens.get("token_type", "")).lower() != "bearer":
            raise SSOError(GENERIC_FAIL, "token response has no bearer ID token")
        claims = self.verify_id_token(id_token, nonce)
        info = dict(claims)
        userinfo_endpoint = self.discovery().get("userinfo_endpoint")
        if "email" not in claims and userinfo_endpoint and isinstance(tokens.get("access_token"), str):
            check_url(userinfo_endpoint, "userinfo_endpoint")
            extra = self.transport.get_json(userinfo_endpoint, {"Authorization": "Bearer " + tokens["access_token"]})
            if extra.get("sub") != claims["sub"]:  # OIDC Core 5.3.2
                raise SSOError(GENERIC_FAIL, "userinfo sub does not match ID token")
            for k in ("email", "email_verified", "name"):
                if k in extra:
                    info[k] = extra[k]
        email = info.get("email")
        verified = info.get("email_verified")
        # Some IdPs send "true" as a string.
        verified = verified is True or (isinstance(verified, str) and verified.lower() == "true")
        email = email.strip() if isinstance(email, str) else ""
        # ASCII only: str.lower() folds look-alikes such as the Kelvin sign
        # (U+212A) to "k", which would let an IdP account named with one link
        # to someone else's local account. Such an email counts as missing.
        if not email.isascii():
            email = ""
        return Identity(
            subject=claims["sub"],
            email=email.lower(),
            email_verified=verified,
            name=str(info.get("name") or "")[:120],
            raw_claims=claims,
        )


class SAMLProvider:
    """Placeholder so SAML providers can be registered and fail clearly.

    Many hospitals run SAML 2.0 (ADFS, Epic-adjacent and older IdPs). Two ways
    to connect one:
    1. Put an OIDC broker in front of it (Microsoft Entra ID, Okta, Keycloak,
       Auth0, ...) and register the broker here as protocol 'oidc'. Nothing in
       this app changes. This is the recommended route.
    2. Implement this class with python3-saml (OneLogin): authorization_url()
       builds the AuthnRequest redirect (RelayState = state), and an ACS route
       validates the signed Response/Assertion (signature, Audience,
       Destination, InResponseTo, NotOnOrAfter) and returns an Identity with
       the NameID as subject. Register it in PROVIDER_FACTORIES['saml'].
    """

    MESSAGE = ("SAML sign-in is not built into this app. Put an OIDC broker (Entra ID, Okta, Keycloak) in front "
               "of the SAML IdP and register it as 'oidc', or add a python3-saml adapter as "
               "PROVIDER_FACTORIES['saml'] in app/sso.py.")

    def __init__(self, config: ProviderConfig, transport: Transport, cache: MetadataCache):
        self.config = config

    def authorization_url(self, state, nonce, code_challenge, redirect_uri, login_hint=""):
        raise NotImplementedError(self.MESSAGE)

    def complete(self, code, code_verifier, nonce, redirect_uri):
        raise NotImplementedError(self.MESSAGE)


ProviderFactory = Callable[[ProviderConfig, Transport, MetadataCache], IdentityProvider]
PROVIDER_FACTORIES: dict[str, ProviderFactory] = {"oidc": OIDCProvider, "saml": SAMLProvider}


# ---------------------------------------------------------------- helpers


def parse_domains(raw: str) -> list[str]:
    return [d.strip().lower().lstrip("@") for d in (raw or "").split(",") if d.strip()]


def email_domain(email: str) -> str:
    email = (email or "").strip().lower()
    if email.count("@") != 1:
        return ""
    local, domain = email.split("@")
    return domain if local and domain else ""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def register(app, ctx) -> None:
    settings, db = ctx.settings, ctx.db
    key = hmac.new(settings.session_pepper.encode(), b"sso-state-key", hashlib.sha256).digest()
    redirect_uri = settings.public_base_url.rstrip("/") + "/sso/callback"
    global ALLOW_LOCAL_HTTP
    ALLOW_LOCAL_HTTP = not settings.force_https
    bind_cookie = SECURE_BROWSER_COOKIE if settings.force_https else BROWSER_COOKIE
    if not hasattr(app.state, "sso_transport"):
        app.state.sso_transport = HttpxTransport()
    if not hasattr(app.state, "sso_cache"):
        app.state.sso_cache = MetadataCache()

    def keyed(label: bytes, value: str) -> str:
        return hmac.new(key, label + value.encode(), hashlib.sha256).hexdigest()

    def provider_for(row) -> IdentityProvider:
        factory = PROVIDER_FACTORIES.get(row["protocol"])
        if factory is None:
            raise SSOError(GENERIC_FAIL, f"no factory for protocol {row['protocol']!r}")
        secret = ctx.cipher.decrypt(row["client_secret_enc"]) if row["client_secret_enc"] else ""
        config = ProviderConfig(row["slug"], row["protocol"], row["issuer"], row["client_id"], secret)
        return factory(config, app.state.sso_transport, app.state.sso_cache)

    def providers_for_domain(conn, domain: str, enforced_only: bool = False):
        sql = "SELECT * FROM sso_providers WHERE enabled = 1" + (" AND enforce = 1" if enforced_only else "")
        return [r for r in conn.execute(sql + " ORDER BY id") if domain and domain in parse_domains(r["email_domains"])]

    def page(request: Request, *, message: str = "", next_url: str = "", status: int = 200, title: str = ""):
        return ctx.templates.TemplateResponse(
            request, "sso_continue.html",
            {"user": None, "message": message, "next_url": next_url, "title": title or "Hospital sign-in"},
            status_code=status)

    def fail_page(request: Request, message: str, status: int = 400, clear_binding: bool = False):
        # The binding cookie is cleared only once a callback proved it belongs
        # to this browser's flow; otherwise any site could cancel a sign-in in
        # progress by sending the browser to /sso/callback?state=junk.
        resp = page(request, message=message, status=status, title="Sign-in did not complete")
        if clear_binding:
            resp.delete_cookie(bind_cookie, path="/")
        return resp

    # -- password guard: enforced SSO domains cannot use passwords

    def enforce_guard(email: str) -> str:
        domain = email_domain(email)
        if not domain:
            return ""
        with db.connect() as conn:
            if providers_for_domain(conn, domain, enforced_only=True):
                return "Your hospital requires its own sign-in. Use “Sign in with your hospital” below."
        return ""

    ctx.password_guards.append(enforce_guard)

    # -- start

    def begin(request: Request, row, login_hint: str, interstitial: bool):
        ip = ctx.client_ip(request)
        state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(64)  # 86 chars, within RFC 7636's 43..128
        browser = secrets.token_urlsafe(32)
        try:
            url = provider_for(row).authorization_url(state, nonce, pkce_challenge(verifier), redirect_uri, login_hint)
        except NotImplementedError as exc:
            log.warning("SSO provider %s: %s", row["slug"], exc)
            with db.connect() as conn:
                db.audit(conn, row["org_id"], None, "sso_failed", f"provider:{row['slug']} not_implemented", ip)
            return fail_page(request, "Your hospital's sign-in is not connected to Discharge Check yet. "
                                      "Ask your administrator, or sign in with your password.", 501)
        except SSOError as exc:
            log.warning("SSO start for %s failed: %s", row["slug"], exc.detail)
            with db.connect() as conn:
                db.audit(conn, row["org_id"], None, "sso_failed", f"provider:{row['slug']} start", ip)
            return fail_page(request, exc.public, 502)
        expires = (_now() + timedelta(minutes=STATE_MINUTES)).isoformat()
        with db.connect() as conn:
            conn.execute("DELETE FROM sso_states WHERE expires_at < ?", (_now().isoformat(),))
            conn.execute("INSERT INTO sso_states (state_hash, provider_id, nonce, code_verifier, browser_hash, expires_at)"
                         " VALUES (?, ?, ?, ?, ?, ?)",
                         (keyed(b"state:", state), row["id"], nonce, verifier, keyed(b"browser:", browser), expires))
            db.audit(conn, row["org_id"], None, "sso_start", f"provider:{row['slug']}", ip)
        resp = page(request, next_url=url, title="Continuing to your hospital") if interstitial \
            else RedirectResponse(url, status_code=303)
        # SameSite=Lax, not Strict: the IdP sends the browser back with a
        # cross-site top-level GET to /sso/callback, and a Strict cookie would
        # not be sent on it. Lax is sent on that GET and still withheld from
        # cross-site subresource and POST requests. The cookie only binds the
        # state to this browser; it grants nothing by itself.
        resp.set_cookie(bind_cookie, browser, max_age=STATE_MINUTES * 60, httponly=True,
                        secure=settings.force_https, samesite="lax", path="/")
        return resp

    def rate_ok(request: Request) -> bool:
        return ctx.rate.allow(f"sso:ip:{ctx.client_ip(request)}", 30, timedelta(minutes=10))

    @app.post("/sso/start")
    def sso_start(request: Request, email: str = Form("", max_length=254), pre: str = Form("", max_length=64)):
        if not csrf_ok(request.cookies.get(ctx.PRE_COOKIE, ""), pre):
            return ctx.go("/login", error="The sign-in form expired. Try again.")
        if not rate_ok(request):
            return ctx.go("/login", error="Too many attempts. Wait a few minutes and try again.")
        email = email.strip().lower()
        with db.connect() as conn:
            rows = providers_for_domain(conn, email_domain(email))
        if not rows:
            return ctx.go("/login", error="Hospital sign-in is not set up for that email. Sign in with your password, "
                                          "or ask your administrator.")
        # The form POST must not redirect off-site (CSP form-action 'self'): continue by page.
        return begin(request, rows[0], email, interstitial=True)

    @app.get("/sso/{slug}/start")
    def sso_start_slug(request: Request, slug: str):
        if len(slug) > 64:
            return fail_page(request, "That hospital sign-in link is not valid.", 404)
        if not rate_ok(request):
            return fail_page(request, "Too many attempts. Wait a few minutes and try again.", 429)
        with db.connect() as conn:
            row = conn.execute("SELECT * FROM sso_providers WHERE slug = ? AND enabled = 1", (slug,)).fetchone()
        if row is None:
            return fail_page(request, "That hospital sign-in link is not valid.", 404)
        return begin(request, row, "", interstitial=False)

    # -- callback

    @app.get("/sso/callback")
    def sso_callback(request: Request):
        q = request.query_params
        ip = ctx.client_ip(request)
        state, code, error = q.get("state", ""), q.get("code", ""), q.get("error", "")
        if not ctx.rate.allow(f"sso:cb:{ip}", 60, timedelta(minutes=10)):
            return fail_page(request, "Too many attempts. Wait a few minutes and try again.", 429)
        if len(state) > 128 or len(code) > 2048:
            return fail_page(request, GENERIC_FAIL)
        st = None
        if state:
            with db.connect() as conn:
                # Single use: whichever request deletes the row owns it.
                st = conn.execute("DELETE FROM sso_states WHERE state_hash = ? RETURNING provider_id, nonce, "
                                  "code_verifier, browser_hash, expires_at", (keyed(b"state:", state),)).fetchone()
                prov = (conn.execute("SELECT * FROM sso_providers WHERE id = ?", (st["provider_id"],)).fetchone()
                        if st else None)
        if st is None or prov is None:
            with db.connect() as conn:
                db.audit(conn, None, None, "sso_failed", "state:unknown", ip)
            return fail_page(request, "This sign-in link expired or was already used. Start again from the sign-in page.")
        target = f"provider:{prov['slug']}"

        bound = False

        def refuse(public: str, reason: str, detail: str = "", status: int = 400):
            # `reason` is a short fixed code for the access log; `detail` may
            # carry IdP-supplied text and goes to the server log only.
            log.warning("SSO %s refused (%s): %s", prov["slug"], reason, detail[:500])
            with db.connect() as conn:
                db.audit(conn, prov["org_id"], None, "sso_failed", f"{target} {reason}", ip)
            return fail_page(request, public, status, clear_binding=bound)

        if error:
            log.info("SSO %s: IdP returned error=%r description=%r", prov["slug"], error[:80],
                     q.get("error_description", "")[:300])
            return refuse("Your hospital's sign-in was cancelled or refused. Start again, or ask your administrator.",
                          "idp_error")
        browser = request.cookies.get(bind_cookie, "")
        if not browser or not hmac.compare_digest(keyed(b"browser:", browser), st["browser_hash"]):
            return refuse("This sign-in was started in a different browser. Start again from the sign-in page.",
                          "browser_mismatch")
        bound = True
        if st["expires_at"] < _now().isoformat():
            return refuse("This sign-in link expired. Start again from the sign-in page.", "expired")
        if not prov["enabled"]:
            return refuse(GENERIC_FAIL, "provider_disabled")
        if not code:
            return refuse(GENERIC_FAIL, "no_code")
        try:
            ident = provider_for(prov).complete(code, st["code_verifier"], st["nonce"], redirect_uri)
        except NotImplementedError as exc:
            return refuse("Your hospital's sign-in is not connected to Discharge Check yet.", "not_implemented",
                          str(exc), status=501)
        except TransportError as exc:
            return refuse(exc.public, "idp_unreachable", exc.detail, status=502)
        except SSOError as exc:
            return refuse(exc.public, "token_rejected", exc.detail)
        if not ident.email or not ident.email_verified:
            return refuse("Your hospital account has no verified email address. Ask your administrator.",
                          "email_unverified")
        try:
            user, problem = map_identity(prov, ident, ip)
        except sqlite3.IntegrityError as exc:  # a concurrent first sign-in won the insert
            return refuse(GENERIC_FAIL, "conflict", str(exc))
        if user is None:
            return refuse("Your hospital account is not set up for Discharge Check. Ask your administrator.", problem)
        resp = ctx.start_session(request, user, "sso", target)
        with db.connect() as conn:
            db.audit(conn, prov["org_id"], user["id"], "sso_login", target, ip)
        # Continue by a same-origin page so the SameSite=Strict session cookie
        # is sent on the next request (see module docstring).
        out = page(request, next_url=resp.headers.get("location", "/patients"), title="Signed in")
        for k, v in resp.raw_headers:
            if k.lower() == b"set-cookie":
                out.raw_headers.append((k, v))
        out.delete_cookie(bind_cookie, path="/")
        return out

    def map_identity(prov, ident: Identity, ip: str):
        """(user row, "") or (None, reason code). Never links or signs in
        across orgs: every path checks the provider's org_id."""
        cols = "u.id, u.org_id, u.role, u.totp_enabled_at, u.email"
        with db.connect() as conn:
            user = conn.execute(f"SELECT {cols} FROM sso_identities i JOIN users u ON u.id = i.user_id"
                                " WHERE i.provider_id = ? AND i.subject = ?", (prov["id"], ident.subject)).fetchone()
            if user is not None:
                return (user, "") if user["org_id"] == prov["org_id"] else (None, "linked_user_other_org")
            if email_domain(ident.email) not in parse_domains(prov["email_domains"]):
                return None, "email_domain_not_allowed"
            user = conn.execute(f"SELECT {cols} FROM users u WHERE u.email = ?", (ident.email,)).fetchone()
            if user is not None:
                if user["org_id"] != prov["org_id"]:
                    return None, "email_in_other_org"
                if user["role"] == "admin" or user["totp_enabled_at"]:
                    # Linking by email trusts the IdP's word for who owns the
                    # account. For administrators and accounts protected by
                    # two-factor, an admin links them explicitly instead
                    # (python -m scripts.sso link).
                    return None, "link_needs_admin"
                if conn.execute("SELECT 1 FROM sso_identities WHERE provider_id = ? AND user_id = ?",
                                (prov["id"], user["id"])).fetchone():
                    # Same email, different IdP subject: do not silently re-link.
                    return None, "user_linked_to_other_subject"
                conn.execute("INSERT INTO sso_identities (provider_id, subject, user_id) VALUES (?, ?, ?)",
                             (prov["id"], ident.subject, user["id"]))
                db.audit(conn, prov["org_id"], user["id"], "sso_linked", f"provider:{prov['slug']}", ip)
                return user, ""
            if not prov["auto_provision"] or prov["default_role"] not in PROVISION_ROLES:
                return None, "no_account"
            name = ident.name.strip() or ident.email.split("@")[0]
            # "!sso" is not an argon2 hash: verify_password() returns False on
            # InvalidHashError, so a provisioned account has no usable password.
            uid = conn.execute("INSERT INTO users (org_id, email, display_name, role, password_hash)"
                               " VALUES (?, ?, ?, ?, '!sso')",
                               (prov["org_id"], ident.email, name[:120], prov["default_role"])).lastrowid
            conn.execute("INSERT INTO sso_identities (provider_id, subject, user_id) VALUES (?, ?, ?)",
                         (prov["id"], ident.subject, uid))
            db.audit(conn, prov["org_id"], uid, "sso_provisioned",
                     f"provider:{prov['slug']} role:{prov['default_role']}", ip)
            return conn.execute(f"SELECT {cols} FROM users u WHERE u.id = ?", (uid,)).fetchone(), ""
