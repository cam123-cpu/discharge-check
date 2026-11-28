"""SMART on FHIR R4 client: discovery, backend services and standalone launch
auth, and a FHIR REST client hardened for talking to outside servers.

Works with the SMART Health IT open server, the SMART launcher and the Epic
sandbox. Uses httpx and `cryptography` only (no PyJWT).

    python -m app.fhir.smart jwks private.pem   # print the public JWKS
"""
from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import os
import posixpath
import re
import secrets
import sys
import time
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode, urljoin, urlsplit

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

AUTH_MODES = ("open", "backend", "standalone")
JWT_ALGS = ("RS384", "ES384")
OAUTH_URIS_EXT = "http://fhir-registry.smarthealthit.org/StructureDefinition/oauth-uris"
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
FHIR_JSON = "application/fhir+json"

BACKEND_TYPES = ("Patient", "Encounter", "Condition", "MedicationRequest", "AllergyIntolerance",
                 "DocumentReference", "DiagnosticReport", "Appointment", "ServiceRequest",
                 "CarePlan", "Goal", "Procedure", "Medication", "Binary")
DEFAULT_SCOPES = {
    "open": "",
    "backend": " ".join(f"system/{t}.read" for t in BACKEND_TYPES),
    "standalone": "launch/patient openid fhirUser offline_access "
                  + " ".join(f"patient/{t}.read" for t in BACKEND_TYPES),
}

_ID_RE = re.compile(r"[A-Za-z0-9\-.]{1,64}")
_TYPE_RE = re.compile(r"[A-Z][A-Za-z]{1,63}")
_SCOPE_RE = re.compile(r"[\x21\x23-\x5B\x5D-\x7E]+")  # RFC 6749 scope-token
RETRY_STATUSES = {429, 502, 503, 504}
MAX_RETRIES = 3
MAX_RETRY_AFTER = 10.0
EXPIRY_SKEW = 60
ASSERTION_LIFETIME = 300  # SMART Backend Services: exp no more than 5 minutes ahead


class SmartConfigError(ValueError):
    """Missing or invalid SMART/FHIR configuration."""


class FhirClientError(RuntimeError):
    """A FHIR or OAuth request failed. The message never holds a token or secret."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


# ---------------------------------------------------------------- settings

def _is_local(host: str | None) -> bool:
    return (host or "").lower() in ("localhost", "127.0.0.1", "[::1]", "::1")


def check_url(url: str, what: str) -> str:
    """Require https (plain http only for localhost dev) and no credentials in the URL."""
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise SmartConfigError(f"{what} is not a valid URL.") from exc
    if parts.username or parts.password:
        raise SmartConfigError(f"{what} must not contain a user name or password.")
    if not parts.hostname:
        raise SmartConfigError(f"{what} must be an absolute URL.")
    if parts.scheme == "https" or (parts.scheme == "http" and _is_local(parts.hostname)):
        return url
    raise SmartConfigError(f"{what} must use https (plain http is allowed only for localhost).")


@dataclass(frozen=True)
class SmartSettings:
    base_url: str
    auth_mode: str = "open"
    client_id: str | None = None
    client_secret: str | None = None
    private_key_path: Path | None = None
    key_id: str | None = None
    jwt_alg: str = "RS384"
    scopes: str = ""
    redirect_uri: str | None = None
    timeout_seconds: float = 20.0

    def __repr__(self) -> str:  # secrets and key locations stay out of logs and tracebacks
        return (f"SmartSettings(base_url={self.base_url!r}, auth_mode={self.auth_mode!r}, "
                f"client_id={self.client_id!r}, client_secret={'***' if self.client_secret else None}, "
                f"private_key_path={'***' if self.private_key_path else None}, key_id={self.key_id!r}, "
                f"jwt_alg={self.jwt_alg!r}, scopes={self.scopes!r}, redirect_uri={self.redirect_uri!r}, "
                f"timeout_seconds={self.timeout_seconds!r})")

    __str__ = __repr__

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> SmartSettings:
        env = os.environ if env is None else env
        get = lambda k: (env.get(k) or "").strip() or None
        base = get("FHIR_BASE_URL")
        if not base:
            raise SmartConfigError("FHIR_BASE_URL is not set (e.g. https://r4.smarthealthit.org).")
        base = check_url(base.rstrip("/"), "FHIR_BASE_URL")
        mode = (get("FHIR_AUTH_MODE") or "open").lower()
        if mode not in AUTH_MODES:
            raise SmartConfigError(f"FHIR_AUTH_MODE must be one of {', '.join(AUTH_MODES)}.")
        alg = (get("FHIR_JWT_ALG") or "RS384").upper()
        if alg not in JWT_ALGS:
            raise SmartConfigError("FHIR_JWT_ALG must be RS384 or ES384.")
        try:
            timeout = float(get("FHIR_TIMEOUT_SECONDS") or 20)
        except ValueError:
            raise SmartConfigError("FHIR_TIMEOUT_SECONDS must be a number.") from None
        if not 0 < timeout <= 300:
            raise SmartConfigError("FHIR_TIMEOUT_SECONDS must be between 0 and 300.")
        scopes = get("FHIR_SCOPES")
        scopes = " ".join(scopes.split()) if scopes else DEFAULT_SCOPES[mode]
        if scopes and not all(_SCOPE_RE.fullmatch(s) for s in scopes.split()):
            raise SmartConfigError("FHIR_SCOPES contains characters that are not allowed in a scope.")
        key_path = Path(get("FHIR_PRIVATE_KEY_PATH")).expanduser() if get("FHIR_PRIVATE_KEY_PATH") else None
        client_id, redirect = get("FHIR_CLIENT_ID"), get("FHIR_REDIRECT_URI")
        if mode == "backend":
            if not client_id:
                raise SmartConfigError("FHIR_CLIENT_ID is required when FHIR_AUTH_MODE=backend.")
            if not key_path:
                raise SmartConfigError("FHIR_PRIVATE_KEY_PATH is required when FHIR_AUTH_MODE=backend.")
            if not key_path.is_file():
                raise SmartConfigError("FHIR_PRIVATE_KEY_PATH does not point to a readable file.")
        if mode == "standalone":
            if not client_id:
                raise SmartConfigError("FHIR_CLIENT_ID is required when FHIR_AUTH_MODE=standalone.")
            if not redirect:
                raise SmartConfigError("FHIR_REDIRECT_URI is required when FHIR_AUTH_MODE=standalone.")
            check_url(redirect, "FHIR_REDIRECT_URI")
        return cls(base_url=base, auth_mode=mode, client_id=client_id, client_secret=get("FHIR_CLIENT_SECRET"),
                   private_key_path=key_path, key_id=get("FHIR_KEY_ID"), jwt_alg=alg, scopes=scopes,
                   redirect_uri=redirect, timeout_seconds=timeout)


# ---------------------------------------------------------------- tokens

@dataclass
class Token:
    access_token: str = field(repr=False)
    token_type: str = "Bearer"
    expires_at: float | None = None
    scope: str = ""
    patient: str | None = None
    encounter: str | None = None
    refresh_token: str | None = field(default=None, repr=False)

    def __repr__(self) -> str:
        return (f"Token(access_token='***', token_type={self.token_type!r}, expires_at={self.expires_at!r}, "
                f"scope={self.scope!r}, patient={self.patient!r}, encounter={self.encounter!r}, "
                f"refresh_token={'***' if self.refresh_token else None})")

    __str__ = __repr__

    def expired(self, now: float | None = None) -> bool:
        """Treated as expired 60 s early so a request never races the expiry."""
        if self.expires_at is None:
            return False
        return (time.time() if now is None else now) >= self.expires_at - EXPIRY_SKEW

    @classmethod
    def from_response(cls, data: Any, now: float | None = None, refresh_token: str | None = None) -> Token:
        if not isinstance(data, dict) or not isinstance(data.get("access_token"), str) or not data["access_token"]:
            raise FhirClientError("The token endpoint did not return an access token.")
        if str(data.get("token_type", "bearer")).lower() != "bearer":
            raise FhirClientError("The token endpoint returned an unsupported token type.")
        now = time.time() if now is None else now
        exp = data.get("expires_in")
        expires_at = now + float(exp) if isinstance(exp, (int, float)) and not isinstance(exp, bool) else None
        return cls(access_token=data["access_token"], token_type="Bearer", expires_at=expires_at,
                   scope=str(data.get("scope") or ""),
                   patient=data.get("patient") if isinstance(data.get("patient"), str) else None,
                   encounter=data.get("encounter") if isinstance(data.get("encounter"), str) else None,
                   refresh_token=data.get("refresh_token") or refresh_token)


@dataclass(frozen=True)
class SmartConfiguration:
    authorization_endpoint: str | None
    token_endpoint: str | None
    capabilities: tuple[str, ...] = ()
    code_challenge_methods_supported: tuple[str, ...] = ()
    token_endpoint_auth_methods_supported: tuple[str, ...] = ()
    grant_types_supported: tuple[str, ...] = ()
    scopes_supported: tuple[str, ...] = ()
    issuer: str | None = None
    jwks_uri: str | None = None
    source: str = "smart-configuration"  # or "metadata"


@dataclass(frozen=True)
class AuthRequest:
    url: str
    state: str = field(repr=False)
    code_verifier: str = field(repr=False)


# ---------------------------------------------------------------- HTTP core

def _new_http(settings: SmartSettings) -> httpx.Client:
    # Redirects are never followed: a redirect could carry the bearer token to another host.
    return httpx.Client(timeout=settings.timeout_seconds, follow_redirects=False)


def _retry_delay(headers: httpx.Headers | None, attempt: int) -> float:
    if headers is not None and (ra := headers.get("Retry-After")):
        try:
            delay = float(ra)
        except ValueError:
            try:
                delay = parsedate_to_datetime(ra).timestamp() - time.time()
            except (TypeError, ValueError):
                delay = 1.0
        return max(0.0, min(delay, MAX_RETRY_AFTER))
    return min(0.5 * 2 ** attempt, MAX_RETRY_AFTER)


def _sanitize(text: str, secrets_: Iterable[str | None] = ()) -> str:
    for s in secrets_:
        if s and len(s) >= 4:  # masking 1-3 char values would only garble the message
            text = text.replace(s, "***")
    return text


def _error_detail(body: bytes) -> str:
    """OperationOutcome diagnostics (or OAuth error), truncated; never the raw body."""
    try:
        data = json.loads(body)
    except (ValueError, RecursionError):
        return ""
    if not isinstance(data, dict):
        return ""
    if data.get("resourceType") == "OperationOutcome":
        parts = []
        for issue in data.get("issue") or []:
            if isinstance(issue, dict):
                d = issue.get("diagnostics") or (issue.get("details") or {}).get("text") or issue.get("code")
                if isinstance(d, str):
                    parts.append(d)
        return "; ".join(parts)[:200]
    if isinstance(data.get("error"), str):
        desc = data.get("error_description")
        return (data["error"] + (f": {desc}" if isinstance(desc, str) else ""))[:200]
    return ""


@dataclass
class _Raw:
    status: int
    headers: httpx.Headers
    body: bytes

    def json(self) -> Any:
        try:
            return json.loads(self.body)
        except (ValueError, RecursionError) as exc:
            raise FhirClientError("The server returned a response that is not valid JSON.", self.status) from exc


def _send(http: httpx.Client, method: str, url: str, *, label: str, max_bytes: int,
          sleep: Callable[[float], None], retries: int = MAX_RETRIES,
          prepare: Callable[[], Mapping[str, Any]] | None = None, **kw: Any) -> _Raw:
    """One request with retries on 429/502/503/504 and connection errors, and a
    streamed body-size cap so a hostile or broken server cannot exhaust memory.

    `retries=0` sends exactly once. `prepare`, if given, is called before every
    attempt and its result is merged into the request arguments (e.g. a freshly
    signed client assertion)."""
    for attempt in range(retries + 1):
        req_kw = {**kw, **(prepare() if prepare else {})}
        try:
            with http.stream(method, url, **req_kw) as resp:
                declared = resp.headers.get("Content-Length")
                if declared and declared.isdigit() and int(declared) > max_bytes:
                    raise FhirClientError(f"{label}: response is larger than {max_bytes} bytes.", resp.status_code)
                chunks, total = [], 0
                for chunk in resp.iter_bytes():
                    total += len(chunk)
                    if total > max_bytes:
                        raise FhirClientError(f"{label}: response is larger than {max_bytes} bytes.", resp.status_code)
                    chunks.append(chunk)
                raw = _Raw(resp.status_code, resp.headers, b"".join(chunks))
        except httpx.TransportError as exc:
            if attempt < retries:
                sleep(_retry_delay(None, attempt))
                continue
            raise FhirClientError(f"{label}: could not reach the server ({type(exc).__name__}).") from None
        if raw.status in RETRY_STATUSES and attempt < retries:
            sleep(_retry_delay(raw.headers, attempt))
            continue
        return raw
    raise AssertionError("unreachable")


def _fail(raw: _Raw, label: str, hide: Iterable[str | None] = ()) -> FhirClientError:
    detail = _sanitize(_error_detail(raw.body), hide)
    return FhirClientError(f"{label} failed with HTTP {raw.status}" + (f": {detail}" if detail else "."), raw.status)


# ---------------------------------------------------------------- discovery

def _strs(v: Any) -> tuple[str, ...]:
    return tuple(x for x in v if isinstance(x, str)) if isinstance(v, list) else ()


def _endpoint(v: Any, what: str) -> str | None:
    return check_url(v, what) if isinstance(v, str) and v else None


def discover(settings: SmartSettings, http: httpx.Client | None = None, *,
             sleep: Callable[[float], None] = time.sleep, max_bytes: int = 10 * 1024 * 1024) -> SmartConfiguration:
    """Read .well-known/smart-configuration, falling back to the CapabilityStatement's oauth-uris."""
    own = http is None
    http = http or _new_http(settings)
    try:
        hdr = {"Accept": "application/json"}
        raw = _send(http, "GET", f"{settings.base_url}/.well-known/smart-configuration",
                    label="SMART discovery", max_bytes=max_bytes, sleep=sleep, headers=hdr)
        data: Any = None
        if raw.status == 200:
            try:
                data = raw.json()
            except FhirClientError:
                data = None
        if isinstance(data, dict) and (data.get("token_endpoint") or data.get("authorization_endpoint")):
            return SmartConfiguration(
                authorization_endpoint=_endpoint(data.get("authorization_endpoint"), "authorization_endpoint"),
                token_endpoint=_endpoint(data.get("token_endpoint"), "token_endpoint"),
                capabilities=_strs(data.get("capabilities")),
                code_challenge_methods_supported=_strs(data.get("code_challenge_methods_supported")),
                token_endpoint_auth_methods_supported=_strs(data.get("token_endpoint_auth_methods_supported")),
                grant_types_supported=_strs(data.get("grant_types_supported")),
                scopes_supported=_strs(data.get("scopes_supported")),
                issuer=data.get("issuer") if isinstance(data.get("issuer"), str) else None,
                jwks_uri=_endpoint(data.get("jwks_uri"), "jwks_uri"),
            )
        raw = _send(http, "GET", f"{settings.base_url}/metadata", label="FHIR metadata",
                    max_bytes=max_bytes, sleep=sleep, headers={"Accept": FHIR_JSON})
        if raw.status != 200:
            raise _fail(raw, "SMART discovery (metadata)")
        cs = raw.json()
        uris: dict[str, str] = {}
        for rest in (cs.get("rest") or []) if isinstance(cs, dict) else []:
            for ext in ((rest or {}).get("security") or {}).get("extension") or []:
                if isinstance(ext, dict) and ext.get("url") == OAUTH_URIS_EXT:
                    for sub in ext.get("extension") or []:
                        if isinstance(sub, dict) and isinstance(sub.get("valueUri"), str):
                            uris[str(sub.get("url"))] = sub["valueUri"]
        return SmartConfiguration(
            authorization_endpoint=_endpoint(uris.get("authorize"), "authorize endpoint"),
            token_endpoint=_endpoint(uris.get("token"), "token endpoint"),
            source="metadata",
        )
    finally:
        if own:
            http.close()


# ---------------------------------------------------------------- JWT / JWKS

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _int_b64(n: int, length: int | None = None) -> str:
    length = length or max(1, (n.bit_length() + 7) // 8)
    return _b64url(n.to_bytes(length, "big"))


def load_private_key(pem: bytes) -> rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey:
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (ValueError, TypeError) as exc:
        raise SmartConfigError("The private key is not an unencrypted PEM private key.") from exc
    if isinstance(key, rsa.RSAPrivateKey):
        if key.key_size < 2048:
            raise SmartConfigError("RSA keys must be at least 2048 bits.")
        return key
    if isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, ec.SECP384R1):
        return key
    raise SmartConfigError("The private key must be RSA (RS384) or EC P-384 (ES384).")


def public_jwk(key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey, kid: str | None = None) -> dict[str, Any]:
    """Public JWK; kid defaults to the RFC 7638 thumbprint."""
    pub = key.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        nums = pub.public_numbers()
        core = {"e": _int_b64(nums.e), "kty": "RSA", "n": _int_b64(nums.n)}
        alg = "RS384"
    else:
        nums = pub.public_numbers()
        core = {"crv": "P-384", "kty": "EC", "x": _int_b64(nums.x, 48), "y": _int_b64(nums.y, 48)}
        alg = "ES384"
    thumb = _b64url(hashlib.sha256(json.dumps(core, separators=(",", ":"), sort_keys=True).encode()).digest())
    return {**core, "alg": alg, "use": "sig", "kid": kid or thumb}


def generate_jwks(private_key_pem: bytes | str, kid: str | None = None) -> dict[str, Any]:
    """Public JWKS to register with the EHR (e.g. Epic's 'JWK Set URL' or upload)."""
    pem = private_key_pem.encode() if isinstance(private_key_pem, str) else private_key_pem
    return {"keys": [public_jwk(load_private_key(pem), kid)]}


def sign_jwt(claims: dict[str, Any], key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
             alg: str, kid: str) -> str:
    header = {"alg": alg, "typ": "JWT", "kid": kid}
    signing_input = f"{_b64url(json.dumps(header, separators=(',', ':')).encode())}." \
                    f"{_b64url(json.dumps(claims, separators=(',', ':')).encode())}".encode()
    if alg == "RS384":
        if not isinstance(key, rsa.RSAPrivateKey):
            raise SmartConfigError("FHIR_JWT_ALG=RS384 needs an RSA private key.")
        sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA384())
    elif alg == "ES384":
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise SmartConfigError("FHIR_JWT_ALG=ES384 needs an EC P-384 private key.")
        # JWS wants raw r||s (48 bytes each), cryptography returns DER.
        r, s = decode_dss_signature(key.sign(signing_input, ec.ECDSA(hashes.SHA384())))
        sig = r.to_bytes(48, "big") + s.to_bytes(48, "big")
    else:
        raise SmartConfigError("FHIR_JWT_ALG must be RS384 or ES384.")
    return f"{signing_input.decode()}.{_b64url(sig)}"


def client_assertion(settings: SmartSettings, token_endpoint: str, now: float | None = None) -> str:
    """private_key_jwt assertion per SMART Backend Services."""
    if not settings.client_id or not settings.private_key_path:
        raise SmartConfigError("Backend services need FHIR_CLIENT_ID and FHIR_PRIVATE_KEY_PATH.")
    try:
        pem = settings.private_key_path.read_bytes()
    except OSError:
        raise SmartConfigError("FHIR_PRIVATE_KEY_PATH could not be read.") from None
    key = load_private_key(pem)
    kid = settings.key_id or public_jwk(key)["kid"]
    now = int(time.time() if now is None else now)
    claims = {"iss": settings.client_id, "sub": settings.client_id, "aud": token_endpoint,
              "iat": now, "exp": now + ASSERTION_LIFETIME, "jti": secrets.token_urlsafe(24)}
    return sign_jwt(claims, key, settings.jwt_alg, kid)


# ---------------------------------------------------------------- token flows

def _token_post(settings: SmartSettings, config: SmartConfiguration,
                data: dict[str, str] | Callable[[], dict[str, str]],
                http: httpx.Client | None, label: str, *, basic: bool = False,
                sleep: Callable[[float], None] = time.sleep, now: float | None = None,
                keep_refresh: str | None = None, retry: bool = True) -> Token:
    """POST to the token endpoint. `data` may be a callable, which is called again
    for every attempt (so a backend client assertion is re-signed with a new jti).
    `retry=False` sends once only (an authorization code is single-use)."""
    if not config.token_endpoint:
        raise FhirClientError("The server did not advertise a token endpoint.")
    own = http is None
    http = http or _new_http(settings)
    hide: list[str | None] = [settings.client_secret]

    def prepare() -> dict[str, Any]:
        body = data() if callable(data) else data
        hide.extend(body.get(k) for k in ("code", "refresh_token", "client_assertion", "code_verifier"))
        return {"data": body}
    headers = {"Accept": "application/json"}
    if basic and settings.client_secret:
        # RFC 6749 2.3.1: form-urlencode both parts before Basic encoding.
        cred = f"{quote(settings.client_id or '', safe='')}:{quote(settings.client_secret, safe='')}"
        headers["Authorization"] = "Basic " + base64.b64encode(cred.encode()).decode()
    try:
        raw = _send(http, "POST", config.token_endpoint, label=label, max_bytes=1024 * 1024, sleep=sleep,
                    retries=MAX_RETRIES if retry else 0, prepare=prepare, headers=headers)
    finally:
        if own:
            http.close()
    if raw.status != 200:
        raise _fail(raw, label, hide)
    return Token.from_response(raw.json(), now=now, refresh_token=keep_refresh)


def request_backend_token(settings: SmartSettings, config: SmartConfiguration, http: httpx.Client | None = None,
                          *, sleep: Callable[[float], None] = time.sleep, now: float | None = None) -> Token:
    """client_credentials grant with a signed JWT assertion."""
    if not config.token_endpoint:
        raise FhirClientError("The server did not advertise a token endpoint.")
    endpoint = config.token_endpoint
    client_assertion(settings, endpoint, now)  # fail fast on key/config problems before any request
    first = [True]

    def data() -> dict[str, str]:
        # A fresh assertion (new jti, iat, exp) for every attempt: a server may reject a reused jti.
        stamp = now if first[0] else None
        first[0] = False
        return {"grant_type": "client_credentials", "scope": settings.scopes,
                "client_assertion_type": ASSERTION_TYPE,
                "client_assertion": client_assertion(settings, endpoint, stamp)}
    return _token_post(settings, config, data, http, "Backend token request", sleep=sleep, now=now)


def pkce_pair() -> tuple[str, str]:
    """(code_verifier, S256 code_challenge)."""
    verifier = secrets.token_urlsafe(64)[:96]
    return verifier, _b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def begin_authorization(settings: SmartSettings, config: SmartConfiguration, aud: str | None = None,
                        launch: str | None = None) -> AuthRequest:
    """Authorization URL for a standalone (or EHR, with `launch`) launch using PKCE S256."""
    if not config.authorization_endpoint:
        raise FhirClientError("The server did not advertise an authorization endpoint.")
    if not settings.client_id or not settings.redirect_uri:
        raise SmartConfigError("Standalone launch needs FHIR_CLIENT_ID and FHIR_REDIRECT_URI.")
    methods = config.code_challenge_methods_supported
    if methods and "S256" not in methods:
        raise FhirClientError("The server does not support PKCE S256.")
    verifier, challenge = pkce_pair()
    state = secrets.token_urlsafe(32)
    params = {"response_type": "code", "client_id": settings.client_id, "redirect_uri": settings.redirect_uri,
              "scope": settings.scopes, "state": state, "aud": aud or settings.base_url,
              "code_challenge": challenge, "code_challenge_method": "S256"}
    if launch:
        params["launch"] = launch
    sep = "&" if urlsplit(config.authorization_endpoint).query else "?"
    return AuthRequest(url=config.authorization_endpoint + sep + urlencode(params), state=state,
                       code_verifier=verifier)


def exchange_code(settings: SmartSettings, config: SmartConfiguration, code: str, state: str,
                  expected_state: str, code_verifier: str, http: httpx.Client | None = None,
                  *, sleep: Callable[[float], None] = time.sleep, now: float | None = None) -> Token:
    """Swap an authorization code for a token after checking state in constant time."""
    if not state or not hmac.compare_digest(state.encode(), expected_state.encode()):
        raise FhirClientError("The authorization response state does not match; possible CSRF.")
    data = {"grant_type": "authorization_code", "code": code, "redirect_uri": settings.redirect_uri or "",
            "code_verifier": code_verifier}
    if not settings.client_secret:
        data["client_id"] = settings.client_id or ""
    # Never retried: the code is single-use, so a retry after a lost response could only fail
    # (or, on some servers, revoke the tokens already issued for it).
    return _token_post(settings, config, data, http, "Authorization code exchange", basic=True,
                       sleep=sleep, now=now, retry=False)


def refresh(settings: SmartSettings, config: SmartConfiguration, refresh_token: str,
            http: httpx.Client | None = None, *, sleep: Callable[[float], None] = time.sleep,
            now: float | None = None) -> Token:
    """refresh_token grant; keeps the old refresh token if the server does not rotate it."""
    data = {"grant_type": "refresh_token", "refresh_token": refresh_token}
    if not settings.client_secret:
        data["client_id"] = settings.client_id or ""
    return _token_post(settings, config, data, http, "Token refresh", basic=True, sleep=sleep, now=now,
                       keep_refresh=refresh_token)


# ---------------------------------------------------------------- FHIR client

def _check_type(rtype: str) -> str:
    if not isinstance(rtype, str) or not _TYPE_RE.fullmatch(rtype):
        raise FhirClientError("Invalid FHIR resource type.")
    return rtype


def _check_id(rid: str) -> str:
    if not isinstance(rid, str) or not _ID_RE.fullmatch(rid):
        raise FhirClientError("Invalid FHIR resource id.")
    return rid


def _origin_and_path(url: str) -> tuple[str, str, int, str]:
    """(scheme, host, port, path) with dot segments removed and no trailing slash."""
    p = urlsplit(url)
    port = p.port or (443 if p.scheme == "https" else 80)
    path = posixpath.normpath(p.path) if p.path else ""
    return p.scheme.lower(), (p.hostname or "").lower(), port, path.rstrip("/")


class FhirClient:
    """FHIR R4 REST client bound to one base URL. Use as a context manager."""

    def __init__(self, settings: SmartSettings, http: httpx.Client | None = None, *,
                 config: SmartConfiguration | None = None, token: Token | None = None,
                 sleep: Callable[[float], None] = time.sleep, now: Callable[[], float] = time.time,
                 max_pages: int = 20, max_resources: int = 2000, max_bytes: int = 10 * 1024 * 1024):
        self.settings = settings
        self._own = http is None
        self.http = http or _new_http(settings)
        self.config = config
        self.token = token
        self.sleep, self.now = sleep, now
        self.max_pages, self.max_resources, self.max_bytes = max_pages, max_resources, max_bytes
        self.warnings: list[str] = []
        self._base = _origin_and_path(settings.base_url)

    def __repr__(self) -> str:
        return f"FhirClient(base_url={self.settings.base_url!r}, auth_mode={self.settings.auth_mode!r})"

    def __enter__(self) -> FhirClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._own:
            self.http.close()

    # -- auth

    def _config(self) -> SmartConfiguration:
        if self.config is None:
            self.config = discover(self.settings, self.http, sleep=self.sleep, max_bytes=self.max_bytes)
        return self.config

    def _refresh_token(self) -> None:
        mode = self.settings.auth_mode
        if mode == "backend":
            self.token = request_backend_token(self.settings, self._config(), self.http, sleep=self.sleep,
                                               now=self.now())
        elif mode == "standalone" and self.token and self.token.refresh_token:
            self.token = refresh(self.settings, self._config(), self.token.refresh_token, self.http,
                                 sleep=self.sleep, now=self.now())
        else:
            raise FhirClientError("The access token is missing or expired; authorize again.")

    def _auth_header(self) -> dict[str, str]:
        if self.settings.auth_mode == "open":
            return {}
        if self.token is None or self.token.expired(self.now()):
            self._refresh_token()
        assert self.token is not None
        return {"Authorization": f"Bearer {self.token.access_token}"}

    def _can_refresh(self) -> bool:
        mode = self.settings.auth_mode
        return mode == "backend" or (mode == "standalone" and bool(self.token and self.token.refresh_token))

    # -- transport

    def same_server(self, url: str) -> bool:
        """True when `url` is the base URL or below it (same scheme, host, port).

        Dot segments are resolved before the prefix check, and URLs with encoded
        dots or backslashes are refused outright since servers decode them differently."""
        if not isinstance(url, str) or "\\" in url or "%2e" in url.lower():
            return False
        try:
            scheme, host, port, path = _origin_and_path(url)
        except ValueError:
            return False
        bs, bh, bp, bpath = self._base
        return (scheme, host, port) == (bs, bh, bp) and (path == bpath or path.startswith(bpath + "/"))

    def _get(self, url: str, label: str, params: Mapping[str, Any] | None = None,
             accept: str = FHIR_JSON) -> _Raw:
        retried_auth = False
        while True:
            headers = {"Accept": accept, **self._auth_header()}
            hide = [self.token.access_token if self.token else None, self.settings.client_secret]
            raw = _send(self.http, "GET", url, label=label, max_bytes=self.max_bytes, sleep=self.sleep,
                        headers=headers, params=params)
            if raw.status == 401 and not retried_auth and self._can_refresh():
                retried_auth = True
                self._refresh_token()
                continue
            if raw.status != 200:
                raise _fail(raw, label, hide)
            return raw

    def _json_resource(self, raw: _Raw) -> dict[str, Any]:
        data = raw.json()
        if not isinstance(data, dict) or not isinstance(data.get("resourceType"), str):
            raise FhirClientError("The server returned JSON that is not a FHIR resource.", raw.status)
        return data

    # -- API

    def read(self, rtype: str, rid: str) -> dict[str, Any]:
        url = f"{self.settings.base_url}/{_check_type(rtype)}/{_check_id(rid)}"
        res = self._json_resource(self._get(url, f"Read {rtype}"))
        if res.get("resourceType") != rtype:
            raise FhirClientError(f"Read {rtype} returned a {res.get('resourceType')} instead.")
        return res

    def search(self, rtype: str, params: Mapping[str, Any] | None = None, *,
               max_pages: int | None = None) -> list[dict[str, Any]]:
        """Search and follow `next` links on the same server, within page and resource limits."""
        label = f"Search {_check_type(rtype)}"
        url: str | None = f"{self.settings.base_url}/{rtype}"
        q: Mapping[str, Any] | None = dict(params or {})
        out: list[dict[str, Any]] = []
        pages = max_pages or self.max_pages
        for page in range(pages):
            assert url is not None
            bundle = self._json_resource(self._get(url, label, q))
            if bundle.get("resourceType") != "Bundle":
                raise FhirClientError(f"{label} did not return a Bundle.")
            for entry in bundle.get("entry") or []:
                res = entry.get("resource") if isinstance(entry, dict) else None
                if not isinstance(res, dict) or not isinstance(res.get("resourceType"), str):
                    continue
                if (entry.get("search") or {}).get("mode") == "outcome" or res["resourceType"] == "OperationOutcome":
                    continue
                if len(out) >= self.max_resources:
                    self.warnings.append(f"{label}: stopped at {self.max_resources} resources.")
                    return out
                out.append(res)
            nxt = next((link.get("url") for link in bundle.get("link") or []
                        if isinstance(link, dict) and link.get("relation") == "next"), None)
            if not isinstance(nxt, str) or not nxt:
                return out
            nxt = urljoin(self.settings.base_url + "/", nxt)
            if not self.same_server(nxt):
                # Following a link to another host would send our token there (SSRF / token leak).
                self.warnings.append(f"{label}: next page link points to another server; stopped paging.")
                return out
            if page == pages - 1:
                if max_pages is None:
                    self.warnings.append(f"{label}: stopped after {pages} pages.")
                return out
            url, q = nxt, None  # the next link already carries the query
        return out

    def binary(self, url_or_ref: str) -> dict[str, Any]:
        """Fetch a Binary from this server; returns a Binary resource with base64 `data`."""
        ref = url_or_ref.strip()
        if "://" in ref:
            if not self.same_server(ref):
                raise FhirClientError("Refusing to fetch a Binary from another server.")
            url = ref
        else:
            parts = ref.strip("/").split("/")
            if len(parts) != 2:
                raise FhirClientError("Invalid Binary reference.")
            url = f"{self.settings.base_url}/{_check_type(parts[0])}/{_check_id(parts[1])}"
        raw = self._get(url, "Read Binary", accept=f"{FHIR_JSON}, */*;q=0.5")
        ctype = raw.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if ctype in (FHIR_JSON, "application/json", "application/json+fhir"):
            res = self._json_resource(raw)
            if res.get("resourceType") == "Binary":
                return res
            raise FhirClientError("Binary reference returned a different resource type.")
        return {"resourceType": "Binary", "contentType": ctype or "application/octet-stream",
                "data": base64.b64encode(raw.body).decode()}


# ---------------------------------------------------------------- discharge bundle

INPATIENT_CLASSES = {"IMP", "ACUTE", "NONAC"}
SKIP_STATUSES = {400, 403, 404, 405, 422, 501}


def _enc_class(enc: dict[str, Any]) -> set[str]:
    cls = enc.get("class")
    codes: set[str] = set()
    for item in cls if isinstance(cls, list) else [cls]:  # R4 Coding; R5 list of CodeableConcept
        if not isinstance(item, dict):
            continue
        for c in [item, *(item.get("coding") or [])]:
            if isinstance(c, dict) and isinstance(c.get("code"), str):
                codes.add(c["code"].upper())
    return codes


def _period(enc: dict[str, Any]) -> tuple[str, str]:
    p = enc.get("period") if isinstance(enc.get("period"), dict) else {}
    end = enc.get("actualPeriod", {}).get("end") if isinstance(enc.get("actualPeriod"), dict) else None
    return str(p.get("start") or ""), str(p.get("end") or end or "")


def _pick_encounter(encs: list[dict[str, Any]], warnings: list[str]) -> dict[str, Any]:
    finished = [e for e in encs if e.get("status") == "finished" or _period(e)[1]]
    inpatient = [e for e in finished if _enc_class(e) & INPATIENT_CLASSES]
    pool = inpatient or finished
    if not pool:
        raise FhirClientError("No finished encounter was found for this patient; pass --encounter.")
    # Sort ourselves: some servers ignore _sort.
    pool.sort(key=lambda e: (_period(e)[1] or _period(e)[0]), reverse=True)
    chosen = pool[0]
    kind = "inpatient" if inpatient else "finished (no inpatient encounter found)"
    warnings.append(f"No encounter given; chose the most recent {kind} encounter "
                    f"Encounter/{chosen.get('id')} ending {_period(chosen)[1][:10] or 'unknown'}.")
    return chosen


def _encounter_refs(res: dict[str, Any]) -> list[str]:
    refs: list[Any] = []
    for v in (res.get("encounter"), (res.get("context") or {}).get("encounter")
              if isinstance(res.get("context"), dict) else None):
        refs.extend(v if isinstance(v, list) else [v])
    return [r["reference"] for r in refs if isinstance(r, dict) and isinstance(r.get("reference"), str)]


_PATIENT_REF_RE = re.compile(r"(?:^|/)Patient/([A-Za-z0-9\-.]{1,64})(?:/_history/[^/]+)?$")


def _patient_ref_id(ref: Any) -> str | None:
    """The id in a Patient reference ("Patient/x", a full URL ending in it, optionally
    with /_history/n); None when the value is not a Patient reference."""
    if not isinstance(ref, str):
        return None
    m = _PATIENT_REF_RE.search(ref.strip())
    return m.group(1) if m else None


def _patient_refs(res: dict[str, Any]) -> list[str]:
    out = []
    for key in ("subject", "patient"):
        v = res.get(key)
        for item in v if isinstance(v, list) else [v]:
            if isinstance(item, dict) and isinstance(item.get("reference"), str):
                out.append(item["reference"])
    return out


def _names_other_patient(res: dict[str, Any], patient_id: str) -> bool:
    """True when the resource's subject/patient points at a Patient other than ours."""
    ids = [_patient_ref_id(r) for r in _patient_refs(res)]
    return any(i is not None and i != patient_id for i in ids)


def _patient_stub(patient: dict[str, Any], patient_id: str) -> dict[str, Any]:
    """Only what the parser needs to redact the patient from narrative text; nothing
    else (no address, contacts, extensions...) leaves this module."""
    stub: dict[str, Any] = {"resourceType": "Patient", "id": patient_id}
    names = []
    raw_names = patient.get("name") if isinstance(patient.get("name"), list) else []
    for n in raw_names:
        if not isinstance(n, dict):
            continue
        name: dict[str, Any] = {}
        given = [g for g in n.get("given") or [] if isinstance(g, str)] if isinstance(n.get("given"), list) else []
        if given:
            name["given"] = given
        for k in ("family", "text"):
            if isinstance(n.get(k), str):
                name[k] = n[k]
        if name:
            names.append(name)
    if names:
        stub["name"] = names
    if isinstance(patient.get("birthDate"), str):
        stub["birthDate"] = patient["birthDate"]
    for key in ("identifier", "telecom"):
        vals = patient.get(key) if isinstance(patient.get(key), list) else []
        kept = [{"value": v["value"]} for v in vals if isinstance(v, dict) and isinstance(v.get("value"), str)]
        if kept:
            stub[key] = kept
    return stub


def _try_search(client: FhirClient, rtype: str, attempts: list[dict[str, Any]], warnings: list[str],
                encounter_ref: str | None = None) -> list[dict[str, Any]]:
    """Try each parameter set in turn; a 400-style rejection moves to the next one,
    a 403 (scope not granted) or unsupported type is skipped with a warning."""
    for i, params in enumerate(attempts):
        try:
            found = client.search(rtype, params)
        except FhirClientError as exc:
            if exc.status not in SKIP_STATUSES:
                raise
            if exc.status == 400 and i + 1 < len(attempts):
                dropped = sorted(set(params) - set(attempts[i + 1]))
                warnings.append(f"{rtype}: server rejected the search; retried without {', '.join(dropped)}.")
                continue
            why = "access not granted (check scopes)" if exc.status == 403 else f"HTTP {exc.status}"
            warnings.append(f"{rtype}: skipped, {why}.")
            return []
        if encounter_ref and "encounter" not in params:
            # Patient-wide fallback: drop items that clearly belong to another encounter.
            kept = [r for r in found if not _encounter_refs(r)
                    or any(ref.endswith(encounter_ref) for ref in _encounter_refs(r))]
            if len(kept) < len(found):
                warnings.append(f"{rtype}: dropped {len(found) - len(kept)} item(s) from other encounters.")
            found = kept
        return found
    return []


def fetch_discharge_bundle(client: FhirClient, patient_id: str,
                           encounter_id: str | None = None) -> tuple[dict[str, Any], list[str]]:
    """Collect what a discharge check needs into a collection Bundle.

    The Patient appears only as a stub (id, names, birth date, identifier and telecom
    values) so the parser can redact the patient from narrative text; it is never output."""
    _check_id(patient_id)
    start = len(client.warnings)
    warnings: list[str] = []
    if encounter_id:
        encounter = client.read("Encounter", _check_id(encounter_id))
        subject = encounter.get("subject") if isinstance(encounter.get("subject"), dict) else {}
        if _patient_ref_id(subject.get("reference")) != patient_id:
            raise FhirClientError("The encounter does not belong to that patient.")
    else:
        encs = _try_search(client, "Encounter", [{"patient": patient_id, "_sort": "-date", "_count": "10"},
                                                 {"patient": patient_id, "_count": "10"}], warnings)
        encs = [e for e in encs if e.get("resourceType") == "Encounter" and not _names_other_patient(e, patient_id)]
        encounter = client.read("Encounter", _check_id(str(_pick_encounter(encs, warnings).get("id"))))
        if _names_other_patient(encounter, patient_id):
            raise FhirClientError("The encounter does not belong to that patient.")
    eid = str(encounter["id"])
    eref = f"Encounter/{eid}"
    discharge_date = _period(encounter)[1][:10]

    p = {"patient": patient_id}
    pe = {"patient": patient_id, "encounter": eid}
    stub: dict[str, Any] | None = None
    try:
        stub = _patient_stub(client.read("Patient", patient_id), patient_id)
    except FhirClientError as exc:
        if exc.status not in (403, 404):
            raise
        why = "access not granted (check scopes)" if exc.status == 403 else "not found"
        warnings.append(f"Patient: not read, {why}; the patient's name cannot be redacted from notes.")
    resources: list[dict[str, Any]] = [encounter]
    plan: list[tuple[str, list[dict[str, Any]]]] = [
        # Epic requires a category on Condition searches.
        ("Condition", [{**pe, "category": "encounter-diagnosis"}, pe, p]),
        ("Condition", [{**p, "category": "problem-list-item"}]),
        ("MedicationRequest", [{**pe, "_include": "MedicationRequest:medication"}, pe, p]),
        ("AllergyIntolerance", [p]),
        ("DocumentReference", [pe, p]),
        ("DiagnosticReport", [pe, p]),
    ]
    if discharge_date:
        plan.append(("Appointment", [{**p, "date": f"ge{discharge_date}"}, p]))
    else:
        warnings.append("Encounter has no end date; follow-up appointments were not searched.")
    plan += [("ServiceRequest", [pe, p]), ("CarePlan", [pe, p]), ("Goal", [p]), ("Procedure", [pe, p])]
    for rtype, attempts in plan:
        found = _try_search(client, rtype, attempts, warnings, eref)
        if rtype == "Appointment":
            # Also covers servers that rejected the date filter: keep only appointments from discharge on.
            before = [a for a in found if a.get("resourceType") == "Appointment" and isinstance(a.get("start"), str)
                      and a["start"][:10] < discharge_date]
            found = [a for a in found if not any(a is b for b in before)]
        other = [r for r in found if _names_other_patient(r, patient_id)]
        if other:
            warnings.append(f"{rtype}: dropped {len(other)} item(s) that belong to another patient.")
            found = [r for r in found if not any(r is o for o in other)]
        resources.extend(found)

    # Inline attachments that are only referenced by URL, from this server only.
    for res in resources:
        if res.get("resourceType") != "DocumentReference":
            continue
        for content in res.get("content") or []:
            att = content.get("attachment") if isinstance(content, dict) else None
            if not isinstance(att, dict) or att.get("data") or not isinstance(att.get("url"), str):
                continue
            url = att["url"]
            absolute = urljoin(client.settings.base_url + "/", url)
            if not client.same_server(absolute):
                warnings.append(f"DocumentReference/{res.get('id')}: attachment on another server not fetched.")
                continue
            try:
                binary = client.binary(url if "://" not in url else absolute)
            except FhirClientError as exc:
                warnings.append(f"DocumentReference/{res.get('id')}: attachment not fetched ({exc}).")
                continue
            if isinstance(binary.get("data"), str):
                att["data"] = binary["data"]
                att.setdefault("contentType", binary.get("contentType"))

    seen: set[str] = set()
    entries = []
    if stub is not None:
        resources.insert(1, stub)
    for res in resources:
        rtype = res.get("resourceType")
        if rtype == "Patient" and res is not stub:  # only the redaction stub, never a full Patient
            continue
        rid = res.get("id")
        if isinstance(rid, str) and rid:
            key = f"{rtype}/{rid}"
            if key in seen:
                continue
            seen.add(key)
            full_url = f"{client.settings.base_url}/{key}"
        else:
            full_url = f"urn:uuid:{uuid.uuid4()}"
        entries.append({"fullUrl": full_url, "resource": copy.deepcopy(res)})
    bundle = {"resourceType": "Bundle", "type": "collection",
              "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"), "entry": entries}
    return bundle, client.warnings[start:] + warnings


# ---------------------------------------------------------------- CLI

def _main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "jwks":
        try:
            print(json.dumps(generate_jwks(Path(argv[1]).read_bytes()), indent=2))
        except (OSError, SmartConfigError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return 0
    print("usage: python -m app.fhir.smart jwks <private-key.pem>", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
