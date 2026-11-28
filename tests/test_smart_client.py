"""SMART on FHIR client against a fake sandbox (httpx.MockTransport; no network, no sleeps)."""
import base64
import hashlib
import json
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from app.fhir import smart
from app.fhir.smart import (
    FhirClient,
    FhirClientError,
    SmartConfigError,
    SmartConfiguration,
    SmartSettings,
    Token,
    begin_authorization,
    discover,
    exchange_code,
    fetch_discharge_bundle,
    generate_jwks,
    refresh,
    request_backend_token,
)

BASE = "https://fhir.test/r4"
TOKEN_URL = "https://fhir.test/auth/token"
AUTH_URL = "https://fhir.test/auth/authorize"
CONFIG = SmartConfiguration(authorization_endpoint=AUTH_URL, token_endpoint=TOKEN_URL,
                            code_challenge_methods_supported=("S256",))


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def bundle(*resources, next_url=None, mode="match"):
    b = {"resourceType": "Bundle", "type": "searchset",
         "entry": [{"resource": r, "search": {"mode": mode}} for r in resources]}
    if next_url:
        b["link"] = [{"relation": "next", "url": next_url}]
    return b


def fjson(obj, status=200, headers=None):
    return httpx.Response(status, json=obj, headers=headers)


def client_for(handler, settings=None, **kw):
    http = httpx.Client(transport=httpx.MockTransport(handler))
    sleeps: list[float] = []
    c = FhirClient(settings or SmartSettings(base_url=BASE), http, sleep=sleeps.append, **kw)
    return c, sleeps


def write_key(tmp_path, alg):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048) if alg == "RS384" \
        else ec.generate_private_key(ec.SECP384R1())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    path = tmp_path / f"{alg}.pem"
    path.write_bytes(pem)
    return key, path


def verify_assertion(jwt: str, key, alg: str) -> dict:
    h, c, s = jwt.split(".")
    header, claims, sig = json.loads(b64d(h)), json.loads(b64d(c)), b64d(s)
    assert header["alg"] == alg and header["kid"]
    data = f"{h}.{c}".encode()
    if alg == "RS384":
        key.public_key().verify(sig, data, padding.PKCS1v15(), hashes.SHA384())
    else:
        assert len(sig) == 96
        der = encode_dss_signature(int.from_bytes(sig[:48], "big"), int.from_bytes(sig[48:], "big"))
        key.public_key().verify(der, data, ec.ECDSA(hashes.SHA384()))
    return {"header": header, **claims}


# ---------------------------------------------------------------- settings

def test_settings_from_env_defaults_and_validation(tmp_path):
    s = SmartSettings.from_env({"FHIR_BASE_URL": "https://r4.smarthealthit.org/"})
    assert s.base_url == "https://r4.smarthealthit.org" and s.auth_mode == "open" and s.timeout_seconds == 20
    assert SmartSettings.from_env({"FHIR_BASE_URL": "http://localhost:8080/fhir"}).base_url.startswith("http://")
    with pytest.raises(SmartConfigError, match="https"):
        SmartSettings.from_env({"FHIR_BASE_URL": "http://fhir.example.org"})
    with pytest.raises(SmartConfigError, match="FHIR_BASE_URL"):
        SmartSettings.from_env({})
    with pytest.raises(SmartConfigError, match="FHIR_AUTH_MODE"):
        SmartSettings.from_env({"FHIR_BASE_URL": BASE, "FHIR_AUTH_MODE": "magic"})
    with pytest.raises(SmartConfigError, match="FHIR_CLIENT_ID"):
        SmartSettings.from_env({"FHIR_BASE_URL": BASE, "FHIR_AUTH_MODE": "backend"})
    with pytest.raises(SmartConfigError, match="FHIR_PRIVATE_KEY_PATH"):
        SmartSettings.from_env({"FHIR_BASE_URL": BASE, "FHIR_AUTH_MODE": "backend", "FHIR_CLIENT_ID": "x",
                                "FHIR_PRIVATE_KEY_PATH": str(tmp_path / "missing.pem")})
    with pytest.raises(SmartConfigError, match="FHIR_REDIRECT_URI"):
        SmartSettings.from_env({"FHIR_BASE_URL": BASE, "FHIR_AUTH_MODE": "standalone", "FHIR_CLIENT_ID": "x"})
    _, path = write_key(tmp_path, "ES384")
    b = SmartSettings.from_env({"FHIR_BASE_URL": BASE, "FHIR_AUTH_MODE": "backend", "FHIR_CLIENT_ID": "app",
                                "FHIR_PRIVATE_KEY_PATH": str(path), "FHIR_JWT_ALG": "es384"})
    assert b.jwt_alg == "ES384" and "system/Encounter.read" in b.scopes
    v2 = SmartSettings.from_env({"FHIR_BASE_URL": BASE, "FHIR_SCOPES": "system/Patient.rs  system/Encounter.rs"})
    assert v2.scopes == "system/Patient.rs system/Encounter.rs"


def test_secrets_not_in_repr(tmp_path):
    s = SmartSettings(base_url=BASE, auth_mode="standalone", client_id="app", client_secret="s3cr3t-value",
                      private_key_path=tmp_path / "very-secret-key.pem", redirect_uri="http://localhost:9/cb")
    assert "s3cr3t-value" not in repr(s) and "very-secret-key" not in repr(s) and "s3cr3t" not in str(s)
    t = Token(access_token="tok-abc-123", refresh_token="ref-xyz-789")
    assert "tok-abc-123" not in repr(t) and "ref-xyz-789" not in repr(t)


# ---------------------------------------------------------------- discovery

def test_discover_smart_configuration():
    def handler(req):
        assert req.url.path == "/r4/.well-known/smart-configuration"
        return fjson({"authorization_endpoint": AUTH_URL, "token_endpoint": TOKEN_URL,
                      "capabilities": ["launch-standalone", "client-confidential-asymmetric"],
                      "code_challenge_methods_supported": ["S256"]})
    cfg = discover(SmartSettings(base_url=BASE), httpx.Client(transport=httpx.MockTransport(handler)))
    assert cfg.token_endpoint == TOKEN_URL and "launch-standalone" in cfg.capabilities
    assert cfg.source == "smart-configuration"


def test_discover_falls_back_to_metadata_and_checks_https():
    def handler(req, token="https://fhir.test/auth/token"):
        if req.url.path.endswith("smart-configuration"):
            return httpx.Response(404)
        return fjson({"resourceType": "CapabilityStatement", "rest": [{"security": {"extension": [
            {"url": smart.OAUTH_URIS_EXT, "extension": [{"url": "authorize", "valueUri": AUTH_URL},
                                                        {"url": "token", "valueUri": token}]}]}}]})
    cfg = discover(SmartSettings(base_url=BASE), httpx.Client(transport=httpx.MockTransport(handler)))
    assert (cfg.authorization_endpoint, cfg.token_endpoint, cfg.source) == (AUTH_URL, TOKEN_URL, "metadata")
    bad = httpx.MockTransport(lambda r: handler(r, token="http://evil.test/token"))
    with pytest.raises(SmartConfigError, match="https"):
        discover(SmartSettings(base_url=BASE), httpx.Client(transport=bad))


# ---------------------------------------------------------------- backend services

@pytest.mark.parametrize("alg", ["RS384", "ES384"])
def test_backend_token_assertion_signed(tmp_path, alg):
    key, path = write_key(tmp_path, alg)
    settings = SmartSettings(base_url=BASE, auth_mode="backend", client_id="my-app", private_key_path=path,
                             key_id="kid-1", jwt_alg=alg, scopes="system/Patient.read")
    seen = {}

    def handler(req):
        form = parse_qs(req.content.decode())
        assert form["grant_type"] == ["client_credentials"]
        assert form["client_assertion_type"] == [smart.ASSERTION_TYPE]
        assert form["scope"] == ["system/Patient.read"]
        seen.update(verify_assertion(form["client_assertion"][0], key, alg))
        return fjson({"access_token": "at-1", "token_type": "bearer", "expires_in": 300, "scope": "system/Patient.read"})

    tok = request_backend_token(settings, CONFIG, httpx.Client(transport=httpx.MockTransport(handler)), now=1000)
    assert tok.access_token == "at-1" and tok.expires_at == 1300
    assert seen["iss"] == seen["sub"] == "my-app" and seen["aud"] == TOKEN_URL
    assert seen["header"]["kid"] == "kid-1" and 0 < seen["exp"] - seen["iat"] <= 300 and seen["jti"]
    assert not tok.expired(now=1200) and tok.expired(now=1241)


def test_backend_token_retry_resigns_assertion(tmp_path):
    key, path = write_key(tmp_path, "RS384")
    settings = SmartSettings(base_url=BASE, auth_mode="backend", client_id="my-app", private_key_path=path)
    jtis = []

    def handler(req):
        claims = verify_assertion(parse_qs(req.content.decode())["client_assertion"][0], key, "RS384")
        jtis.append(claims["jti"])
        if len(jtis) == 1:
            raise httpx.ConnectError("boom")
        if len(jtis) == 2:
            return httpx.Response(503)
        return fjson({"access_token": "at", "expires_in": 300})

    sleeps = []
    tok = request_backend_token(settings, CONFIG, httpx.Client(transport=httpx.MockTransport(handler)),
                                sleep=sleeps.append)
    assert tok.access_token == "at" and len(jtis) == 3 and len(set(jtis)) == 3 and len(sleeps) == 2


@pytest.mark.parametrize("failure", ["connect", 503, 429])
def test_code_exchange_never_retried(failure):
    s = SmartSettings(base_url=BASE, auth_mode="standalone", client_id="pub", redirect_uri="http://localhost:1/cb")
    calls = []

    def handler(req):
        calls.append(1)
        if failure == "connect":
            raise httpx.ConnectError("boom")
        return httpx.Response(failure)

    sleeps = []
    with pytest.raises(FhirClientError):
        exchange_code(s, CONFIG, "c0de", "st", "st", "v", httpx.Client(transport=httpx.MockTransport(handler)),
                      sleep=sleeps.append)
    assert len(calls) == 1 and sleeps == []


def test_generate_jwks(tmp_path):
    for alg, kty in (("RS384", "RSA"), ("ES384", "EC")):
        _, path = write_key(tmp_path, alg)
        (jwk,) = generate_jwks(path.read_bytes())["keys"]
        assert jwk["kty"] == kty and jwk["alg"] == alg and jwk["kid"] and "d" not in jwk
        assert jwk["use"] == "sig" and "key_ops" not in jwk


def test_backend_client_fetches_and_refreshes_on_401(tmp_path):
    _, path = write_key(tmp_path, "RS384")
    settings = SmartSettings(base_url=BASE, auth_mode="backend", client_id="a", private_key_path=path)
    issued = []
    calls = []

    def handler(req):
        if req.url.path.endswith("smart-configuration"):
            return fjson({"token_endpoint": TOKEN_URL})
        if str(req.url) == TOKEN_URL:
            issued.append(f"tok{len(issued)}")
            return fjson({"access_token": issued[-1], "token_type": "Bearer", "expires_in": 3600})
        calls.append(req.headers["Authorization"])
        if req.headers["Authorization"] == "Bearer tok0":
            return httpx.Response(401)
        return fjson({"resourceType": "Encounter", "id": "e1"})

    c, _ = client_for(handler, settings)
    assert c.read("Encounter", "e1")["id"] == "e1"
    assert calls == ["Bearer tok0", "Bearer tok1"] and len(issued) == 2


def test_expired_token_refetched(tmp_path):
    _, path = write_key(tmp_path, "RS384")
    settings = SmartSettings(base_url=BASE, auth_mode="backend", client_id="a", private_key_path=path)
    n = {"tok": 0}

    def handler(req):
        if str(req.url) == TOKEN_URL:
            n["tok"] += 1
            return fjson({"access_token": f"t{n['tok']}", "expires_in": 100})
        return fjson({"resourceType": "Goal", "id": "g"})

    clock = {"t": 0.0}
    c, _ = client_for(handler, settings, config=CONFIG, now=lambda: clock["t"])
    c.read("Goal", "g")
    clock["t"] = 30
    c.read("Goal", "g")
    assert n["tok"] == 1
    clock["t"] = 45  # inside the 60 s early-expiry window
    c.read("Goal", "g")
    assert n["tok"] == 2


# ---------------------------------------------------------------- standalone launch

def test_pkce_authorize_exchange_and_refresh():
    s = SmartSettings(base_url=BASE, auth_mode="standalone", client_id="pub", scopes="launch/patient openid",
                      redirect_uri="http://localhost:8765/callback")
    req = begin_authorization(s, CONFIG)
    q = {k: v[0] for k, v in parse_qs(urlsplit(req.url).query).items()}
    assert req.url.startswith(AUTH_URL + "?") and q["aud"] == BASE and q["state"] == req.state
    expected = base64.urlsafe_b64encode(hashlib.sha256(req.code_verifier.encode()).digest()).rstrip(b"=").decode()
    assert q["code_challenge"] == expected and q["code_challenge_method"] == "S256"
    assert 43 <= len(req.code_verifier) <= 128

    def handler(req_):
        form = {k: v[0] for k, v in parse_qs(req_.content.decode()).items()}
        assert "Authorization" not in req_.headers and form["client_id"] == "pub"
        if form["grant_type"] == "authorization_code":
            assert form["code_verifier"] == req.code_verifier and form["code"] == "c0de"
            return fjson({"access_token": "a1", "refresh_token": "r1", "expires_in": 60, "patient": "p1"})
        assert form["refresh_token"] == "r1"
        return fjson({"access_token": "a2", "expires_in": 60})

    http = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(FhirClientError, match="state"):
        exchange_code(s, CONFIG, "c0de", "wrong", req.state, req.code_verifier, http)
    tok = exchange_code(s, CONFIG, "c0de", req.state, req.state, req.code_verifier, http)
    assert tok.patient == "p1" and tok.refresh_token == "r1"
    tok2 = refresh(s, CONFIG, tok.refresh_token, http)
    assert tok2.access_token == "a2" and tok2.refresh_token == "r1"


def test_confidential_client_uses_basic_and_errors_hide_secret():
    s = SmartSettings(base_url=BASE, auth_mode="standalone", client_id="conf", client_secret="hush-123",
                      redirect_uri="http://localhost:1/cb")

    def handler(req):
        user, _, pw = base64.b64decode(req.headers["Authorization"].split()[1]).decode().partition(":")
        assert (user, pw) == ("conf", "hush-123") and "client_id" not in parse_qs(req.content.decode())
        return fjson({"error": "invalid_grant", "error_description": "bad code c0de for hush-123"}, 400)

    with pytest.raises(FhirClientError) as ei:
        exchange_code(s, CONFIG, "c0de", "st", "st", "verifier-1", httpx.Client(transport=httpx.MockTransport(handler)))
    assert ei.value.status == 400 and "hush-123" not in str(ei.value) and "c0de" not in str(ei.value)
    assert "invalid_grant" in str(ei.value)


# ---------------------------------------------------------------- FHIR client behaviour

def test_paging_follows_same_server_links_and_refuses_cross_origin():
    def handler(req):
        page = req.url.params.get("page")
        if page is None:
            return fjson(bundle({"resourceType": "Condition", "id": "c1"}, next_url=f"{BASE}/Condition?page=2"))
        if page == "2":
            return fjson(bundle({"resourceType": "Condition", "id": "c2"}, next_url="https://evil.test/r4/x?page=3"))
        raise AssertionError("followed a cross-origin link")

    c, _ = client_for(handler)
    assert [r["id"] for r in c.search("Condition", {"patient": "p"})] == ["c1", "c2"]
    assert any("another server" in w for w in c.warnings)


def test_paging_limits():
    def handler(req):
        n = int(req.url.params.get("page", "1"))
        return fjson(bundle(*[{"resourceType": "Goal", "id": f"g{n}-{i}"} for i in range(3)],
                            next_url=f"{BASE}/Goal?page={n + 1}"))
    c, _ = client_for(handler, max_pages=2)
    assert len(c.search("Goal", {})) == 6 and any("2 pages" in w for w in c.warnings)
    c, _ = client_for(handler, max_resources=4)
    assert len(c.search("Goal", {})) == 4 and any("4 resources" in w for w in c.warnings)


def test_retry_after_on_429_and_gives_up():
    n = {"calls": 0}

    def handler(req):
        n["calls"] += 1
        if n["calls"] < 3:
            return httpx.Response(429, headers={"Retry-After": "120"})
        return fjson({"resourceType": "Goal", "id": "g"})

    c, sleeps = client_for(handler)
    assert c.read("Goal", "g")["id"] == "g" and sleeps == [10.0, 10.0]

    c, sleeps = client_for(lambda r: httpx.Response(503))
    with pytest.raises(FhirClientError) as ei:
        c.read("Goal", "g")
    assert ei.value.status == 503 and len(sleeps) == 3


def test_connection_errors_retried():
    n = {"calls": 0}

    def handler(req):
        n["calls"] += 1
        if n["calls"] == 1:
            raise httpx.ConnectError("boom")
        return fjson({"resourceType": "Goal", "id": "g"})

    c, sleeps = client_for(handler)
    assert c.read("Goal", "g")["id"] == "g" and len(sleeps) == 1


def test_size_cap():
    c, _ = client_for(lambda r: httpx.Response(200, content=b"x" * 5000), max_bytes=1000)
    with pytest.raises(FhirClientError, match="larger"):
        c.read("Goal", "g")


def test_ids_validated_and_errors_sanitized():
    c, _ = client_for(lambda r: fjson({"resourceType": "OperationOutcome", "issue": [
        {"severity": "error", "code": "invalid", "diagnostics": "token tok-SECRET " + "y" * 500}]}, 404),
        token=Token(access_token="tok-SECRET"),
        settings=SmartSettings(base_url=BASE, auth_mode="standalone", client_id="x", redirect_uri="http://localhost/cb"))
    for bad in ("../x", "a/b", "x" * 65, ""):
        with pytest.raises(FhirClientError, match="id"):
            c.read("Goal", bad)
    with pytest.raises(FhirClientError, match="type"):
        c.read("goal", "g")
    with pytest.raises(FhirClientError) as ei:
        c.read("Goal", "g")
    assert ei.value.status == 404 and "tok-SECRET" not in str(ei.value) and len(str(ei.value)) < 260


def test_open_mode_sends_no_auth_and_fhir_accept():
    def handler(req):
        assert "Authorization" not in req.headers and req.headers["Accept"] == "application/fhir+json"
        return fjson({"resourceType": "Goal", "id": "g"})
    c, _ = client_for(handler)
    c.read("Goal", "g")


def test_same_server_normalises_paths_and_refuses_encoded_tricks():
    c, _ = client_for(lambda r: fjson({}), settings=SmartSettings(base_url="https://h/fhir"))
    assert c.same_server("https://h/fhir/Binary/1") and c.same_server("https://h/fhir/")
    assert c.same_server("https://h/fhir/a/../Binary/1")
    assert not c.same_server("https://h/fhir/../admin/x")
    assert not c.same_server("https://h/fhir/./../admin")
    assert not c.same_server("https://h/fhirx/a")
    assert not c.same_server("https://h/fhir/%2e%2e/admin/x")
    assert not c.same_server("https://h/fhir/%2E%2E/admin/x")
    assert not c.same_server("https://h/fhir/..\\admin")
    with pytest.raises(FhirClientError, match="another server"):
        c.binary("https://h/fhir/../admin/Binary/1")


def test_binary_same_server_only():
    def handler(req):
        return httpx.Response(200, content=b"hello", headers={"Content-Type": "text/plain"})
    c, _ = client_for(handler)
    assert base64.b64decode(c.binary("Binary/b1")["data"]) == b"hello"
    with pytest.raises(FhirClientError, match="another server"):
        c.binary("https://evil.test/r4/Binary/b1")


# ---------------------------------------------------------------- discharge bundle

def sandbox(req, log):
    path, q = req.url.path.removeprefix("/r4/"), dict(req.url.params)
    log.append((path, q))
    enc_ok = {"resourceType": "Encounter", "id": "e2", "status": "finished", "class": {"code": "IMP"},
              "subject": {"reference": "Patient/p1"},
              "period": {"start": "2026-11-10", "end": "2026-11-14T10:00:00Z"}}
    if path == "Patient/p1":
        return fjson({"resourceType": "Patient", "id": "p1", "active": True,
                      "name": [{"use": "official", "family": "Secret", "given": ["Jane", "Q"], "text": "Jane Q Secret",
                                "period": {"start": "2000"}}],
                      "birthDate": "1950-01-02", "gender": "female",
                      "identifier": [{"system": "urn:mrn", "value": "MRN123", "type": {"text": "MRN"}}],
                      "telecom": [{"system": "phone", "value": "555-0100", "use": "home"}],
                      "address": [{"line": ["1 Main St"], "city": "Town"}],
                      "contact": [{"name": {"family": "Kin"}}], "text": {"div": "<div>Jane</div>"}})
    if path == "Encounter":
        return fjson(bundle(
            {"resourceType": "Encounter", "id": "e1", "status": "finished", "class": {"code": "AMB"},
             "period": {"start": "2026-11-20", "end": "2026-11-20"}},
            enc_ok,
            {"resourceType": "Encounter", "id": "e3", "status": "in-progress", "class": {"code": "IMP"}},
            {"resourceType": "Patient", "id": "p1", "name": [{"family": "Secret"}]}, mode="include"))
    if path == "Encounter/e2":
        return fjson(enc_ok)
    if path == "Condition":
        if "encounter" in q:
            return fjson({"resourceType": "OperationOutcome", "issue": [{"diagnostics": "encounter not supported"}]}, 400)
        return fjson(bundle({"resourceType": "Condition", "id": "c1", "encounter": {"reference": "Encounter/e2"}},
                            {"resourceType": "Condition", "id": "c-old", "encounter": {"reference": "Encounter/e0"}},
                            {"resourceType": "Condition", "id": "c-pl", "subject": {"reference": f"{BASE}/Patient/p1"}},
                            {"resourceType": "Condition", "id": "c-other", "subject": {"reference": "Patient/p999"}}))
    if path == "MedicationRequest":
        if "_include" in q:
            return httpx.Response(400)
        return fjson(bundle({"resourceType": "MedicationRequest", "id": "m1"}))
    if path == "AllergyIntolerance":
        return httpx.Response(403)
    if path == "DocumentReference":
        return fjson(bundle({"resourceType": "DocumentReference", "id": "d1", "content": [
            {"attachment": {"contentType": "text/plain", "url": "Binary/b1"}},
            {"attachment": {"url": "https://other.test/Binary/b9"}}]}))
    if path == "Binary/b1":
        return fjson({"resourceType": "Binary", "contentType": "text/plain",
                      "data": base64.b64encode(b"Discharge Summary text").decode()})
    if path == "Appointment":
        assert q["date"] == "ge2026-11-14"
        return fjson(bundle({"resourceType": "Appointment", "id": "a1"}, {"resourceType": "Patient", "id": "p1"}))
    return fjson(bundle())


def test_fetch_discharge_bundle():
    log = []
    c, _ = client_for(lambda r: sandbox(r, log))
    out, warnings = fetch_discharge_bundle(c, "p1")
    ids = [e["resource"]["resourceType"] + "/" + e["resource"]["id"] for e in out["entry"]]
    assert out["resourceType"] == "Bundle" and out["type"] == "collection"
    assert ids[0] == "Encounter/e2"
    # Only a redaction stub of the Patient, never the full resource (or search-included Patients).
    assert [i for i in ids if i.startswith("Patient/")] == ["Patient/p1"]
    pat = next(e["resource"] for e in out["entry"] if e["resource"]["resourceType"] == "Patient")
    assert pat == {"resourceType": "Patient", "id": "p1",
                   "name": [{"given": ["Jane", "Q"], "family": "Secret", "text": "Jane Q Secret"}],
                   "birthDate": "1950-01-02", "identifier": [{"value": "MRN123"}], "telecom": [{"value": "555-0100"}]}
    for absent in ("address", "contact", "gender", "text", "active"):
        assert absent not in pat
    assert "Condition/c-other" not in ids and "another patient" in "\n".join(warnings)
    assert "Condition/c1" in ids and "Condition/c-pl" in ids and "Condition/c-old" not in ids
    assert ids.count("Condition/c1") == 1  # encounter + problem-list searches deduplicated
    assert "MedicationRequest/m1" in ids and "Appointment/a1" in ids
    assert all(e["fullUrl"] == f"{BASE}/{i}" for e, i in zip(out["entry"], ids))
    doc = next(e["resource"] for e in out["entry"] if e["resource"]["resourceType"] == "DocumentReference")
    assert base64.b64decode(doc["content"][0]["attachment"]["data"]) == b"Discharge Summary text"
    assert "data" not in doc["content"][1]["attachment"]
    text = "\n".join(warnings)
    assert "Encounter/e2" in text and "AllergyIntolerance: skipped" in text
    assert "retried without encounter" in text and "_include" in text and "another server" in text
    assert [p for p, _ in log if p.startswith("Patient")] == ["Patient/p1"]
    assert ("Condition", {"patient": "p1", "encounter": "e2", "category": "encounter-diagnosis"}) in log
    assert "retried without category" in text
    assert ("Encounter", {"patient": "p1", "_sort": "-date", "_count": "10"}) in log


def test_fetch_with_explicit_encounter_and_bad_patient_id():
    log = []
    c, _ = client_for(lambda r: sandbox(r, log))
    out, _ = fetch_discharge_bundle(c, "p1", "e2")
    assert out["entry"][0]["resource"]["id"] == "e2" and log[0][0] == "Encounter/e2"
    with pytest.raises(FhirClientError):
        fetch_discharge_bundle(c, "../../evil")
    with pytest.raises(FhirClientError, match="does not belong"):
        fetch_discharge_bundle(c, "p2", "e2")


@pytest.mark.parametrize("subject", [None, "Patient/p10", "Group/p1", "https://x.test/fhir/Patient/p2"])
def test_explicit_encounter_must_belong_to_patient(subject):
    enc = {"resourceType": "Encounter", "id": "e2", "status": "finished", "period": {"end": "2026-11-14"}}
    if subject:
        enc["subject"] = {"reference": subject}
    c, _ = client_for(lambda r: fjson(enc))
    with pytest.raises(FhirClientError, match="does not belong"):
        fetch_discharge_bundle(c, "p1", "e2")


def test_encounter_subject_as_full_url_accepted_and_patient_404_warns():
    def handler(req):
        path = req.url.path.removeprefix("/r4/")
        if path == "Encounter/e2":
            return fjson({"resourceType": "Encounter", "id": "e2", "subject": {"reference": f"{BASE}/Patient/p1"},
                          "period": {"end": "2026-11-14"}})
        if path == "Patient/p1":
            return httpx.Response(404)
        if path == "Appointment":
            if "date" in req.url.params:
                return httpx.Response(400)
            return fjson(bundle({"resourceType": "Appointment", "id": "a-old", "start": "2026-10-01T09:00:00Z"},
                                {"resourceType": "Appointment", "id": "a-new", "start": "2026-11-20T09:00:00Z"}))
        return fjson(bundle())

    c, _ = client_for(handler)
    out, warnings = fetch_discharge_bundle(c, "p1", "e2")
    ids = [e["resource"]["resourceType"] + "/" + e["resource"]["id"] for e in out["entry"]]
    assert ids == ["Encounter/e2", "Appointment/a-new"]
    text = "\n".join(warnings)
    assert "Patient: not read" in text and "retried without date" in text


def test_patient_read_errors_other_than_403_404_raise():
    def handler(req):
        path = req.url.path.removeprefix("/r4/")
        if path == "Encounter/e2":
            return fjson({"resourceType": "Encounter", "id": "e2", "subject": {"reference": "Patient/p1"}})
        if path == "Patient/p1":
            return httpx.Response(500)
        return fjson(bundle())
    c, _ = client_for(handler)
    with pytest.raises(FhirClientError) as ei:
        fetch_discharge_bundle(c, "p1", "e2")
    assert ei.value.status == 500


# ---------------------------------------------------------------- CLI

def test_cli_discharge_fields_tolerates_junk():
    from scripts.fhir_pull import _discharge_fields
    assert _discharge_fields([]) == ("", "")
    assert _discharge_fields({"entry": "x"}) == ("", "")
    assert _discharge_fields({"entry": ["x", None, {"resource": "y"}, {"resource": {"resourceType": "Encounter",
                              "period": "bad", "hospitalization": {"dischargeDisposition": {"coding": ["z", {"display": "Home"}]}}}}]}) \
        == ("", "Home")
    assert _discharge_fields({"entry": [{"resource": {"resourceType": "Encounter", "period": {"end": "2026-11-14T1"},
                              "hospitalization": "bad"}}]}) == ("2026-11-14", "")


def test_cli_callback_ignores_requests_without_code_or_error():
    from scripts.fhir_pull import _callback_params
    assert _callback_params("/favicon.ico", "/cb") is None
    assert _callback_params("/cb", "/cb") is None
    assert _callback_params("/cb?foo=1", "/cb") is None
    assert _callback_params("/cb?code=abc&state=s", "/cb") == {"code": "abc", "state": "s"}
    assert _callback_params("/cb?error=access_denied", "/cb") == {"error": "access_denied"}


def test_cli_wait_for_code_keeps_waiting_past_stray_hits():
    import http.client
    import socket
    import threading

    from scripts import fhir_pull
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    got: dict = {}
    t = threading.Thread(target=lambda: got.update(r=fhir_pull._wait_for_code(f"http://127.0.0.1:{port}/cb", 15)))
    t.start()
    statuses = []
    for path in ("/favicon.ico", "/cb", "/cb?code=abc&state=st"):
        for _ in range(50):
            try:
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                conn.request("GET", path)
                statuses.append(conn.getresponse().status)
                conn.close()
                break
            except ConnectionRefusedError:
                threading.Event().wait(0.05)
    t.join(10)
    assert statuses == [404, 404, 200]
    assert got["r"] == {"code": "abc", "state": "st"}


def test_cli_wait_for_code_times_out_on_bare_hits():
    import socket

    from scripts import fhir_pull
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    with pytest.raises(FhirClientError, match="Timed out"):
        fhir_pull._wait_for_code(f"http://127.0.0.1:{port}/cb", 0.01)


def test_cli_jwks_pull_and_import(tmp_path, monkeypatch, capsys):
    from cryptography.fernet import Fernet

    from scripts import fhir_pull
    _, key = write_key(tmp_path, "ES384")
    assert fhir_pull.main(["jwks", "--key", str(key)]) == 0
    assert json.loads(capsys.readouterr().out)["keys"][0]["crv"] == "P-384"

    log = []
    monkeypatch.setattr(smart, "_new_http", lambda s: httpx.Client(transport=httpx.MockTransport(lambda r: sandbox(r, log))))
    monkeypatch.setenv("FHIR_BASE_URL", BASE)
    monkeypatch.setenv("FHIR_AUTH_MODE", "open")
    out = tmp_path / "b.json"
    assert fhir_pull.main(["pull", "--patient", "p1", "--out", str(out)]) == 0
    assert "warning:" in capsys.readouterr().err
    assert json.loads(out.read_text())["entry"][0]["resource"]["id"] == "e2"

    monkeypatch.setenv("DATA_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("SESSION_PEPPER", "p" * 40)
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "t.db"))
    from app.db import Database
    with Database(tmp_path / "t.db").connect() as conn:
        conn.execute("INSERT INTO orgs (name) VALUES ('Org')")
    assert fhir_pull.main(["import", "--bundle", str(out), "--org-id", "1", "--label", "SYN-0100"]) == 0
    with Database(tmp_path / "t.db").connect() as conn:
        row = conn.execute("SELECT label, discharge_date FROM patients").fetchone()
        assert tuple(row) == ("SYN-0100", "2026-11-14")
        assert conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0] == 1
