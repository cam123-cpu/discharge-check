import secrets
from datetime import date
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from app import llm
from app.analysis import analyze
from app.config import Settings, load_settings
from app.main import create_app
from app.rules import Doc, days_until_deadline
from app.security import csrf_ok, hash_password

from .conftest import PASSWORD, csrf_of, login


def test_pages_require_login(client):
    r = client.get("/patients", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_security_headers(client):
    r = client.get("/login")
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"


def test_login_and_cookie_flags(client):
    r = login(client, "cm@a.test")
    assert r.status_code == 303 and r.headers["location"] == "/patients"
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie


def test_wrong_password_and_rate_limit(client):
    for _ in range(5):
        assert "incorrect" in login(client, "cm@a.test", "wrong").headers["location"]
    r = login(client, "cm@a.test")  # right password, but now locked out
    assert "Too+many" in r.headers["location"]


def test_honeypot_blocks_bots(client):
    page = client.get("/login")
    import re
    pre = re.search(r'name="pre" value="([^"]+)"', page.text).group(1)
    r = client.post("/login", data={"email": "cm@a.test", "password": "correct horse battery staple", "pre": pre, "website": "x"}, follow_redirects=False)
    assert "incorrect" in r.headers["location"]


def test_login_requires_pre_token(client):
    r = client.post("/login", data={"email": "cm@a.test", "password": "x", "pre": "forged"}, follow_redirects=False)
    assert "expired" in r.headers["location"]


def test_other_org_cannot_see_patient(client, app):
    login(client, "doc@b.test")
    with app.state.db.connect() as conn:
        a_patient = conn.execute("SELECT id FROM patients WHERE label = 'A-1'").fetchone()[0]
    assert client.get(f"/patients/{a_patient}").status_code == 404
    assert "A-1" not in client.get("/patients").text


def test_post_without_csrf_is_rejected(client, app):
    login(client, "cm@a.test")
    r = client.post("/patients", data={"label": "X-1"})
    assert r.status_code == 403


def test_role_check_on_compliance(client):
    login(client, "rn@a.test")
    assert client.get("/compliance").status_code == 403
    assert client.get("/api/compliance/summary").status_code == 403


def test_create_upload_check_flow(client, app):
    login(client, "cm@a.test")
    token = csrf_of(client)
    r = client.post("/patients", data={"csrf": token, "label": "SYN-9", "discharge_date": "2026-11-14", "disposition": "Home"}, follow_redirects=False)
    assert r.status_code == 303
    pid = r.headers["location"].rsplit("/", 1)[1]
    text = open("samples/syn-0001-summary.txt", "rb").read()
    r = client.post(f"/patients/{pid}/documents", data={"csrf": token, "kind": "discharge_summary", "confirm": "yes"},
                    files={"file": ("summary.txt", text, "text/plain")}, follow_redirects=False)
    assert "Added" in r.headers["location"]
    r = client.post(f"/patients/{pid}/check", data={"csrf": token}, follow_redirects=True)
    assert "Before signing" in r.text and "shown in the text" in r.text and ">Shown<" in r.text
    # Stored text is encrypted, not plain.
    with app.state.db.connect() as conn:
        blob = conn.execute("SELECT body_enc FROM documents WHERE patient_id = ?", (pid,)).fetchone()[0]
    assert b"Heart failure" not in blob and b"heart failure" not in blob
    page = client.get("/compliance")
    assert page.status_code == 200 and "Open charts" in page.text and "not a score" in page.text
    api = client.get("/api/compliance/summary").json()
    assert set(api) == {"rules_version", "patients_checked", "rules"}
    assert set(api["rules"][0]) == {"id", "citation", "pass", "fail", "unclear", "fail_rate"}


def test_label_validation_blocks_markup(client):
    login(client, "cm@a.test")
    token = csrf_of(client)
    r = client.post("/patients", data={"csrf": token, "label": "<script>alert(1)</script>"})
    assert r.status_code == 400
    assert "<script>alert(1)</script>" not in r.text


def test_upload_requires_confirmation(client, app):
    login(client, "cm@a.test")
    token = csrf_of(client)
    with app.state.db.connect() as conn:
        pid = conn.execute("SELECT id FROM patients WHERE label = 'A-1'").fetchone()[0]
    r = client.post(f"/patients/{pid}/documents", data={"csrf": token, "kind": "other"},
                    files={"file": ("a.txt", b"hello", "text/plain")}, follow_redirects=False)
    assert "Confirm" in r.headers["location"]


# ---------- model review, with a fake client ----------

def _fake_client(parsed):
    resp = SimpleNamespace(stop_reason="end_turn", parsed_output=parsed)
    return SimpleNamespace(beta=SimpleNamespace(messages=SimpleNamespace(parse=lambda **kw: resp)))


def test_model_pass_without_real_quote_is_downgraded():
    docs = [Doc(0, "discharge_summary", "s.txt", "Discharge Diagnosis:\n- Pneumonia\nCode status: full code")]
    empty = []
    parsed = llm.Review(
        brief=llm.PatientBrief(one_liner="x", hospital_course="y", active_problems=[llm.BriefItem(text="Pneumonia", source_quote="Pneumonia")],
                               medication_changes=empty, follow_up=empty, pending_items=empty, readmission_risk_factors=empty,
                               handoff_notes_for_pcp=[llm.BriefItem(text="made up", source_quote="this text is not in the record")]),
        compliance=[
            llm.RuleResult(rule_id="final_diagnosis", status="pass", evidence_quote="- Pneumonia", document_index=0, explanation="ok"),
            llm.RuleResult(rule_id="goals_of_care", status="pass", evidence_quote="Patient wishes hospice", document_index=0, explanation="invented"),
        ],
    )
    result = analyze(docs, disposition_hint="Home", discharge_hint="2026-11-01", client=_fake_client(parsed), model="claude-opus-5-5")
    by = {f["rule_id"]: f for f in result["findings"]}
    assert result["engine"] == "model"
    assert by["final_diagnosis"]["status"] == "pass"
    assert by["goals_of_care"]["status"] == "unclear"
    assert result["model_brief"]["handoff_notes_for_pcp"][0]["grounded"] is False
    assert result["model_brief"]["active_problems"][0]["grounded"] is True


def test_model_failure_falls_back_to_patterns():
    def boom(**kw):
        raise llm.LLMUnavailable("down")
    client = SimpleNamespace(beta=SimpleNamespace(messages=SimpleNamespace(parse=boom)))
    # analyze catches LLMUnavailable raised from review(); emulate by patching review
    orig = llm.review
    llm.review = lambda *a, **k: (_ for _ in ()).throw(llm.LLMUnavailable("Model down."))
    try:
        r = analyze([Doc(0, "discharge_summary", "s.txt", "Discharge Diagnosis:\n- X")], disposition_hint="", discharge_hint="",
                    client=client, model="m")
    finally:
        llm.review = orig
    assert r["engine"] == "pattern" and "pattern-check results only" in r["message"]


def test_model_cannot_clear_a_pattern_miss():
    docs = [Doc(0, "discharge_summary", "s.txt", "Code status: full code. Nothing else is documented.")]
    parsed = llm.Review(
        brief=llm.PatientBrief(
            one_liner="x", hospital_course="y",
            active_problems=[], medication_changes=[], follow_up=[], pending_items=[],
            readmission_risk_factors=[], handoff_notes_for_pcp=[],
        ),
        compliance=[
            llm.RuleResult(
                rule_id="final_diagnosis", status="pass", evidence_quote="Code status: full code",
                document_index=0, explanation="The model treated a code-status line as a diagnosis.",
            ),
        ],
    )
    result = analyze(docs, disposition_hint="Home", discharge_hint="2026-11-01", client=_fake_client(parsed), model="m")
    finding = next(f for f in result["findings"] if f["rule_id"] == "final_diagnosis")
    assert finding["status"] == "fail"
    assert finding["pattern_status"] == "fail"
    assert finding["model_status"] == "pass"


def test_csrf_ok_rejects_odd_tokens():
    good = "a" * 32
    assert csrf_ok(good, good)
    assert not csrf_ok(good, "b" * 32)
    assert not csrf_ok(good, "short")
    assert not csrf_ok(good, "é" * 16)
    assert not csrf_ok(good, None)
    assert not csrf_ok("", good)


def test_non_ascii_csrf_is_rejected(client):
    login(client, "cm@a.test")
    r = client.post("/patients", data={"csrf": "é", "label": "SYN-1"})
    assert r.status_code == 403


def test_work_queue_puts_overdue_charts_first(client):
    login(client, "cm@a.test")
    token = csrf_of(client)
    client.post("/patients", data={"csrf": token, "label": "OLD-1", "discharge_date": "2020-01-01", "disposition": "Home"}, follow_redirects=False)
    page = client.get("/patients").text
    assert "Work queue" in page
    assert "Overdue" in page
    assert page.find("OLD-1") < page.find("A-1")
    days = days_until_deadline("2026-11-14", date.today())
    if days is not None and days > 0:
        assert f"{days} days left" in page


def test_identity_fields_are_encrypted_at_rest(client, app):
    login(client, "cm@a.test")
    token = csrf_of(client)
    r = client.post(
        "/patients",
        data={"csrf": token, "label": "SYN-9", "unit": "4 West", "attending": "Dr. Ada", "discharge_date": "2026-11-14", "disposition": "Home"},
        follow_redirects=False,
    )
    pid = r.headers["location"].rsplit("/", 1)[1]
    with app.state.db.connect() as conn:
        row = conn.execute("SELECT label, unit, attending, discharge_date, disposition FROM patients WHERE id = ?", (pid,)).fetchone()
    stored = " ".join(row)
    assert stored.startswith("enc:v1:") or row["label"].startswith("enc:v1:")
    assert "SYN-9" not in stored and "4 West" not in stored and "Ada" not in stored
    assert "SYN-9" in client.get(f"/patients/{pid}").text


def test_dashboard_ignores_tampered_plaintext(client, app):
    login(client, "cm@a.test")
    token = csrf_of(client)
    r = client.post("/patients", data={"csrf": token, "label": "GAP-1", "discharge_date": "2026-11-01", "disposition": "Home"}, follow_redirects=False)
    pid = int(r.headers["location"].rsplit("/", 1)[1])
    token = csrf_of(client, f"/patients/{pid}")
    client.post(
        f"/patients/{pid}/documents",
        data={"csrf": token, "kind": "discharge_summary", "confirm": "yes"},
        files={"file": ("s.txt", b"Hello\n", "text/plain")},
        follow_redirects=False,
    )
    client.post(f"/patients/{pid}/check", data={"csrf": token}, follow_redirects=True)
    page = client.get("/patients").text
    assert "st-fail" in page
    with app.state.db.connect() as conn:
        org_id, analysis_id = conn.execute(
            "SELECT org_id, id FROM analyses WHERE patient_id = ? ORDER BY id DESC LIMIT 1", (pid,)
        ).fetchone()
        conn.execute(
            "INSERT INTO findings (org_id, analysis_id, patient_id, rule_id, status) VALUES (?, ?, ?, 'goals_of_care', 'fail')",
            (org_id, analysis_id, pid),
        )
        conn.execute("UPDATE analyses SET failed = 0, unclear = 0, passed = 20 WHERE id = ?", (analysis_id,))
    api_before = client.get("/api/compliance/summary").json()
    queue = client.get("/patients").text
    assert "st-fail" in queue and "All shown" not in queue
    with app.state.db.connect() as conn:
        conn.execute("UPDATE analyses SET result_enc = ? WHERE id = ?", (b"tampered", analysis_id))
    assert client.get("/api/compliance/summary").json()["patients_checked"] == api_before["patients_checked"] - 1
    assert "Check unreadable" in client.get("/patients").text
    assert "All shown" not in client.get("/patients").text


def test_medication_diff_is_on_the_chart(client):
    login(client, "cm@a.test")
    token = csrf_of(client)
    r = client.post("/patients", data={"csrf": token, "label": "MED-1", "discharge_date": "2026-11-09", "disposition": "Skilled nursing facility (SNF)"}, follow_redirects=False)
    pid = r.headers["location"].rsplit("/", 1)[1]
    token = csrf_of(client, f"/patients/{pid}")
    for name, kind in (("syn-0002-summary.txt", "discharge_summary"), ("syn-0002-nursing.txt", "nursing_instructions")):
        client.post(
            f"/patients/{pid}/documents",
            data={"csrf": token, "kind": kind, "confirm": "yes"},
            files={"file": (name, open(f"samples/{name}", "rb").read(), "text/plain")},
            follow_redirects=False,
        )
    page = client.post(f"/patients/{pid}/check", data={"csrf": token}, follow_redirects=True)
    assert "do not match" in page.text
    assert "lisinopril" in page.text and "insulin" in page.text


def test_database_file_is_owner_only(app):
    mode = app.state.settings.database_path.stat().st_mode & 0o777
    assert mode == 0o600


def test_oversized_body_is_rejected(client):
    login(client, "cm@a.test")
    token = csrf_of(client)
    with client.app.state.db.connect() as conn:
        pid = conn.execute("SELECT id FROM patients WHERE label = 'A-1'").fetchone()[0]
    big = b"a" * (3 * 1024 * 1024)
    r = client.post(
        f"/patients/{pid}/documents",
        data={"csrf": token, "kind": "other", "confirm": "yes"},
        files={"file": ("a.txt", big, "text/plain")},
        follow_redirects=False,
    )
    assert r.status_code == 413


def test_too_many_form_fields_are_rejected(client):
    login(client, "cm@a.test")
    token = csrf_of(client)
    data = {"csrf": token, "label": "SYN-1"}
    data.update({f"extra{i}": "a" for i in range(30)})
    r = client.post("/patients", data=data)
    assert r.status_code == 400


def _client(tmp_path, **kwargs):
    base_url = kwargs.pop("base_url", "http://testserver")
    settings = Settings(
        data_key=Fernet.generate_key().decode(),
        session_pepper=secrets.token_urlsafe(32),
        anthropic_api_key=kwargs.pop("anthropic_api_key", None),
        force_https=kwargs.pop("force_https", False),
        database_path=tmp_path / "t.db",
        **kwargs,
    )
    app = create_app(settings)
    with app.state.db.connect() as conn:
        org = conn.execute("INSERT INTO orgs (name) VALUES ('Org A')").lastrowid
        conn.execute(
            "INSERT INTO users (org_id, email, display_name, role, password_hash) VALUES (?, ?, ?, ?, ?)",
            (org, "cm@a.test", "cm", "compliance", hash_password(PASSWORD)),
        )
    return TestClient(app, base_url=base_url)


def test_https_redirect_uses_public_host_only(tmp_path):
    client = _client(tmp_path, force_https=True, public_host="charts.example")
    r = client.get("/login", headers={"host": "evil.example"}, follow_redirects=False)
    assert r.status_code == 308
    assert r.headers["location"] == "https://charts.example/login"
    assert "evil" not in r.headers["location"]


def test_https_without_public_host_does_not_redirect(tmp_path):
    client = _client(tmp_path, force_https=True)
    r = client.get("/login", headers={"host": "evil.example"}, follow_redirects=False)
    assert r.status_code == 400
    assert "location" not in {k.lower() for k in r.headers}
    assert "evil" not in r.text


def test_forwarded_proto_is_ignored_unless_the_proxy_is_trusted(tmp_path):
    client = _client(tmp_path, force_https=True, public_host="charts.example", trust_proxy=False)
    r = client.get("/login", headers={"x-forwarded-proto": "https", "host": "evil.example"}, follow_redirects=False)
    assert r.status_code == 308
    assert r.headers["location"] == "https://charts.example/login"


def test_trusted_proxy_honors_forwarded_proto(tmp_path):
    client = _client(tmp_path, force_https=True, public_host="charts.example", trust_proxy=True)
    r = client.get("/login", headers={"x-forwarded-proto": "https"}, follow_redirects=False)
    assert r.status_code == 200


def test_logout_deletes_the_secure_cookie(tmp_path):
    client = _client(tmp_path, force_https=True, public_host="charts.example", base_url="https://testserver")
    assert login(client, "cm@a.test").status_code == 303
    token = csrf_of(client)
    r = client.post("/logout", data={"csrf": token}, follow_redirects=False)
    assert "secure" in r.headers["set-cookie"].lower()
    assert "samesite=strict" in r.headers["set-cookie"].lower()


def test_public_host_rejects_a_url(monkeypatch):
    monkeypatch.setenv("DATA_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("SESSION_PEPPER", "pepper-for-the-test")
    monkeypatch.setenv("PUBLIC_HOST", "https://evil.example/phish")
    with pytest.raises(RuntimeError):
        load_settings()


def test_trust_proxy_requires_public_host(monkeypatch):
    monkeypatch.setenv("DATA_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("SESSION_PEPPER", "pepper-for-the-test")
    monkeypatch.setenv("PUBLIC_HOST", "")
    monkeypatch.setenv("TRUST_PROXY", "1")
    with pytest.raises(RuntimeError):
        load_settings()


def test_model_review_is_opt_in_and_held_for_contact_details(monkeypatch, tmp_path):
    called = {}

    class Recorder:
        def __init__(self, api_key=None, **kwargs):
            pass

        @property
        def beta(self):
            return self

        @property
        def messages(self):
            return self

        def parse(self, **kwargs):
            called["yes"] = True
            raise llm.LLMUnavailable("stub")

    monkeypatch.setattr("anthropic.Anthropic", Recorder)
    client = _client(tmp_path, anthropic_api_key="test-key")
    login(client, "cm@a.test")
    token = csrf_of(client)
    r = client.post("/patients", data={"csrf": token, "label": "OPT-1", "discharge_date": "2026-11-14", "disposition": "Home"}, follow_redirects=False)
    pid = r.headers["location"].rsplit("/", 1)[1]
    token = csrf_of(client, f"/patients/{pid}")
    client.post(
        f"/patients/{pid}/documents",
        data={"csrf": token, "kind": "discharge_summary", "confirm": "yes"},
        files={"file": ("s.txt", b"Discharge Diagnosis:\n- Pneumonia\n", "text/plain")},
        follow_redirects=False,
    )
    page = client.post(f"/patients/{pid}/check", data={"csrf": token}, follow_redirects=True)
    assert "yes" not in called
    assert "pattern rules" in page.text
    token = csrf_of(client, f"/patients/{pid}")
    page = client.post(f"/patients/{pid}/check", data={"csrf": token, "use_model": "yes"}, follow_redirects=True)
    assert called.get("yes") is True
    assert "pattern-check results only" in page.text
    called.clear()
    token = csrf_of(client, f"/patients/{pid}")
    client.post(
        f"/patients/{pid}/documents",
        data={"csrf": token, "kind": "other", "confirm": "yes"},
        files={"file": ("phone.txt", b"Call 415 867 5309 about the discharge.\n", "text/plain")},
        follow_redirects=False,
    )
    token = csrf_of(client, f"/patients/{pid}")
    page = client.post(f"/patients/{pid}/check", data={"csrf": token, "use_model": "yes"}, follow_redirects=True)
    assert "yes" not in called
    assert "stayed off" in page.text
