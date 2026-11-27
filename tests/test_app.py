from types import SimpleNamespace

from app import llm
from app.analysis import analyze
from app.rules import Doc

from .conftest import csrf_of, login


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
    assert "Before signing" in r.text and "Complete" in r.text
    # Stored text is encrypted, not plain.
    with app.state.db.connect() as conn:
        blob = conn.execute("SELECT body_enc FROM documents WHERE patient_id = ?", (pid,)).fetchone()[0]
    assert b"Heart failure" not in blob and b"heart failure" not in blob
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
