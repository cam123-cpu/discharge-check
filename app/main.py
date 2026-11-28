"""Discharge Check: web app entry point."""
from __future__ import annotations

import json
import re
import secrets
from collections import defaultdict
from datetime import date
from pathlib import Path
from urllib.parse import urlencode

import anthropic
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import analysis
from .config import Settings, load_settings
from .db import Database
from .ingest import DOC_KINDS, IngestError, parse_upload, phi_screen
from .rules import RULES, RULES_BY_ID, RULES_VERSION, Doc, days_until_deadline
from .security import (
    SESSION_COOKIE,
    Cipher,
    LoginLimiter,
    SecurityHeadersMiddleware,
    Sessions,
    burn_password_check,
    csrf_ok,
    verify_password,
)

HERE = Path(__file__).parent
PRE_COOKIE = "dc_pre"
DISPOSITIONS = [
    "Home",
    "Home with home health services",
    "Skilled nursing facility (SNF)",
    "Inpatient rehabilitation facility (IRF)",
    "Long-term care hospital (LTCH)",
    "Hospice",
    "Another acute care hospital",
    "Left against medical advice",
]
ROLE_LABELS = {
    "physician": "Physician",
    "nurse": "Nurse",
    "case_manager": "Case manager",
    "compliance": "Compliance",
    "admin": "Administrator",
}
_LABEL_RE = re.compile(r"^[A-Za-z0-9 .,'()#/-]{1,80}$")
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}$")
# Text fields stay small. The file itself is capped by max_body_size plus the ingest check.
FORM_LIMITS = {"max_fields": 24, "max_files": 3, "max_part_size": 16 * 1024}
PII_FIELDS = ("label", "unit", "attending", "disposition", "discharge_date")


def reveal_patient(cipher: Cipher, row) -> dict:
    data = dict(row)
    for key in PII_FIELDS:
        if data.get(key):
            data[key] = cipher.decrypt_field(data[key])
    return data


def seal_fields(cipher: Cipher, data: dict) -> dict:
    sealed = dict(data)
    for key in PII_FIELDS:
        sealed[key] = cipher.encrypt_field(data.get(key, ""))
    return sealed


def reveal_doc(cipher: Cipher, row) -> dict:
    data = dict(row)
    data.pop("body_enc", None)
    if data.get("author"):
        data["author"] = cipher.decrypt_field(data["author"])
    return data


def status_of(result: dict | None, rule_id: str) -> str:
    if not result:
        return ""
    for finding in result.get("findings", []):
        if finding.get("rule_id") == rule_id:
            return str(finding.get("status", ""))
    return ""


def timeliness_of(result: dict | None) -> str:
    return status_of(result, "timeliness")


def clock_for(discharge_date: str, timeliness: str, today: date, authenticated: str = "") -> dict:
    """The 30-day completion clock.

    'Signed on time' requires both the date math and a complete signature.
    A date with no time must not look finished.
    """
    days = days_until_deadline(discharge_date, today)
    if timeliness == "pass" and authenticated == "pass":
        return {"label": "Signed on time", "tone": "pass", "days": days}
    if days is None:
        return {"label": "No discharge date", "tone": "na", "days": None}
    if days < 0 or timeliness == "fail":
        if days is not None and days < 0:
            return {"label": f"Overdue {-days} days", "tone": "fail", "days": days}
        return {"label": "Delinquent", "tone": "fail", "days": days}
    if days == 0:
        return {"label": "Due today", "tone": "unclear", "days": 0}
    # Days remaining are not a Shown result, so they do not use that green.
    return {"label": f"{days} days left", "tone": "unclear" if days <= 7 else "na", "days": days}


def apply_sealed_check(patient: dict, cipher: Cipher) -> None:
    """Counts and the signature clock come from the sealed result, not the cache columns."""
    blob = patient.pop("result_enc", None)
    patient["timeliness"] = ""
    patient["authenticated"] = ""
    patient["miss_titles"] = []
    patient["check_unreadable"] = False
    patient["check_stale"] = False
    if not blob:
        return
    try:
        result = json.loads(cipher.decrypt(blob))
        tally = result["tally"]
        patient["last_failed"] = int(tally["fail"])
        patient["last_unclear"] = int(tally["unclear"])
        patient["last_passed"] = int(tally["pass"])
        patient["timeliness"] = timeliness_of(result)
        patient["authenticated"] = status_of(result, "authenticated")
        titles = []
        for finding in result.get("findings", []):
            if finding.get("status") != "fail":
                continue
            rule = RULES_BY_ID.get(finding.get("rule_id"))
            if rule:
                titles.append(rule.title)
        patient["miss_titles"] = titles[:4]
        stored = result.get("document_ids")
        current = patient.get("doc_id_set") or set()
        # Results sealed before document ids were stored stay as they are.
        patient["check_stale"] = bool(stored) and set(stored) != set(current)
    except (RuntimeError, KeyError, TypeError, ValueError):
        patient["last_failed"] = None
        patient["last_unclear"] = None
        patient["last_passed"] = None
        patient["check_unreadable"] = True


def queue_rank(patient: dict):
    if patient.get("check_unreadable"):
        return (0, -100_000, 0, patient["label"].lower())
    if patient.get("check_stale"):
        return (0, -50_000, 0, patient["label"].lower())
    open_items = (patient["last_failed"] or 0) + (patient["last_unclear"] or 0)
    unchecked = patient["last_failed"] is None
    signed = patient.get("timeliness") == "pass" and patient.get("authenticated") == "pass"
    days = patient["clock"]["days"]
    overdue = (not signed) and days is not None and days < 0
    needs_work = 0 if (unchecked or open_items or overdue) else 1
    if days is None:
        clock = 9_000
    elif signed:
        clock = 5_000
    else:
        clock = days
    return (needs_work, clock, -open_items, patient["label"].lower())


def model_block_reason(docs: list[Doc]) -> str:
    for doc in docs:
        try:
            warnings = phi_screen(doc.text)
        except IngestError:
            return "Model review stayed off because the record looks like it contains an identifier. Pattern results are shown."
        if warnings:
            return "Model review stayed off because the record has an email or a phone number. Pattern results are shown."
    return ""


class AuthRequired(Exception):
    pass


# Query strings carry a code, never a sentence. A crafted ?notice= cannot
# put attacker text on the page. Unknown codes render as nothing.
NOTICES = {
    "confirm": "Confirm the record is synthetic or de-identified.",
    "added": "Document added. Run the check to update results.",
    "removed": "Document removed. Run the check again. The saved result is out of date.",
    "need-doc": "Upload at least one document first.",
    "checked": "Check finished. A person decides whether to sign.",
    "model-held-id": "Model review stayed off because the record looks like it contains an identifier. Pattern results are shown.",
    "model-held-contact": "Model review stayed off because the record has an email or a phone number. Pattern results are shown.",
    "model-down": "The model could not be reached. Pattern results are shown.",
    "rejected": "That file could not be accepted.",
    "type": "Only .txt, .md and FHIR .json files are accepted.",
    "empty": "The file is empty.",
    "oversize": "The file is larger than the upload limit.",
    "binary": "The file looks binary, not text.",
    "encoding": "The file must be UTF-8 text.",
    "toolong": "The file has too much text for one record.",
    "phi-ssn": "The file contains what looks like a Social Security number. Only synthetic or de-identified records may be uploaded.",
    "phi-dob": "The file contains what looks like a date of birth. Only synthetic or de-identified records may be uploaded.",
    "phi-mrn": "The file contains what looks like a medical record number. Only synthetic or de-identified records may be uploaded.",
    "phi-street": "The file contains what looks like a street address. Only synthetic or de-identified records may be uploaded.",
    "fhir-type": "JSON files must be a FHIR R4 Bundle or DocumentReference.",
    "fhir-empty": "No usable clinical content was found in the FHIR file.",
    "kind": "Choose a valid document type.",
    "json": "The JSON file could not be parsed.",
}
LOGIN_ERRORS = {
    "bad": "Email or password is incorrect.",
    "expired": "Your session expired. Try again.",
    "locked": "Too many attempts. Wait 15 minutes.",
}
WARNINGS = {
    "email": "Contains an email address. Confirm it is synthetic.",
    "phone": "Contains a phone number outside the fictional 555 range. Confirm it is synthetic.",
}


def page_notice(request: Request) -> str:
    return NOTICES.get(request.query_params.get("notice", ""), "")


def page_warnings(request: Request) -> list[str]:
    return [WARNINGS[code] for code in request.query_params.getlist("warn") if code in WARNINGS][:3]


def warning_codes(warnings: list[str]) -> list[str]:
    codes = []
    for text in warnings:
        if text.startswith("Contains an email"):
            codes.append("email")
        elif text.startswith("Contains a phone"):
            codes.append("phone")
    return codes


def check_notice_code(message: str) -> str:
    if "identifier" in message:
        return "model-held-id"
    if "email" in message or "phone" in message:
        return "model-held-contact"
    if message:
        return "model-down"
    return "checked"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    db = Database(settings.database_path)
    cipher = Cipher(settings.data_key)
    db.seal_existing_plaintext(cipher.encrypt_field)
    sessions = Sessions(db, settings)
    limiter = LoginLimiter(db, settings)
    client = anthropic.Anthropic(api_key=settings.anthropic_api_key) if settings.anthropic_api_key else None

    app = FastAPI(
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        max_body_size=settings.max_upload_bytes + 256 * 1024,
        form_limits=FORM_LIMITS,
    )
    app.add_middleware(
        SecurityHeadersMiddleware,
        force_https=settings.force_https,
        public_host=settings.public_host,
        trust_proxy=settings.trust_proxy,
        trusted_proxy_ips=settings.trusted_proxy_ips,
    )
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=HERE / "templates")
    templates.env.globals.update(DOC_KINDS=DOC_KINDS, ROLE_LABELS=ROLE_LABELS, RULES_VERSION=RULES_VERSION)

    app.state.db = db
    app.state.settings = settings

    def client_ip(request: Request) -> str:
        return (request.client.host if request.client else "")[:64]

    def set_cookie(resp, name: str, value: str, max_age: int):
        resp.set_cookie(name, value, max_age=max_age, httponly=True, secure=settings.force_https, samesite="strict", path="/")

    def clear_cookie(resp, name: str):
        # Secure and SameSite must match the cookie that was set, or the browser can keep it.
        resp.delete_cookie(name, path="/", httponly=True, secure=settings.force_https, samesite="strict")

    # ---------- auth dependencies ----------

    def current_user(request: Request):
        user = sessions.lookup(request.cookies.get(SESSION_COOKIE))
        if user is None:
            raise AuthRequired()
        return user

    def require_role(*roles: str):
        def dep(user=Depends(current_user)):
            if user["role"] not in roles:
                raise HTTPException(status_code=403)
            return user
        return dep

    async def check_csrf(request: Request, user=Depends(current_user)):
        form = await request.form(**FORM_LIMITS)
        token = form.get("csrf")
        if not isinstance(token, str) or not csrf_ok(user["csrf_token"], token):
            raise HTTPException(status_code=403)
        return user

    def render(request: Request, name: str, ctx: dict, status: int = 200):
        return templates.TemplateResponse(request, name, ctx, status_code=status)

    @app.exception_handler(AuthRequired)
    async def _auth(request: Request, exc: AuthRequired):
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException):
        messages = {403: "You do not have access to this page.", 404: "That page or record does not exist.", 413: "The upload is too large."}
        msg = messages.get(exc.status_code, "Something went wrong.")
        if request.url.path.startswith("/api/"):
            return JSONResponse({"error": msg}, status_code=exc.status_code)
        return render(request, "error.html", {"user": None, "message": msg, "code": exc.status_code}, exc.status_code)

    # ---------- login ----------

    @app.get("/favicon.ico", include_in_schema=False)
    def favicon():
        from fastapi.responses import Response
        return Response(status_code=204)

    @app.get("/", include_in_schema=False)
    def home(request: Request):
        return RedirectResponse("/patients" if sessions.lookup(request.cookies.get(SESSION_COOKIE)) else "/login", status_code=303)

    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request):
        token = secrets.token_urlsafe(24)
        error = LOGIN_ERRORS.get(request.query_params.get("error", ""), "")
        resp = render(request, "login.html", {"user": None, "pre": token, "error": error})
        set_cookie(resp, PRE_COOKIE, token, 900)
        return resp

    @app.post("/login")
    def login(request: Request, email: str = Form("", max_length=254), password: str = Form("", max_length=256),
              pre: str = Form("", max_length=64), website: str = Form("", max_length=200)):
        ip = client_ip(request)
        email = email.strip().lower()
        bad = RedirectResponse("/login?error=bad", status_code=303)
        if website:  # honeypot field, invisible to people
            return bad
        if not csrf_ok(request.cookies.get(PRE_COOKIE, ""), pre):
            return RedirectResponse("/login?error=expired", status_code=303)
        keys = (f"ip:{ip}", f"email:{email}")
        if limiter.blocked(*keys):
            return RedirectResponse("/login?error=locked", status_code=303)
        user = None
        if _EMAIL_RE.match(email):
            with db.connect() as conn:
                user = conn.execute("SELECT id, org_id, password_hash FROM users WHERE email = ?", (email,)).fetchone()
        if user is None:
            burn_password_check(password)
            limiter.record_failure(*keys)
            return bad
        if not verify_password(user["password_hash"], password):
            limiter.record_failure(*keys)
            with db.connect() as conn:
                db.audit(conn, user["org_id"], user["id"], "login_failed", ip=ip)
            return bad
        limiter.clear(*keys)
        token = sessions.create(user["id"])
        with db.connect() as conn:
            db.audit(conn, user["org_id"], user["id"], "login", ip=ip)
        resp = RedirectResponse("/patients", status_code=303)
        set_cookie(resp, SESSION_COOKIE, token, settings.session_hours * 3600)
        clear_cookie(resp, PRE_COOKIE)
        return resp

    @app.post("/logout")
    def logout(request: Request, user=Depends(check_csrf)):
        sessions.destroy(request.cookies.get(SESSION_COOKIE))
        resp = RedirectResponse("/login", status_code=303)
        clear_cookie(resp, SESSION_COOKIE)
        return resp

    # ---------- patients ----------

    @app.get("/patients", response_class=HTMLResponse)
    def patients(request: Request, user=Depends(current_user)):
        today = date.today()
        with db.connect() as conn:
            rows = db.patients(conn, user["org_id"])
            id_rows = conn.execute(
                "SELECT patient_id, id FROM documents WHERE org_id = ?",
                (user["org_id"],),
            ).fetchall()
        doc_ids: dict[int, set[int]] = defaultdict(set)
        for item in id_rows:
            doc_ids[item["patient_id"]].add(item["id"])
        queue = []
        for row in rows:
            patient = reveal_patient(cipher, row)
            patient["doc_id_set"] = doc_ids.get(patient["id"], set())
            apply_sealed_check(patient, cipher)
            patient["clock"] = clock_for(
                patient.get("discharge_date") or "", patient.get("timeliness") or "", today, patient.get("authenticated") or "",
            )
            queue.append(patient)
        queue.sort(key=queue_rank)
        return render(request, "patients.html", {"user": user, "patients": queue, "nav": "patients"})

    @app.get("/patients/new", response_class=HTMLResponse)
    def new_patient_page(request: Request, user=Depends(current_user)):
        return render(request, "patient_new.html", {"user": user, "dispositions": DISPOSITIONS, "errors": [], "form": {}, "nav": "patients"})

    @app.post("/patients")
    async def create_patient(request: Request, user=Depends(check_csrf)):
        form = await request.form()
        data = {k: str(form.get(k, "")).strip() for k in ("label", "unit", "attending", "discharge_date", "disposition")}
        errors = []
        if not _LABEL_RE.match(data["label"]):
            errors.append("Label is required: up to 80 letters, numbers and basic punctuation. Do not use a real name.")
        for k, name in (("unit", "Unit"), ("attending", "Attending")):
            if data[k] and not _LABEL_RE.match(data[k]):
                errors.append(f"{name} has characters that are not allowed.")
        if data["discharge_date"]:
            try:
                date.fromisoformat(data["discharge_date"])
            except ValueError:
                errors.append("Discharge date must be a valid date.")
        if data["disposition"] and data["disposition"] not in DISPOSITIONS:
            errors.append("Choose a disposition from the list.")
        if errors:
            return render(request, "patient_new.html", {"user": user, "dispositions": DISPOSITIONS, "errors": errors, "form": data, "nav": "patients"}, 400)
        sealed = seal_fields(cipher, data)
        with db.connect() as conn:
            cur = conn.execute(
                "INSERT INTO patients (org_id, label, unit, attending, discharge_date, disposition, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (user["org_id"], sealed["label"], sealed["unit"], sealed["attending"], sealed["discharge_date"], sealed["disposition"], user["user_id"]),
            )
            pid = cur.lastrowid
            db.audit(conn, user["org_id"], user["user_id"], "patient_create", f"patient:{pid}", client_ip(request))
        return RedirectResponse(f"/patients/{pid}", status_code=303)

    def load_patient(conn, user, patient_id: int):
        p = db.patient(conn, user["org_id"], patient_id)
        if p is None:
            raise HTTPException(status_code=404)
        return p

    def load_docs(conn, user, patient_id: int) -> list[Doc]:
        rows = db.documents(conn, user["org_id"], patient_id)
        return [Doc(index=i, kind=r["kind"], filename=r["filename"], text=cipher.decrypt(r["body_enc"]), author=r["author"], doc_id=r["id"]) for i, r in enumerate(rows)]

    @app.get("/patients/{patient_id}", response_class=HTMLResponse)
    def patient_detail(request: Request, patient_id: int, user=Depends(current_user)):
        with db.connect() as conn:
            p = reveal_patient(cipher, load_patient(conn, user, patient_id))
            docs = [reveal_doc(cipher, row) for row in db.documents(conn, user["org_id"], patient_id)]
            a = db.latest_analysis(conn, user["org_id"], patient_id)
            db.audit(conn, user["org_id"], user["user_id"], "patient_view", f"patient:{patient_id}", client_ip(request))
        result = None
        unreadable = False
        if a:
            try:
                result = json.loads(cipher.decrypt(a["result_enc"]))
            except (RuntimeError, ValueError):
                unreadable = True
        groups: dict[str, list] = defaultdict(list)
        if result:
            for f in result["findings"]:
                rule = RULES_BY_ID.get(f["rule_id"])
                if rule:
                    groups[rule.group].append({"rule": rule, **f})
        stored_ids = (result or {}).get("document_ids") or []
        current_ids = {d["id"] for d in docs}
        stale = bool(stored_ids) and set(stored_ids) != current_ids
        return render(request, "patient.html", {
            "user": user, "p": p, "docs": docs, "analysis": a, "result": result, "groups": dict(groups),
            "notice": page_notice(request), "model_on": client is not None, "nav": "patients",
            "warnings": page_warnings(request),
            "unreadable": unreadable,
            "stale": stale,
            "clock": clock_for(
                p.get("discharge_date") or "", timeliness_of(result), date.today(), status_of(result, "authenticated"),
            ),
        })

    @app.post("/patients/{patient_id}/documents")
    async def upload_document(request: Request, patient_id: int, user=Depends(check_csrf),
                              kind: str = Form(..., max_length=40), confirm: str = Form(""), file: UploadFile = File(...)):
        if confirm != "yes":
            return RedirectResponse(f"/patients/{patient_id}?notice=confirm", status_code=303)
        raw = await file.read(settings.max_upload_bytes + 1)
        try:
            parsed = parse_upload(raw, file.filename or "upload.txt", kind, settings.max_upload_bytes)
        except IngestError as exc:
            code = exc.code if exc.code in NOTICES else "rejected"
            return RedirectResponse(f"/patients/{patient_id}?notice={code}", status_code=303)
        with db.connect() as conn:
            load_patient(conn, user, patient_id)
            conn.execute(
                "INSERT INTO documents (org_id, patient_id, kind, filename, author, body_enc, uploaded_by) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (user["org_id"], patient_id, parsed.kind, parsed.filename, cipher.encrypt_field(parsed.author), cipher.encrypt(parsed.text), user["user_id"]),
            )
            db.audit(conn, user["org_id"], user["user_id"], "document_upload", f"patient:{patient_id}", client_ip(request))
        q = urlencode([("notice", "added")] + [("warn", code) for code in warning_codes(parsed.warnings)])
        return RedirectResponse(f"/patients/{patient_id}?{q}", status_code=303)

    @app.get("/patients/{patient_id}/documents/{doc_id}", response_class=HTMLResponse)
    def view_document(request: Request, patient_id: int, doc_id: int, user=Depends(current_user)):
        with db.connect() as conn:
            p = load_patient(conn, user, patient_id)
            row = conn.execute("SELECT * FROM documents WHERE id = ? AND patient_id = ? AND org_id = ?", (doc_id, patient_id, user["org_id"])).fetchone()
            if row is None:
                raise HTTPException(status_code=404)
            db.audit(conn, user["org_id"], user["user_id"], "document_view", f"document:{doc_id}", client_ip(request))
            try:
                text = cipher.decrypt(row["body_enc"])
                unreadable = False
            except RuntimeError:
                text, unreadable = "", True
        return render(request, "document.html", {
            "user": user, "p": reveal_patient(cipher, p), "doc": reveal_doc(cipher, row),
            "text": text, "unreadable": unreadable, "nav": "patients",
        })

    @app.post("/patients/{patient_id}/documents/{doc_id}/delete")
    def delete_document(request: Request, patient_id: int, doc_id: int, user=Depends(check_csrf)):
        with db.connect() as conn:
            load_patient(conn, user, patient_id)
            n = conn.execute("DELETE FROM documents WHERE id = ? AND patient_id = ? AND org_id = ?", (doc_id, patient_id, user["org_id"])).rowcount
            if n == 0:
                raise HTTPException(status_code=404)
            db.audit(conn, user["org_id"], user["user_id"], "document_delete", f"document:{doc_id}", client_ip(request))
        return RedirectResponse(f"/patients/{patient_id}?notice=removed", status_code=303)

    @app.post("/patients/{patient_id}/check")
    def run_check(request: Request, patient_id: int, user=Depends(check_csrf), use_model: str = Form("")):
        with db.connect() as conn:
            p = reveal_patient(cipher, load_patient(conn, user, patient_id))
            docs = load_docs(conn, user, patient_id)
        if not docs:
            return RedirectResponse(f"/patients/{patient_id}?notice=need-doc", status_code=303)
        want_model = use_model == "yes" and client is not None
        held = model_block_reason(docs) if want_model else ""
        result = analysis.analyze(
            docs, disposition_hint=p["disposition"], discharge_hint=p["discharge_date"],
            client=client if want_model and not held else None, model=settings.model,
        )
        if held:
            result["message"] = held
        with db.connect() as conn:
            analysis.store(db, conn, cipher, user["org_id"], patient_id, user["user_id"], result)
            db.audit(conn, user["org_id"], user["user_id"], "check_run", f"patient:{patient_id}", client_ip(request))
        return RedirectResponse(f"/patients/{patient_id}?notice={check_notice_code(result['message'])}", status_code=303)

    # ---------- compliance ----------

    def compliance_summary(org_id: int) -> dict:
        # The sealed analysis is the record. Plaintext finding rows are ignored
        # so a copied or edited database cannot paint a miss as a pass.
        today = date.today()
        with db.connect() as conn:
            latest = conn.execute(
                """SELECT a.result_enc, a.patient_id, p.label, p.unit, p.attending, p.discharge_date
                   FROM analyses a JOIN patients p ON p.id = a.patient_id AND p.org_id = a.org_id
                   WHERE a.org_id = ? AND a.id IN
                     (SELECT MAX(id) FROM analyses WHERE org_id = ? GROUP BY patient_id)""",
                (org_id, org_id),
            ).fetchall()
        by_rule = {r.id: {"pass": 0, "fail": 0, "unclear": 0} for r in RULES}
        by_attending: dict[str, dict] = defaultdict(lambda: {"checked": set(), "fail": 0, "unclear": 0})
        by_unit: dict[str, dict] = defaultdict(lambda: {"checked": set(), "fail": 0, "unclear": 0})
        open_items: dict[int, dict] = {}
        unreadable = 0
        for row in latest:
            try:
                result = json.loads(cipher.decrypt(row["result_enc"]))
                findings = result["findings"]
            except (RuntimeError, KeyError, TypeError, ValueError):
                unreadable += 1
                continue
            label = cipher.decrypt_field(row["label"] or "")
            unit = cipher.decrypt_field(row["unit"] or "") or "Not recorded"
            attending = cipher.decrypt_field(row["attending"] or "") or "Not recorded"
            discharge = cipher.decrypt_field(row["discharge_date"] or "")
            timeliness = timeliness_of(result)
            authenticated = status_of(result, "authenticated")
            signed = timeliness == "pass" and authenticated == "pass"
            for finding in findings:
                rule_id, status = finding.get("rule_id"), finding.get("status")
                if status in by_rule.get(rule_id, {}):
                    by_rule[rule_id][status] += 1
                for key, bucket in ((attending, by_attending), (unit, by_unit)):
                    bucket[key]["checked"].add(row["patient_id"])
                    if status in ("fail", "unclear"):
                        bucket[key][status] += 1
                if status in ("fail", "unclear") and rule_id in RULES_BY_ID:
                    item = open_items.setdefault(row["patient_id"], {
                        "patient_id": row["patient_id"], "label": label, "attending": attending,
                        "fails": [], "reviews": [], "signed": signed,
                        "clock": clock_for(discharge, timeliness, today, authenticated),
                    })
                    bucket_name = "fails" if status == "fail" else "reviews"
                    item[bucket_name].append(RULES_BY_ID[rule_id].title)
        rules_out = []
        for r in RULES:
            c = by_rule[r.id]
            applicable = c["pass"] + c["fail"] + c["unclear"]
            rules_out.append({"id": r.id, "title": r.title, "citation": r.citation, "group": r.group, **c,
                              "applicable": applicable, "fail_rate": round(100 * c["fail"] / applicable) if applicable else None})
        rules_out.sort(key=lambda x: (-(x["fail_rate"] or -1), x["title"]))

        def flat(b):
            rows = ({"name": k, "checked": len(v["checked"]), "fail": v["fail"], "unclear": v["unclear"]} for k, v in b.items())
            return sorted(rows, key=lambda x: x["name"].lower())

        patients_checked = len(latest) - unreadable

        def open_rank(item: dict):
            # Same clock order as the work queue. A negative day count on a
            # signed chart must not jump ahead of a chart that is still due.
            days = item["clock"]["days"]
            if days is None:
                clock = 9_000
            elif item.get("signed"):
                clock = 5_000
            else:
                clock = days
            return (clock, -(len(item["fails"]) + len(item["reviews"])), item["label"].lower())

        open_rows = sorted(open_items.values(), key=open_rank)
        return {"patients_checked": patients_checked, "unreadable": unreadable, "rules": rules_out,
                "by_attending": flat(by_attending), "by_unit": flat(by_unit), "open": open_rows}

    @app.get("/compliance", response_class=HTMLResponse)
    def compliance(request: Request, user=Depends(require_role("compliance", "admin"))):
        s = compliance_summary(user["org_id"])
        return render(request, "compliance.html", {"user": user, "s": s, "nav": "compliance"})

    @app.get("/api/compliance/summary")
    def compliance_api(user=Depends(require_role("compliance", "admin"))):
        s = compliance_summary(user["org_id"])
        # Aggregates only: no patient labels or document text leave through the API.
        return {"rules_version": RULES_VERSION, "patients_checked": s["patients_checked"],
                "rules": [{k: r[k] for k in ("id", "citation", "pass", "fail", "unclear", "fail_rate")} for r in s["rules"]]}

    @app.get("/rules", response_class=HTMLResponse)
    def rules_page(request: Request, user=Depends(current_user)):
        return render(request, "rules.html", {"user": user, "rules": RULES, "nav": "rules"})

    @app.get("/audit", response_class=HTMLResponse)
    def audit(request: Request, user=Depends(require_role("admin", "compliance"))):
        with db.connect() as conn:
            rows = conn.execute(
                """SELECT a.at, a.action, a.target, a.ip, u.display_name FROM audit_log a
                   LEFT JOIN users u ON u.id = a.user_id WHERE a.org_id = ? ORDER BY a.id DESC LIMIT 300""",
                (user["org_id"],),
            ).fetchall()
        return render(request, "audit.html", {"user": user, "rows": rows, "nav": "audit"})

    @app.get("/privacy", response_class=HTMLResponse)
    def privacy(request: Request):
        return render(request, "legal.html", {"user": sessions.lookup(request.cookies.get(SESSION_COOKIE)), "page": "privacy"})

    @app.get("/terms", response_class=HTMLResponse)
    def terms(request: Request):
        return render(request, "legal.html", {"user": sessions.lookup(request.cookies.get(SESSION_COOKIE)), "page": "terms"})

    return app


def get_app() -> FastAPI:  # for `uvicorn app.main:get_app --factory`
    return create_app()
