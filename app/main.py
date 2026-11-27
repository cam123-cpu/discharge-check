"""Discharge Check: web app entry point."""
from __future__ import annotations

import json
import re
import secrets
from collections import defaultdict
from datetime import date
from pathlib import Path

import anthropic
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import analysis
from .config import Settings, load_settings
from .db import Database
from .ingest import DOC_KINDS, IngestError, parse_upload
from .rules import RULES, RULES_BY_ID, RULES_VERSION, Doc
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


class AuthRequired(Exception):
    pass


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    db = Database(settings.database_path)
    cipher = Cipher(settings.data_key)
    sessions = Sessions(db, settings)
    limiter = LoginLimiter(db, settings)
    client = anthropic.Anthropic(api_key=settings.anthropic_api_key) if settings.anthropic_api_key else None

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(SecurityHeadersMiddleware, force_https=settings.force_https)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=HERE / "templates")
    templates.env.globals.update(DOC_KINDS=DOC_KINDS, ROLE_LABELS=ROLE_LABELS, RULES_VERSION=RULES_VERSION)

    app.state.db = db
    app.state.settings = settings

    def client_ip(request: Request) -> str:
        return (request.client.host if request.client else "")[:64]

    def set_cookie(resp, name: str, value: str, max_age: int):
        resp.set_cookie(name, value, max_age=max_age, httponly=True, secure=settings.force_https, samesite="strict", path="/")

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
        form = await request.form()
        if not csrf_ok(user["csrf_token"], form.get("csrf")):
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
    def login_page(request: Request, error: str = ""):
        token = secrets.token_urlsafe(24)
        resp = render(request, "login.html", {"user": None, "pre": token, "error": error[:120]})
        set_cookie(resp, PRE_COOKIE, token, 900)
        return resp

    @app.post("/login")
    def login(request: Request, email: str = Form("", max_length=254), password: str = Form("", max_length=256),
              pre: str = Form("", max_length=64), website: str = Form("", max_length=200)):
        ip = client_ip(request)
        email = email.strip().lower()
        bad = RedirectResponse("/login?error=Email+or+password+is+incorrect.", status_code=303)
        if website:  # honeypot field, invisible to people
            return bad
        if not csrf_ok(request.cookies.get(PRE_COOKIE, ""), pre):
            return RedirectResponse("/login?error=Your+session+expired.+Try+again.", status_code=303)
        keys = (f"ip:{ip}", f"email:{email}")
        if limiter.blocked(*keys):
            return RedirectResponse("/login?error=Too+many+attempts.+Wait+15+minutes.", status_code=303)
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
        resp.delete_cookie(PRE_COOKIE, path="/")
        return resp

    @app.post("/logout")
    def logout(request: Request, user=Depends(check_csrf)):
        sessions.destroy(request.cookies.get(SESSION_COOKIE))
        resp = RedirectResponse("/login", status_code=303)
        resp.delete_cookie(SESSION_COOKIE, path="/")
        return resp

    # ---------- patients ----------

    @app.get("/patients", response_class=HTMLResponse)
    def patients(request: Request, user=Depends(current_user)):
        with db.connect() as conn:
            rows = db.patients(conn, user["org_id"])
        return render(request, "patients.html", {"user": user, "patients": rows, "nav": "patients"})

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
        with db.connect() as conn:
            cur = conn.execute(
                "INSERT INTO patients (org_id, label, unit, attending, discharge_date, disposition, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (user["org_id"], data["label"], data["unit"], data["attending"], data["discharge_date"], data["disposition"], user["user_id"]),
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
        return [Doc(index=i, kind=r["kind"], filename=r["filename"], text=cipher.decrypt(r["body_enc"]), author=r["author"]) for i, r in enumerate(rows)]

    @app.get("/patients/{patient_id}", response_class=HTMLResponse)
    def patient_detail(request: Request, patient_id: int, user=Depends(current_user), notice: str = ""):
        with db.connect() as conn:
            p = load_patient(conn, user, patient_id)
            docs = db.documents(conn, user["org_id"], patient_id)
            a = db.latest_analysis(conn, user["org_id"], patient_id)
            db.audit(conn, user["org_id"], user["user_id"], "patient_view", f"patient:{patient_id}", client_ip(request))
        result = json.loads(cipher.decrypt(a["result_enc"])) if a else None
        groups: dict[str, list] = defaultdict(list)
        if result:
            for f in result["findings"]:
                rule = RULES_BY_ID.get(f["rule_id"])
                if rule:
                    groups[rule.group].append({"rule": rule, **f})
        return render(request, "patient.html", {
            "user": user, "p": p, "docs": docs, "analysis": a, "result": result, "groups": dict(groups),
            "notice": notice[:200], "model_on": client is not None, "nav": "patients",
            "warnings": [w for w in request.query_params.getlist("warn")][:3],
        })

    @app.post("/patients/{patient_id}/documents")
    async def upload_document(request: Request, patient_id: int, user=Depends(check_csrf),
                              kind: str = Form(..., max_length=40), confirm: str = Form(""), file: UploadFile = File(...)):
        if confirm != "yes":
            return RedirectResponse(f"/patients/{patient_id}?notice=Confirm+the+record+is+synthetic+or+de-identified.", status_code=303)
        raw = await file.read(settings.max_upload_bytes + 1)
        try:
            parsed = parse_upload(raw, file.filename or "upload.txt", kind, settings.max_upload_bytes)
        except IngestError as exc:
            from urllib.parse import quote
            return RedirectResponse(f"/patients/{patient_id}?notice={quote(str(exc))}", status_code=303)
        with db.connect() as conn:
            load_patient(conn, user, patient_id)
            conn.execute(
                "INSERT INTO documents (org_id, patient_id, kind, filename, author, body_enc, uploaded_by) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (user["org_id"], patient_id, parsed.kind, parsed.filename, parsed.author, cipher.encrypt(parsed.text), user["user_id"]),
            )
            db.audit(conn, user["org_id"], user["user_id"], "document_upload", f"patient:{patient_id}", client_ip(request))
        from urllib.parse import urlencode
        q = urlencode([("notice", f"Added {parsed.filename}. Run the check to update results.")] + [("warn", w) for w in parsed.warnings])
        return RedirectResponse(f"/patients/{patient_id}?{q}", status_code=303)

    @app.get("/patients/{patient_id}/documents/{doc_id}", response_class=HTMLResponse)
    def view_document(request: Request, patient_id: int, doc_id: int, user=Depends(current_user)):
        with db.connect() as conn:
            p = load_patient(conn, user, patient_id)
            row = conn.execute("SELECT * FROM documents WHERE id = ? AND patient_id = ? AND org_id = ?", (doc_id, patient_id, user["org_id"])).fetchone()
            if row is None:
                raise HTTPException(status_code=404)
            db.audit(conn, user["org_id"], user["user_id"], "document_view", f"document:{doc_id}", client_ip(request))
        return render(request, "document.html", {"user": user, "p": p, "doc": row, "text": cipher.decrypt(row["body_enc"]), "nav": "patients"})

    @app.post("/patients/{patient_id}/documents/{doc_id}/delete")
    def delete_document(request: Request, patient_id: int, doc_id: int, user=Depends(check_csrf)):
        with db.connect() as conn:
            load_patient(conn, user, patient_id)
            n = conn.execute("DELETE FROM documents WHERE id = ? AND patient_id = ? AND org_id = ?", (doc_id, patient_id, user["org_id"])).rowcount
            if n == 0:
                raise HTTPException(status_code=404)
            db.audit(conn, user["org_id"], user["user_id"], "document_delete", f"document:{doc_id}", client_ip(request))
        return RedirectResponse(f"/patients/{patient_id}?notice=Document+removed.", status_code=303)

    @app.post("/patients/{patient_id}/check")
    def run_check(request: Request, patient_id: int, user=Depends(check_csrf)):
        with db.connect() as conn:
            p = load_patient(conn, user, patient_id)
            docs = load_docs(conn, user, patient_id)
        if not docs:
            return RedirectResponse(f"/patients/{patient_id}?notice=Upload+at+least+one+document+first.", status_code=303)
        result = analysis.analyze(docs, disposition_hint=p["disposition"], discharge_hint=p["discharge_date"],
                                  client=client, model=settings.model)
        with db.connect() as conn:
            analysis.store(db, conn, cipher, user["org_id"], patient_id, user["user_id"], result)
            db.audit(conn, user["org_id"], user["user_id"], "check_run", f"patient:{patient_id}", client_ip(request))
        note = result["message"] or "Check complete."
        from urllib.parse import quote
        return RedirectResponse(f"/patients/{patient_id}?notice={quote(note)}", status_code=303)

    # ---------- compliance ----------

    def compliance_summary(org_id: int) -> dict:
        with db.connect() as conn:
            latest = conn.execute(
                """SELECT f.rule_id, f.status, p.unit, p.attending, p.id AS patient_id, p.label
                   FROM findings f JOIN patients p ON p.id = f.patient_id AND p.org_id = f.org_id
                   WHERE f.org_id = ? AND f.analysis_id IN
                     (SELECT MAX(a.id) FROM analyses a WHERE a.org_id = ? GROUP BY a.patient_id)""",
                (org_id, org_id),
            ).fetchall()
        by_rule = {r.id: {"pass": 0, "fail": 0, "unclear": 0} for r in RULES}
        by_attending: dict[str, dict] = defaultdict(lambda: {"checked": set(), "fail": 0, "unclear": 0})
        by_unit: dict[str, dict] = defaultdict(lambda: {"checked": set(), "fail": 0, "unclear": 0})
        open_items: dict[int, dict] = {}
        for row in latest:
            if row["status"] in by_rule.get(row["rule_id"], {}):
                by_rule[row["rule_id"]][row["status"]] += 1
            for key, bucket in ((row["attending"] or "Not recorded", by_attending), (row["unit"] or "Not recorded", by_unit)):
                bucket[key]["checked"].add(row["patient_id"])
                if row["status"] in ("fail", "unclear"):
                    bucket[key][row["status"]] += 1
            if row["status"] == "fail":
                item = open_items.setdefault(row["patient_id"], {"patient_id": row["patient_id"], "label": row["label"], "attending": row["attending"], "fails": []})
                item["fails"].append(RULES_BY_ID[row["rule_id"]].title)
        rules_out = []
        for r in RULES:
            c = by_rule[r.id]
            applicable = c["pass"] + c["fail"] + c["unclear"]
            rules_out.append({"id": r.id, "title": r.title, "citation": r.citation, "group": r.group, **c,
                              "applicable": applicable, "fail_rate": round(100 * c["fail"] / applicable) if applicable else None})
        rules_out.sort(key=lambda x: (-(x["fail_rate"] or -1), x["title"]))

        def flat(b):
            return sorted(({"name": k, "checked": len(v["checked"]), "fail": v["fail"], "unclear": v["unclear"]} for k, v in b.items()), key=lambda x: -x["fail"])

        patients_checked = len({row["patient_id"] for row in latest})
        return {"patients_checked": patients_checked, "rules": rules_out, "by_attending": flat(by_attending),
                "by_unit": flat(by_unit), "open": sorted(open_items.values(), key=lambda x: -len(x["fails"]))}

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
