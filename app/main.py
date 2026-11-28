"""Discharge Check: web app entry point."""
from __future__ import annotations

import json
import logging
import re
import secrets
from collections import defaultdict
from datetime import date, timedelta
from pathlib import Path
from typing import Annotated

import anthropic
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi import Path as PathParam
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import analysis, audit as audit_chain
from .config import Settings, load_settings
from .db import Database
from .ingest import DOC_KINDS, IngestError, parse_upload
from .rules import RULES, RULES_BY_ID, RULES_VERSION, Doc
from .security import (
    FLASH_COOKIE,
    SESSION_COOKIE,
    Cipher,
    Flash,
    LoginLimiter,
    RateLimiter,
    SecurityMiddleware,
    Sessions,
    burn_password_check,
    csrf_ok,
    is_health_check,
    verify_password,
)

log = logging.getLogger(__name__)
HERE = Path(__file__).parent
# Path ids: positive and inside SQLite's 64-bit range (a larger number used to crash the query).
Id = Annotated[int, PathParam(ge=1, le=2**53)]
AUDIT_PAGE = 100
# The /audit page re-verifies the chain on each view; past this many rows it
# checks only the newest ones (run scripts/verify_audit.py for the full log).
AUDIT_VERIFY_MAX = 50_000
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


AUDIT_ACTIONS = {
    "login": "Signed in", "login_failed": "Sign-in failed", "login_blocked": "Sign-in blocked (too many attempts)",
    "logout": "Signed out", "patient_list": "Discharge list viewed", "patient_create": "Discharge added", "patient_view": "Discharge viewed", "document_upload": "Document added",
    "document_view": "Document viewed", "document_delete": "Document removed", "check_run": "Check run",
    "compliance_view": "Compliance overview viewed", "compliance_api": "Compliance data exported", "audit_view": "Access log viewed",
}


class AuthRequired(Exception):
    pass


class _HostCheck(TrustedHostMiddleware):
    """Host allow-list for everything except the load balancer's health
    probe, which arrives addressed to the task IP."""

    async def __call__(self, scope, receive, send):
        if is_health_check(scope):
            return await self.app(scope, receive, send)
        return await super().__call__(scope, receive, send)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    db = Database(settings.database_path, audit_chain.derive_key(settings.audit_key, settings.data_key))
    cipher = Cipher(settings.data_key)
    sessions = Sessions(db, settings)
    limiter = LoginLimiter(db, settings)
    rate = RateLimiter(db)
    flash = Flash(settings.session_pepper, settings.force_https)
    client = (anthropic.Anthropic(api_key=settings.anthropic_api_key, timeout=settings.model_timeout_seconds, max_retries=2)
              if settings.anthropic_api_key else None)

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    # Multipart overhead on top of the file itself.
    app.add_middleware(SecurityMiddleware, force_https=settings.force_https, max_body=settings.max_upload_bytes + 64 * 1024)
    if "*" not in settings.allowed_hosts:
        app.add_middleware(_HostCheck, allowed_hosts=list(settings.allowed_hosts))
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
        f = flash.read(request.cookies.get(FLASH_COOKIE))
        ctx = {"notice": f["n"], "warnings": f["w"], "error": f["e"], **ctx}
        resp = templates.TemplateResponse(request, name, ctx, status_code=status)
        if request.cookies.get(FLASH_COOKIE):
            resp.delete_cookie(FLASH_COOKIE, path="/")
        return resp

    def go(url: str, notice: str = "", warnings: list[str] | None = None, error: str = ""):
        resp = RedirectResponse(url, status_code=303)
        if notice or warnings or error:
            flash.set(resp, notice, warnings, error)
        return resp

    @app.exception_handler(AuthRequired)
    async def _auth(request: Request, exc: AuthRequired):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"error": "Sign in first."}, status_code=401)
        resp = RedirectResponse("/login", status_code=303)
        if request.cookies.get(SESSION_COOKIE):  # had a session, and it ended
            flash.set(resp, error="Your session ended. Sign in again.")
            resp.delete_cookie(SESSION_COOKIE, path="/")
        return resp

    def error_response(request: Request, code: int):
        messages = {400: "The request was not valid.", 401: "Sign in first.", 403: "You do not have access to this page.",
                    404: "That page or record does not exist.", 405: "That action is not allowed here.",
                    413: "The upload is too large.", 429: "Too many requests. Wait a few minutes and try again."}
        msg = messages.get(code, "Something went wrong.")
        if request.url.path.startswith("/api/"):
            return JSONResponse({"error": msg}, status_code=code)
        user = sessions.lookup(request.cookies.get(SESSION_COOKIE)) if code in (403, 404) else None
        return templates.TemplateResponse(request, "error.html", {"user": user, "message": msg, "code": code}, status_code=code)

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException):
        return error_response(request, exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def _invalid(request: Request, exc: RequestValidationError):
        # FastAPI's default echoes the submitted values (passwords included) back as JSON.
        return error_response(request, 404 if any(e.get("loc", [""])[0] == "path" for e in exc.errors()) else 400)

    # ---------- login ----------

    @app.get("/favicon.ico", include_in_schema=False)
    def favicon():
        from fastapi.responses import Response
        return Response(status_code=204)

    @app.get("/robots.txt", include_in_schema=False)
    def robots():
        return Response("User-agent: *\nDisallow: /\n", media_type="text/plain")

    @app.get("/", include_in_schema=False)
    def home(request: Request):
        return RedirectResponse("/patients" if sessions.lookup(request.cookies.get(SESSION_COOKIE)) else "/login", status_code=303)

    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request):
        if sessions.lookup(request.cookies.get(SESSION_COOKIE)):
            return RedirectResponse("/patients", status_code=303)
        token = secrets.token_urlsafe(24)
        resp = render(request, "login.html", {"user": None, "pre": token})
        set_cookie(resp, PRE_COOKIE, token, 900)
        return resp

    @app.post("/login")
    def login(request: Request, email: str = Form("", max_length=254), password: str = Form("", max_length=256),
              pre: str = Form("", max_length=64), website: str = Form("", max_length=200)):
        ip = client_ip(request)
        email = email.strip().lower()
        bad = go("/login", error="Email or password is incorrect.")
        if website:  # honeypot field, invisible to people
            return bad
        if not csrf_ok(request.cookies.get(PRE_COOKIE, ""), pre):
            return go("/login", error="The sign-in form expired. Try again.")
        if limiter.blocked(ip, email):
            with db.connect() as conn:
                db.audit(conn, None, None, "login_blocked", f"email:{email[:80]}", ip)
            return go("/login", error=f"Too many attempts. Wait {settings.login_window_minutes} minutes and try again.")
        user = None
        if _EMAIL_RE.match(email):
            with db.connect() as conn:
                user = conn.execute("SELECT id, org_id, password_hash FROM users WHERE email = ?", (email,)).fetchone()
        if user is None:
            burn_password_check(password)
            limiter.record_failure(ip, email)
            with db.connect() as conn:
                db.audit(conn, None, None, "login_failed", f"email:{email[:80]}", ip)
            return bad
        if not verify_password(user["password_hash"], password):
            limiter.record_failure(ip, email)
            with db.connect() as conn:
                db.audit(conn, user["org_id"], user["id"], "login_failed", ip=ip)
            return bad
        limiter.clear(email)
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
        with db.connect() as conn:
            db.audit(conn, user["org_id"], user["user_id"], "logout", ip=client_ip(request))
        resp = go("/login", notice="You are signed out.")
        resp.delete_cookie(SESSION_COOKIE, path="/")
        return resp

    # ---------- patients ----------

    @app.get("/patients", response_class=HTMLResponse)
    def patients(request: Request, user=Depends(current_user)):
        with db.connect() as conn:
            rows = db.patients(conn, user["org_id"])
            db.audit(conn, user["org_id"], user["user_id"], "patient_list", ip=client_ip(request))
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
                d = date.fromisoformat(data["discharge_date"])
                if not (date(2000, 1, 1) <= d <= date.today() + timedelta(days=30)):
                    errors.append("Discharge date must be between 2000 and 30 days from today.")
                data["discharge_date"] = d.isoformat()
            except ValueError:
                errors.append("Discharge date must be a valid date (YYYY-MM-DD).")
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

    def limited(user, action: str, limit: int) -> bool:
        return rate.allow(f"{action}:user:{user['user_id']}", limit, timedelta(hours=1))

    def load_patient(conn, user, patient_id: int):
        p = db.patient(conn, user["org_id"], patient_id)
        if p is None:
            raise HTTPException(status_code=404)
        return p

    def load_docs(conn, user, patient_id: int) -> list[Doc]:
        rows = db.documents(conn, user["org_id"], patient_id)
        return [Doc(index=i, kind=r["kind"], filename=r["filename"], text=cipher.decrypt(r["body_enc"]), author=r["author"]) for i, r in enumerate(rows)]

    @app.get("/patients/{patient_id}", response_class=HTMLResponse)
    def patient_detail(request: Request, patient_id: Id, user=Depends(current_user)):
        with db.connect() as conn:
            p = load_patient(conn, user, patient_id)
            docs = db.documents(conn, user["org_id"], patient_id)
            a = db.latest_analysis(conn, user["org_id"], patient_id)
            db.audit(conn, user["org_id"], user["user_id"], "patient_view", f"patient:{patient_id}", client_ip(request))
        result = json.loads(cipher.decrypt(a["result_enc"])) if a else None
        stale = bool(a and docs and max(d["created_at"] for d in docs) > a["created_at"])
        # Gaps first, grouped by section; finished items fold away below them.
        groups: dict[str, list] = defaultdict(list)
        done: dict[str, list] = defaultdict(list)
        if result:
            for f in result["findings"]:
                rule = RULES_BY_ID.get(f["rule_id"])
                if rule:
                    (groups if f["status"] in ("fail", "unclear") else done)[rule.group].append({"rule": rule, **f})
        return render(request, "patient.html", {
            "user": user, "p": p, "docs": docs, "analysis": a, "result": result, "groups": dict(groups), "done": dict(done),
            "model_on": client is not None, "nav": "patients", "stale": stale,
            "can_delete": lambda d: user["role"] == "admin" or d["uploaded_by"] == user["user_id"],
        })

    @app.post("/patients/{patient_id}/documents")
    async def upload_document(request: Request, patient_id: Id, user=Depends(check_csrf),
                              kind: str = Form(..., max_length=40), confirm: str = Form(""), file: UploadFile = File(...)):
        with db.connect() as conn:
            load_patient(conn, user, patient_id)
        back = f"/patients/{patient_id}"
        if confirm != "yes":
            return go(back, error="Confirm the record is synthetic or de-identified.")
        if not limited(user, "upload", settings.uploads_per_hour):
            return go(back, error="Upload limit reached for this hour. Try again later.")
        raw = await file.read(settings.max_upload_bytes + 1)
        try:
            parsed = parse_upload(raw, file.filename or "upload.txt", kind, settings.max_upload_bytes)
        except IngestError as exc:
            return go(back, error=str(exc))
        with db.connect() as conn:
            conn.execute(
                "INSERT INTO documents (org_id, patient_id, kind, filename, author, body_enc, uploaded_by) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (user["org_id"], patient_id, parsed.kind, parsed.filename, parsed.author, cipher.encrypt(parsed.text), user["user_id"]),
            )
            db.audit(conn, user["org_id"], user["user_id"], "document_upload", f"patient:{patient_id}", client_ip(request))
        return go(back, notice=f"Added {parsed.filename}. Run the check to update the results.", warnings=parsed.warnings)

    @app.get("/patients/{patient_id}/documents/{doc_id}", response_class=HTMLResponse)
    def view_document(request: Request, patient_id: Id, doc_id: Id, user=Depends(current_user)):
        with db.connect() as conn:
            p = load_patient(conn, user, patient_id)
            row = db.document(conn, user["org_id"], patient_id, doc_id)
            if row is None:
                raise HTTPException(status_code=404)
            db.audit(conn, user["org_id"], user["user_id"], "document_view", f"document:{doc_id}", client_ip(request))
        return render(request, "document.html", {"user": user, "p": p, "doc": row, "text": cipher.decrypt(row["body_enc"]), "nav": "patients"})

    @app.post("/patients/{patient_id}/documents/{doc_id}/delete")
    def delete_document(request: Request, patient_id: Id, doc_id: Id, user=Depends(check_csrf)):
        """Removal is a soft delete: the record leaves the patient's file and
        every check, but stays in the database for the retention period."""
        with db.connect() as conn:
            load_patient(conn, user, patient_id)
            row = db.document(conn, user["org_id"], patient_id, doc_id)
            if row is None:
                raise HTTPException(status_code=404)
            if user["role"] != "admin" and row["uploaded_by"] != user["user_id"]:
                raise HTTPException(status_code=403)
            conn.execute("UPDATE documents SET deleted_at = datetime('now'), deleted_by = ? WHERE id = ?", (user["user_id"], doc_id))
            db.audit(conn, user["org_id"], user["user_id"], "document_delete", f"document:{doc_id}", client_ip(request))
        return go(f"/patients/{patient_id}", notice=f"Removed {row['filename']}. Run the check again to update the results.")

    @app.post("/patients/{patient_id}/check")
    def run_check(request: Request, patient_id: Id, user=Depends(check_csrf)):
        back = f"/patients/{patient_id}"
        with db.connect() as conn:
            p = load_patient(conn, user, patient_id)
            docs = load_docs(conn, user, patient_id)
        if not docs:
            return go(back, error="Upload at least one document first.")
        if not limited(user, "check", settings.checks_per_hour):
            return go(back, error=f"You have run {settings.checks_per_hour} checks in the last hour. Try again later.")
        result = analysis.analyze(docs, disposition_hint=p["disposition"], discharge_hint=p["discharge_date"],
                                  client=client, model=settings.model)
        with db.connect() as conn:
            analysis.store(db, conn, cipher, user["org_id"], patient_id, user["user_id"], result)
            db.audit(conn, user["org_id"], user["user_id"], "check_run", f"patient:{patient_id}", client_ip(request))
        if result["message"]:
            return go(back, error=result["message"])
        return go(back, notice="Check complete.")

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
        with db.connect() as conn:  # the page lists patient labels with their gaps
            db.audit(conn, user["org_id"], user["user_id"], "compliance_view", ip=client_ip(request))
        return render(request, "compliance.html", {"user": user, "s": s, "nav": "compliance"})

    @app.get("/api/compliance/summary")
    def compliance_api(request: Request, user=Depends(require_role("compliance", "admin"))):
        s = compliance_summary(user["org_id"])
        with db.connect() as conn:
            db.audit(conn, user["org_id"], user["user_id"], "compliance_api", ip=client_ip(request))
        # Aggregates only: no patient labels or document text leave through the API.
        return {"rules_version": RULES_VERSION, "patients_checked": s["patients_checked"],
                "rules": [{k: r[k] for k in ("id", "citation", "pass", "fail", "unclear", "fail_rate")} for r in s["rules"]]}

    @app.get("/rules", response_class=HTMLResponse)
    def rules_page(request: Request, user=Depends(current_user)):
        return render(request, "rules.html", {"user": user, "rules": RULES, "nav": "rules"})

    @app.get("/audit", response_class=HTMLResponse)
    def audit(request: Request, user=Depends(require_role("admin", "compliance")), page: int = 1, action: str = ""):
        page = max(1, min(page, 10_000))
        action = action if action in AUDIT_ACTIONS else ""
        where, args = "a.org_id = ?", [user["org_id"]]
        if action:
            where += " AND a.action = ?"
            args.append(action)
        with db.connect() as conn:
            # `where` holds only constant fragments; every value is a bound parameter.
            sql = ("SELECT a.at, a.action, a.target, a.ip, u.display_name FROM audit_log a "
                   "LEFT JOIN users u ON u.id = a.user_id WHERE " + where +  # nosec B608
                   " ORDER BY a.id DESC LIMIT ? OFFSET ?")
            rows = conn.execute(
                sql,
                (*args, AUDIT_PAGE + 1, (page - 1) * AUDIT_PAGE),
            ).fetchall()
            integrity = audit_chain.verify(conn, db.audit_key, last=AUDIT_VERIFY_MAX)
            if not integrity.ok:
                log.error("Access log integrity check failed at event %s: %s", integrity.broken_id, integrity.reason)
            db.audit(conn, user["org_id"], user["user_id"], "audit_view", ip=client_ip(request))
        return render(request, "audit.html", {"user": user, "rows": rows[:AUDIT_PAGE], "page": page, "action": action,
                                              "more": len(rows) > AUDIT_PAGE, "actions": AUDIT_ACTIONS, "nav": "audit",
                                              "integrity": integrity})

    @app.get("/privacy", response_class=HTMLResponse)
    def privacy(request: Request):
        return render(request, "legal.html", {"user": sessions.lookup(request.cookies.get(SESSION_COOKIE)), "page": "privacy"})

    @app.get("/terms", response_class=HTMLResponse)
    def terms(request: Request):
        return render(request, "legal.html", {"user": sessions.lookup(request.cookies.get(SESSION_COOKIE)), "page": "terms"})

    return app


def get_app() -> FastAPI:  # for `uvicorn app.main:get_app --factory`
    return create_app()
