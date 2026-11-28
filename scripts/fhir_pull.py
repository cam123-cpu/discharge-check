"""Pull a discharge from a SMART on FHIR server (sandboxes or a real EHR).

Usage:
    python -m scripts.fhir_pull discover
    python -m scripts.fhir_pull jwks --key private.pem
    python -m scripts.fhir_pull pull --patient ID [--encounter ID] [--out bundle.json]
    python -m scripts.fhir_pull import --bundle bundle.json --org-id 1 --label SYN-0100 [--kind discharge_summary]

Settings come from .env / the environment (FHIR_BASE_URL, FHIR_AUTH_MODE, ...).
Access tokens are never printed."""
from __future__ import annotations

import argparse
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import app.config  # noqa: F401  (loads .env into os.environ)
from app.fhir.smart import (
    FhirClient,
    FhirClientError,
    SmartConfigError,
    SmartSettings,
    begin_authorization,
    discover,
    exchange_code,
    fetch_discharge_bundle,
    generate_jwks,
)

LOGIN_TIMEOUT = 300  # seconds to wait for the browser sign-in


def _err(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)


def cmd_discover(_: argparse.Namespace) -> int:
    s = SmartSettings.from_env()
    cfg = discover(s)
    print(f"FHIR base:               {s.base_url}")
    print(f"Source:                  {cfg.source}")
    print(f"Authorization endpoint:  {cfg.authorization_endpoint or '-'}")
    print(f"Token endpoint:          {cfg.token_endpoint or '-'}")
    for name in ("capabilities", "code_challenge_methods_supported", "token_endpoint_auth_methods_supported",
                 "grant_types_supported"):
        print(f"{name}: {', '.join(getattr(cfg, name)) or '-'}")
    return 0


def cmd_jwks(args: argparse.Namespace) -> int:
    print(json.dumps(generate_jwks(Path(args.key).read_bytes(), args.kid), indent=2))
    return 0


def _callback_params(request_path: str, expected_path: str) -> dict[str, str] | None:
    """Query parameters of an OAuth redirect, or None for any other request (another
    path, a favicon, a bare hit without `code` or `error`), which is ignored."""
    url = urlsplit(request_path)
    if url.path != expected_path:
        return None
    q = {k: v[0] for k, v in parse_qs(url.query).items()}
    return q if ("code" in q or "error" in q) else None


def _wait_for_code(redirect_uri: str, timeout: float | None = None) -> dict[str, str]:
    """Local server that catches the OAuth redirect; other requests are ignored until timeout."""
    parts = urlsplit(redirect_uri)
    if parts.scheme != "http" or parts.hostname not in ("localhost", "127.0.0.1"):
        raise SmartConfigError("Automatic sign-in needs FHIR_REDIRECT_URI on http://localhost or http://127.0.0.1.")
    expected_path = parts.path or "/"
    result: dict[str, str] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if result:  # already have the redirect; ignore late or repeated hits
                self.send_error(404)
                return
            q = _callback_params(self.path, expected_path)
            if q is None:
                self.send_error(404)
                return
            result.update(q)
            ok = "code" in q
            self.send_response(200 if ok else 400)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Signed in. You can close this tab." if ok else b"Sign-in failed. See the terminal.")

        def log_message(self, *a: object) -> None:  # keep the code out of the terminal
            pass

    server = HTTPServer((parts.hostname, parts.port or 80), Handler)
    server.timeout = 1
    deadline = time.monotonic() + (LOGIN_TIMEOUT if timeout is None else timeout)
    try:
        while not result and time.monotonic() < deadline:
            server.handle_request()
    finally:
        server.server_close()
    if not result:
        raise FhirClientError("Timed out waiting for the sign-in redirect.")
    if "error" in result:
        raise FhirClientError(f"Authorization failed: {result['error']} {result.get('error_description', '')[:200]}")
    return result


def cmd_pull(args: argparse.Namespace) -> int:
    s = SmartSettings.from_env()
    token = None
    cfg = None
    if s.auth_mode == "standalone":
        cfg = discover(s)
        req = begin_authorization(s, cfg)
        print("Open this URL in a browser and sign in:\n", file=sys.stderr)
        print(req.url + "\n", file=sys.stderr)
        got = _wait_for_code(s.redirect_uri or "")
        token = exchange_code(s, cfg, got.get("code", ""), got.get("state", ""), req.state, req.code_verifier)
    patient = args.patient or (token.patient if token else None)
    if not patient:
        _err("--patient is required (the server did not return a patient in the launch context).")
        return 2
    with FhirClient(s, config=cfg, token=token) as client:
        bundle, warnings = fetch_discharge_bundle(client, patient, args.encounter)
    text = json.dumps(bundle, indent=2)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"Wrote {len(bundle['entry'])} resources to {args.out}", file=sys.stderr)
    else:
        print(text)
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    return 0


def _dict(v: object) -> dict:
    return v if isinstance(v, dict) else {}


def _discharge_fields(bundle: object) -> tuple[str, str]:
    """(discharge date, disposition) from the first Encounter; tolerant of malformed JSON."""
    entries = _dict(bundle).get("entry")
    for e in entries if isinstance(entries, list) else []:
        r = _dict(_dict(e).get("resource"))
        if r.get("resourceType") == "Encounter":
            end = str(_dict(r.get("period")).get("end") or "")[:10]
            dd = _dict(_dict(r.get("hospitalization")).get("dischargeDisposition"))
            coding = dd.get("coding") if isinstance(dd.get("coding"), list) else []
            dispo = dd.get("text") if isinstance(dd.get("text"), str) else ""
            dispo = dispo or next((c["display"] for c in coding
                                   if isinstance(c, dict) and isinstance(c.get("display"), str) and c["display"]), "")
            return end, str(dispo or "")[:120]
    return "", ""


def cmd_import(args: argparse.Namespace) -> int:
    # Same calls scripts/seed.py makes to store a document.
    from app.config import load_settings
    from app.db import Database
    from app.ingest import IngestError, parse_upload
    from app.security import Cipher

    s = load_settings()
    path = Path(args.bundle)
    raw = path.read_bytes()
    try:
        doc = parse_upload(raw, path.name, args.kind, s.max_upload_bytes)
    except IngestError as exc:
        _err(str(exc))
        return 1
    discharge_date, dispo = _discharge_fields(json.loads(raw))
    db = Database(s.database_path)
    cipher = Cipher(s.data_key)
    with db.connect() as conn:
        if not conn.execute("SELECT 1 FROM orgs WHERE id = ?", (args.org_id,)).fetchone():
            _err(f"No organization with id {args.org_id}.")
            return 1
        row = conn.execute("SELECT id FROM patients WHERE org_id = ? AND label = ?",
                           (args.org_id, args.label)).fetchone()
        pid = row[0] if row else conn.execute(
            "INSERT INTO patients (org_id, label, discharge_date, disposition) VALUES (?, ?, ?, ?)",
            (args.org_id, args.label, discharge_date, dispo)).lastrowid
        conn.execute("INSERT INTO documents (org_id, patient_id, kind, filename, author, body_enc) VALUES (?, ?, ?, ?, ?, ?)",
                     (args.org_id, pid, doc.kind, doc.filename, doc.author, cipher.encrypt(doc.text)))
        db.audit(conn, args.org_id, None, "fhir_import", f"patient:{pid}")
    print(f"Stored {doc.kind} for {args.label} (patient id {pid}).")
    for w in doc.warnings:
        print(f"warning: {w}", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m scripts.fhir_pull", description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("discover", help="show the server's SMART endpoints").set_defaults(fn=cmd_discover)
    j = sub.add_parser("jwks", help="print the public JWKS for a backend-services key")
    j.add_argument("--key", required=True, help="PEM private key (RSA 2048+ or EC P-384)")
    j.add_argument("--kid", help="key id (default: RFC 7638 thumbprint)")
    j.set_defaults(fn=cmd_jwks)
    pl = sub.add_parser("pull", help="fetch a discharge as a FHIR Bundle")
    pl.add_argument("--patient", help="patient id (optional in standalone mode if the launch picks one)")
    pl.add_argument("--encounter", help="encounter id (default: most recent finished inpatient stay)")
    pl.add_argument("--out", help="write the Bundle here instead of stdout")
    pl.set_defaults(fn=cmd_pull)
    im = sub.add_parser("import", help="store a pulled Bundle as a document")
    im.add_argument("--bundle", required=True)
    im.add_argument("--org-id", type=int, required=True)
    im.add_argument("--label", required=True, help="non-identifying label, e.g. SYN-0100")
    im.add_argument("--kind", default="discharge_summary")
    im.set_defaults(fn=cmd_import)
    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except (SmartConfigError, FhirClientError, OSError) as exc:
        _err(str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
