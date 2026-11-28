"""Manage hospital single sign-on providers.

Usage:
  python -m scripts.sso add --org "Demo General Hospital" --slug demo-idp --name "Demo SSO" \\
      --issuer https://login.example.org/tenant/v2.0 --client-id abc --client-secret-env DEMO_SSO_SECRET \\
      --domains demo.test [--auto-provision --default-role nurse] [--enforce] [--protocol oidc|saml]
  python -m scripts.sso list
  python -m scripts.sso disable SLUG
  python -m scripts.sso link SLUG EMAIL SUBJECT

Administrators and accounts with two-factor on are never linked to an IdP
account by email alone; `link` does it explicitly, with the IdP's subject id
for that person (the `sub` claim; in Entra ID the user's object id).

The client secret is read from the named environment variable, never from the
command line (argv shows up in shell history and `ps`). It is stored encrypted
with DATA_KEY. The IdP must be configured with the redirect URI
{PUBLIC_BASE_URL}/sso/callback."""
from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.config import load_settings  # noqa: E402
from app.db import Database  # noqa: E402
from app import sso as sso_module  # noqa: E402
from app.security import Cipher  # noqa: E402
from app.sso import PROVISION_ROLES, SSOError, check_url, parse_domains  # noqa: E402

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
DOMAIN_RE = re.compile(r"^(?=.{1,190}$)[a-z0-9-]+(\.[a-z0-9-]+)+$")


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m scripts.sso", description="Manage hospital SSO providers.")
    sub = p.add_subparsers(dest="cmd", required=True)
    add = sub.add_parser("add", help="register an identity provider for an organization")
    add.add_argument("--org", required=True, help="organization name, exactly as stored")
    add.add_argument("--slug", required=True, help="short id used in /sso/<slug>/start")
    add.add_argument("--name", required=True, help="display name")
    add.add_argument("--protocol", choices=("oidc", "saml"), default="oidc")
    add.add_argument("--issuer", required=True)
    add.add_argument("--client-id", required=True)
    add.add_argument("--client-secret-env", required=True, metavar="VAR",
                     help="name of the environment variable holding the client secret")
    add.add_argument("--domains", required=True, help="comma-separated email domains, e.g. demo.test,demo.org")
    add.add_argument("--auto-provision", action="store_true", help="create accounts on first sign-in")
    add.add_argument("--default-role", default="", choices=("",) + PROVISION_ROLES)
    add.add_argument("--enforce", action="store_true", help="refuse password sign-in for these domains")
    sub.add_parser("list", help="list providers (secrets are never shown)")
    dis = sub.add_parser("disable", help="disable a provider")
    dis.add_argument("slug")
    link = sub.add_parser("link", help="link an existing account to its IdP subject id")
    link.add_argument("slug")
    link.add_argument("email")
    link.add_argument("subject", help="the IdP's `sub` claim for this person")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    s = load_settings()
    db = Database(s.database_path)
    sso_module.ALLOW_LOCAL_HTTP = not s.force_https
    if args.cmd == "link":
        with db.connect() as conn:
            prov = conn.execute("SELECT id, org_id FROM sso_providers WHERE slug = ?", (args.slug,)).fetchone()
            user = conn.execute("SELECT id, org_id FROM users WHERE email = ?", (args.email.strip().lower(),)).fetchone()
            if prov is None or user is None:
                print("No such provider or account.", file=sys.stderr)
                return 1
            if prov["org_id"] != user["org_id"]:
                print("That account belongs to another organization.", file=sys.stderr)
                return 1
            if not args.subject.strip() or len(args.subject) > 255:
                print("Give the IdP subject id.", file=sys.stderr)
                return 2
            conn.execute("DELETE FROM sso_identities WHERE provider_id = ? AND user_id = ?", (prov["id"], user["id"]))
            conn.execute("INSERT INTO sso_identities (provider_id, subject, user_id) VALUES (?, ?, ?)",
                         (prov["id"], args.subject.strip(), user["id"]))
            db.audit(conn, prov["org_id"], user["id"], "sso_linked", f"provider:{args.slug} by:console", "console")
        print(f"Linked {args.email} to {args.slug}.")
        return 0
    if args.cmd == "list":
        with db.connect() as conn:
            rows = conn.execute("SELECT p.*, o.name AS org_name FROM sso_providers p JOIN orgs o ON o.id = p.org_id"
                                " ORDER BY p.id").fetchall()
        if not rows:
            print("No SSO providers.")
        for r in rows:
            flags = [f for f, on in (("enabled", r["enabled"]), ("enforce", r["enforce"]),
                                      (f"auto-provision:{r['default_role']}", r["auto_provision"])) if on]
            print(f"{r['slug']:20} {r['protocol']:5} {r['org_name']!r} {r['issuer']} domains={r['email_domains']}"
                  f" {' '.join(flags) or 'disabled'}")
        return 0
    if args.cmd == "disable":
        with db.connect() as conn:
            n = conn.execute("UPDATE sso_providers SET enabled = 0 WHERE slug = ?", (args.slug,)).rowcount
        if not n:
            print(f"No provider {args.slug!r}.", file=sys.stderr)
            return 1
        print(f"Disabled {args.slug}.")
        return 0

    # add
    def fail(msg: str) -> int:
        print(msg, file=sys.stderr)
        return 2

    if not SLUG_RE.match(args.slug):
        return fail("--slug: use lowercase letters, digits and hyphens.")
    try:
        check_url(args.issuer, "issuer")
    except SSOError:
        return fail("--issuer must be an https URL (http is allowed only for localhost).")
    secret = os.environ.get(args.client_secret_env, "")
    if not secret:
        return fail(f"Environment variable {args.client_secret_env} is empty or not set.")
    domains = parse_domains(args.domains)
    if not domains or not all(DOMAIN_RE.match(d) for d in domains):
        return fail("--domains: give one or more email domains, comma-separated.")
    if args.auto_provision and not args.default_role:
        return fail("--auto-provision needs --default-role.")
    with db.connect() as conn:
        org = conn.execute("SELECT id FROM orgs WHERE name = ?", (args.org,)).fetchone()
        if org is None:
            return fail(f"No organization named {args.org!r}.")
        if conn.execute("SELECT 1 FROM sso_providers WHERE slug = ?", (args.slug,)).fetchone():
            return fail(f"A provider with slug {args.slug!r} already exists.")
        for r in conn.execute("SELECT slug, email_domains FROM sso_providers WHERE enabled = 1"):
            clash = set(domains) & set(parse_domains(r["email_domains"]))
            if clash:
                return fail(f"Domain {min(clash)} already belongs to provider {r['slug']!r}.")
        conn.execute(
            "INSERT INTO sso_providers (org_id, slug, display_name, protocol, issuer, client_id, client_secret_enc,"
            " email_domains, default_role, auto_provision, enforce, enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
            (org["id"], args.slug, args.name[:120], args.protocol, args.issuer, args.client_id,
             Cipher(s.data_key).encrypt(secret), ",".join(domains), args.default_role, int(args.auto_provision),
             int(args.enforce)))
    print(f"Added {args.slug}. Register this redirect URI with the IdP: {s.public_base_url}/sso/callback")
    return 0


if __name__ == "__main__":
    sys.exit(main())
