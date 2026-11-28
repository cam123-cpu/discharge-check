"""Row-level security on Postgres: each hospital sees only its own rows.

Every transaction the app opens sets `app.org_id` (one organization) or
`app.rls_bypass = on` (the system: sign-in, session lookup, setup), see
app.db.set_rls_context. With neither set, a query sees nothing and cannot
write, so a forgotten setting fails closed. FORCE applies the policies to the
tables' owner too, which is usually the role the app connects as. Superusers
and BYPASSRLS roles skip all policies; the app warns at start if it has one.

This guards against a query that forgets its org_id filter. It does not stop
SQL injection (injected SQL could change the settings); every query is
parameterized for that. Sessions and login attempts hold no patient data and
are only touched by system transactions, so they have no policy. SQLite has
no row-level security; nothing changes there.

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-28
"""
from __future__ import annotations

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

# table -> the column holding the organization id
TABLES = {
    "orgs": "id",
    "users": "org_id",
    "patients": "org_id",
    "documents": "org_id",
    "analyses": "org_id",
    "findings": "org_id",
    "audit_log": "org_id",
}

RULE = ("current_setting('app.rls_bypass', true) = 'on' "
        "OR {col} = nullif(current_setting('app.org_id', true), '')::integer")


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for table, col in TABLES.items():
        rule = RULE.format(col=col)
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(f"CREATE POLICY org_isolation ON {table} USING ({rule}) WITH CHECK ({rule})")


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for table in TABLES:
        op.execute(f"DROP POLICY IF EXISTS org_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
