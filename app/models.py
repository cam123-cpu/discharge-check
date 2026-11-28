"""The schema, defined once with SQLAlchemy and shared by the app and by the
Alembic migrations in `migrations/`. It runs on Postgres (deployments) and on
SQLite (local development and tests).

Timestamps stay as UTC text ("YYYY-MM-DD HH:MM:SS" for server defaults, ISO
8601 for values the app writes) so both databases sort and compare them the
same way the original SQLite schema did. Clinical text is encrypted by the app
before it reaches any column (`*_enc`), so the database never sees plaintext.
"""
from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Column,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    Table,
    Text,
    text,
)
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.sql.expression import FunctionElement

# Stable constraint names, so Alembic can alter them later on either database.
metadata = MetaData(naming_convention={
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
})


class utcnow_text(FunctionElement):
    """Current UTC time as 'YYYY-MM-DD HH:MM:SS' text, matching SQLite's
    datetime('now'), for use as a server default on either database."""
    type = Text()
    inherit_cache = True


@compiles(utcnow_text)
def _utcnow_sqlite(element, compiler, **kw):
    return "(datetime('now'))"


@compiles(utcnow_text, "postgresql")
def _utcnow_pg(element, compiler, **kw):
    return "(to_char(timezone('utc', now()), 'YYYY-MM-DD HH24:MI:SS'))"


def _now_default():
    return utcnow_text()


# Tables that grow without bound get 64-bit ids on Postgres. SQLite must keep
# INTEGER so the column stays an alias of its rowid (and autoincrements).
BigId = BigInteger().with_variant(Integer(), "sqlite")

# Text the app compares with < and > (ISO timestamps). On Postgres it uses the
# byte-order "C" collation, so ordering matches SQLite's and never depends on
# the server's locale (ICU locales ignore punctuation such as "+" and ".").
SortableText = Text().with_variant(Text(collation="C"), "postgresql")

ROLES = ("physician", "nurse", "case_manager", "compliance", "admin")
STATUSES = ("pass", "fail", "unclear", "not_applicable")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


orgs = Table(
    "orgs", metadata,
    Column("id", Integer, primary_key=True),
    Column("name", Text, nullable=False),
)

users = Table(
    "users", metadata,
    Column("id", Integer, primary_key=True),
    Column("org_id", Integer, ForeignKey("orgs.id"), nullable=False),
    Column("email", Text, nullable=False, unique=True),
    Column("display_name", Text, nullable=False),
    Column("role", Text, nullable=False),
    Column("password_hash", Text, nullable=False),
    Column("created_at", Text, nullable=False, server_default=_now_default()),
    CheckConstraint(_in("role", ROLES), name="role"),
)

sessions = Table(
    "sessions", metadata,
    Column("token_hash", Text, primary_key=True),
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
    Column("csrf_token", Text, nullable=False),
    Column("expires_at", SortableText, nullable=False),
    Column("last_seen", SortableText, nullable=False, server_default=text("''")),
    Index("idx_sessions_user", "user_id"),
)

login_attempts = Table(
    "login_attempts", metadata,
    Column("id", BigId, primary_key=True),
    Column("key", Text, nullable=False),
    Column("at", SortableText, nullable=False, server_default=_now_default()),
    Index("idx_login_attempts_key", "key", "at"),
)

patients = Table(
    "patients", metadata,
    Column("id", Integer, primary_key=True),
    Column("org_id", Integer, ForeignKey("orgs.id"), nullable=False),
    Column("label", Text, nullable=False),
    Column("unit", Text, nullable=False, server_default=text("''")),
    Column("attending", Text, nullable=False, server_default=text("''")),
    Column("discharge_date", Text, nullable=False, server_default=text("''")),
    Column("disposition", Text, nullable=False, server_default=text("''")),
    Column("created_by", Integer, ForeignKey("users.id")),
    Column("created_at", Text, nullable=False, server_default=_now_default()),
    Index("idx_patients_org", "org_id"),
)

documents = Table(
    "documents", metadata,
    Column("id", Integer, primary_key=True),
    Column("org_id", Integer, ForeignKey("orgs.id"), nullable=False),
    Column("patient_id", Integer, ForeignKey("patients.id", ondelete="CASCADE"), nullable=False),
    Column("kind", Text, nullable=False),
    Column("filename", Text, nullable=False),
    Column("author", Text, nullable=False, server_default=text("''")),
    Column("body_enc", LargeBinary, nullable=False),
    Column("uploaded_by", Integer, ForeignKey("users.id")),
    Column("created_at", Text, nullable=False, server_default=_now_default()),
    Column("deleted_at", Text),
    Column("deleted_by", Integer, ForeignKey("users.id")),
    Index("idx_documents_patient", "org_id", "patient_id"),
)

analyses = Table(
    "analyses", metadata,
    Column("id", Integer, primary_key=True),
    Column("org_id", Integer, ForeignKey("orgs.id"), nullable=False),
    Column("patient_id", Integer, ForeignKey("patients.id", ondelete="CASCADE"), nullable=False),
    Column("engine", Text, nullable=False),
    Column("result_enc", LargeBinary, nullable=False),
    Column("passed", Integer, nullable=False),
    Column("failed", Integer, nullable=False),
    Column("unclear", Integer, nullable=False),
    Column("created_by", Integer, ForeignKey("users.id")),
    Column("created_at", Text, nullable=False, server_default=_now_default()),
    Index("idx_analyses_patient", "org_id", "patient_id"),
    Index("idx_analyses_latest", "org_id", "patient_id", "id"),
)

findings = Table(
    "findings", metadata,
    Column("id", BigId, primary_key=True),
    Column("org_id", Integer, ForeignKey("orgs.id"), nullable=False),
    Column("analysis_id", Integer, ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
    Column("patient_id", Integer, ForeignKey("patients.id", ondelete="CASCADE"), nullable=False),
    Column("rule_id", Text, nullable=False),
    Column("status", Text, nullable=False),
    CheckConstraint(_in("status", STATUSES), name="status"),
    Index("idx_findings_org", "org_id", "rule_id"),
    Index("idx_findings_analysis", "analysis_id"),
)

audit_log = Table(
    "audit_log", metadata,
    Column("id", BigId, primary_key=True),
    Column("org_id", Integer),
    Column("user_id", Integer),
    Column("action", Text, nullable=False),
    Column("target", Text, nullable=False, server_default=text("''")),
    Column("ip", Text, nullable=False, server_default=text("''")),
    Column("at", Text, nullable=False, server_default=_now_default()),
    Index("idx_audit_org", "org_id", "id"),
)
