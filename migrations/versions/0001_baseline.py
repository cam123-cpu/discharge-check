"""Baseline: the schema the original SQLite code created.

A SQLite file made before Alembic is stamped at this revision instead of
running it (see Database.migrate), so it must stay exactly that schema.

Revision ID: 0001
Revises:
Create Date: 2026-11-28
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from app.models import BigId, ROLES, STATUSES, utcnow_text

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def _in(column, values):
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


def _now():
    return utcnow_text()


def _blank():
    return sa.text("''")


def upgrade() -> None:
    op.create_table(
        "orgs",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.Text, nullable=False),
    )
    op.create_table(
        "users",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("org_id", sa.Integer, sa.ForeignKey("orgs.id"), nullable=False),
        sa.Column("email", sa.Text, nullable=False, unique=True),
        sa.Column("display_name", sa.Text, nullable=False),
        sa.Column("role", sa.Text, nullable=False),
        sa.Column("password_hash", sa.Text, nullable=False),
        sa.Column("created_at", sa.Text, nullable=False, server_default=_now()),
        sa.CheckConstraint(_in("role", ROLES), name="role"),
    )
    op.create_table(
        "sessions",
        sa.Column("token_hash", sa.Text, primary_key=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("csrf_token", sa.Text, nullable=False),
        sa.Column("expires_at", sa.Text, nullable=False),
        sa.Column("last_seen", sa.Text, nullable=False, server_default=_blank()),
    )
    op.create_table(
        "login_attempts",
        sa.Column("id", BigId, primary_key=True),
        sa.Column("key", sa.Text, nullable=False),
        sa.Column("at", sa.Text, nullable=False, server_default=_now()),
    )
    op.create_index("idx_login_attempts_key", "login_attempts", ["key", "at"])
    op.create_table(
        "patients",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("org_id", sa.Integer, sa.ForeignKey("orgs.id"), nullable=False),
        sa.Column("label", sa.Text, nullable=False),
        sa.Column("unit", sa.Text, nullable=False, server_default=_blank()),
        sa.Column("attending", sa.Text, nullable=False, server_default=_blank()),
        sa.Column("discharge_date", sa.Text, nullable=False, server_default=_blank()),
        sa.Column("disposition", sa.Text, nullable=False, server_default=_blank()),
        sa.Column("created_by", sa.Integer, sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.Text, nullable=False, server_default=_now()),
    )
    op.create_index("idx_patients_org", "patients", ["org_id"])
    op.create_table(
        "documents",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("org_id", sa.Integer, sa.ForeignKey("orgs.id"), nullable=False),
        sa.Column("patient_id", sa.Integer, sa.ForeignKey("patients.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.Text, nullable=False),
        sa.Column("filename", sa.Text, nullable=False),
        sa.Column("author", sa.Text, nullable=False, server_default=_blank()),
        sa.Column("body_enc", sa.LargeBinary, nullable=False),
        sa.Column("uploaded_by", sa.Integer, sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.Text, nullable=False, server_default=_now()),
        sa.Column("deleted_at", sa.Text),
        sa.Column("deleted_by", sa.Integer, sa.ForeignKey("users.id")),
    )
    op.create_index("idx_documents_patient", "documents", ["org_id", "patient_id"])
    op.create_table(
        "analyses",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("org_id", sa.Integer, sa.ForeignKey("orgs.id"), nullable=False),
        sa.Column("patient_id", sa.Integer, sa.ForeignKey("patients.id", ondelete="CASCADE"), nullable=False),
        sa.Column("engine", sa.Text, nullable=False),
        sa.Column("result_enc", sa.LargeBinary, nullable=False),
        sa.Column("passed", sa.Integer, nullable=False),
        sa.Column("failed", sa.Integer, nullable=False),
        sa.Column("unclear", sa.Integer, nullable=False),
        sa.Column("created_by", sa.Integer, sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.Text, nullable=False, server_default=_now()),
    )
    op.create_index("idx_analyses_patient", "analyses", ["org_id", "patient_id"])
    op.create_index("idx_analyses_latest", "analyses", ["org_id", "patient_id", "id"])
    op.create_table(
        "findings",
        sa.Column("id", BigId, primary_key=True),
        sa.Column("org_id", sa.Integer, sa.ForeignKey("orgs.id"), nullable=False),
        sa.Column("analysis_id", sa.Integer, sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("patient_id", sa.Integer, sa.ForeignKey("patients.id", ondelete="CASCADE"), nullable=False),
        sa.Column("rule_id", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False),
        sa.CheckConstraint(_in("status", STATUSES), name="status"),
    )
    op.create_index("idx_findings_org", "findings", ["org_id", "rule_id"])
    op.create_table(
        "audit_log",
        sa.Column("id", BigId, primary_key=True),
        sa.Column("org_id", sa.Integer),
        sa.Column("user_id", sa.Integer),
        sa.Column("action", sa.Text, nullable=False),
        sa.Column("target", sa.Text, nullable=False, server_default=_blank()),
        sa.Column("ip", sa.Text, nullable=False, server_default=_blank()),
        sa.Column("at", sa.Text, nullable=False, server_default=_now()),
    )
    op.create_index("idx_audit_org", "audit_log", ["org_id", "id"])


def downgrade() -> None:
    for table in ("audit_log", "findings", "analyses", "documents", "patients", "login_attempts", "sessions", "users", "orgs"):
        op.drop_table(table)
