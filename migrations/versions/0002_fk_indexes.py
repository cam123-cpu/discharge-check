"""Index the foreign keys that cascading deletes look up.

Postgres does not index foreign keys on its own, so deleting a user or an
analysis would scan every session or finding without these.

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-28
"""
from __future__ import annotations

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index("idx_sessions_user", "sessions", ["user_id"])
    op.create_index("idx_findings_analysis", "findings", ["analysis_id"])


def downgrade() -> None:
    op.drop_index("idx_findings_analysis", table_name="findings")
    op.drop_index("idx_sessions_user", table_name="sessions")
