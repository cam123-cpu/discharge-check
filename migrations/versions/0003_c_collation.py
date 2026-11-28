"""Compare timestamp text byte by byte on Postgres.

Sessions expire and login attempts age out by comparing ISO timestamps as
text. Under a locale collation (for example ICU en-US) that order can differ
from plain byte order, so these columns use "C" on Postgres. SQLite already
compares bytes; nothing changes there.

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-28
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

COLUMNS = [("sessions", "expires_at"), ("sessions", "last_seen"), ("login_attempts", "at")]


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for table, column in COLUMNS:
        op.alter_column(table, column, type_=sa.Text(collation="C"), existing_nullable=False)


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for table, column in COLUMNS:
        op.alter_column(table, column, type_=sa.Text(), existing_nullable=False)
