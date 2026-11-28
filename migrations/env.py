"""Alembic environment. The app passes its own connection in
`config.attributes["connection"]`; the `alembic` command line builds one from
DATABASE_URL (or DATABASE_PATH) instead."""
from __future__ import annotations

import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.models import metadata  # noqa: E402

config = context.config
if config.config_file_name is not None and config.attributes.get("connection") is None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)


def _include_object(obj, name, type_, reflected, compare_to):
    # Tables that other parts of the system own (none yet) are left alone.
    return True


def _configure(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=metadata,
        render_as_batch=connection.dialect.name == "sqlite",  # SQLite needs table rebuilds to alter
        compare_type=True,
        compare_server_default=True,
        include_object=_include_object,
    )


def run_migrations_offline() -> None:
    from app.config import database_target
    from app.db import normalize_url
    context.configure(url=normalize_url(database_target()), target_metadata=metadata,
                      literal_binds=True, dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        _configure(connection)
        with context.begin_transaction():
            context.run_migrations()
        return
    # The `alembic` command line: same safeguards as Database.migrate (one
    # Postgres advisory lock, SQLite foreign keys off for batch rebuilds,
    # adoption of pre-Alembic SQLite files).
    from app.config import database_target
    from app.db import (_MIGRATION_LOCK_ID, Database, adopt_legacy_sqlite, set_rls_context, sqlite_fk_check,
                        sqlite_fk_off, sqlite_fk_on)
    db = Database(database_target(), migrate=False)
    try:
        with db.engine.connect() as conn:
            sqlite = conn.dialect.name == "sqlite"
            if sqlite:
                sqlite_fk_off(conn)
            try:
                with conn.begin():
                    if conn.dialect.name == "postgresql":
                        conn.exec_driver_sql(f"SELECT pg_advisory_xact_lock({_MIGRATION_LOCK_ID})")
                    set_rls_context(conn, None)
                    adopt_legacy_sqlite(conn)
                    _configure(conn)
                    with context.begin_transaction():
                        context.run_migrations()
                    sqlite_fk_check(conn)
            finally:
                if sqlite:
                    sqlite_fk_on(conn)
    finally:
        db.dispose()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
