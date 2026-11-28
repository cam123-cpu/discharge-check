"""Storage on Postgres or SQLite through SQLAlchemy.

Every query is parameterized, and every read of patient data goes through a
helper that requires the caller's org_id, so one organization can never read
another's records (row-level isolation). Clinical text is encrypted by the
app before it is written.

The schema lives in `app/models.py` and changes only through Alembic
migrations (`migrations/`), which `Database` applies on start.

`Database.connect()` yields one transaction. Its `execute(sql, params)` takes
SQL with `?` placeholders and works the same on both databases (it rewrites
placeholders for Postgres and fills `lastrowid` from `RETURNING id`), so code
written against the original SQLite layer keeps working unchanged.
"""
from __future__ import annotations

import os
import re
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

from sqlalchemy import create_engine, event, func, inspect, select
from sqlalchemy.engine import URL, Connection, Engine, make_url
from sqlalchemy.pool import NullPool

from . import models as m

ROOT = Path(__file__).resolve().parent.parent
MIGRATIONS_DIR = ROOT / "migrations"
BASELINE_REVISION = "0001"  # the schema the pre-Alembic SQLite code created

# Columns the pre-Alembic code added to older SQLite files on start. A legacy
# file gets these before it is stamped at the baseline revision.
_LEGACY_COLUMNS = [
    ("sessions", "last_seen", "ALTER TABLE sessions ADD COLUMN last_seen TEXT NOT NULL DEFAULT ''"),
    ("documents", "deleted_at", "ALTER TABLE documents ADD COLUMN deleted_at TEXT"),
    ("documents", "deleted_by", "ALTER TABLE documents ADD COLUMN deleted_by INTEGER REFERENCES users(id)"),
]

# Migrations on Postgres hold this advisory lock, so several app processes
# starting at once apply them one at a time instead of racing.
_MIGRATION_LOCK_ID = 7_310_442_118


def utcnow_text() -> str:
    """The format SQLite's datetime('now') returns, for values the app writes."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def normalize_url(url: str | Path) -> URL:
    """A SQLAlchemy URL from DATABASE_URL or a SQLite file path. Plain
    `postgres://` and `postgresql://` URLs (as hosting providers hand them
    out) use the psycopg 3 driver."""
    if isinstance(url, Path):
        return URL.create("sqlite", database=str(url))
    u = make_url(url)
    if u.drivername in ("postgres", "postgresql"):
        u = u.set(drivername="postgresql+psycopg")
    if u.get_backend_name() == "postgresql" and "sslmode" not in u.query and not _local_host(u.host):
        # psycopg's default ("prefer") silently falls back to plaintext; PHI in
        # transit must be encrypted (HIPAA 164.312(e)). Opt out explicitly with
        # sslmode=disable, or use verify-full with the provider's CA.
        u = u.update_query_dict({"sslmode": "require"})
    return u


def _local_host(host: str | None) -> bool:
    return not host or host in ("localhost", "127.0.0.1", "::1") or host.startswith("/")


def redact(url: URL) -> str:
    return url.render_as_string(hide_password=True)


class Record:
    """A result row readable by column name or position, like sqlite3.Row."""
    __slots__ = ("_keys", "_values", "_index")

    def __init__(self, keys: Sequence[str], values: Sequence[Any]):
        self._keys = tuple(keys)
        self._values = tuple(bytes(v) if isinstance(v, memoryview) else v for v in values)
        self._index = {k: i for i, k in enumerate(self._keys)}

    def __getitem__(self, key):
        if isinstance(key, str):
            return self._values[self._index[key]]
        return self._values[key]

    def __getattr__(self, name):
        try:
            return self._values[self._index[name]]
        except KeyError:
            raise AttributeError(name) from None

    def __contains__(self, key) -> bool:
        return key in self._index

    def get(self, key, default=None):
        i = self._index.get(key)
        return default if i is None else self._values[i]

    def keys(self) -> list[str]:
        return list(self._keys)

    def __iter__(self):
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __hash__(self) -> int:
        return hash(self._values)

    def __eq__(self, other) -> bool:
        if isinstance(other, Record):
            return self._values == other._values
        return self._values == tuple(other) if isinstance(other, (tuple, list)) else NotImplemented

    def __repr__(self) -> str:
        return f"Record({dict(zip(self._keys, self._values))!r})"


class Result:
    def __init__(self, keys: Sequence[str], rows: list[Sequence[Any]], rowcount: int, lastrowid: int | None):
        self._keys = list(keys)
        self._rows = rows
        self._pos = 0
        self.rowcount = rowcount
        self.lastrowid = lastrowid

    def fetchone(self) -> Record | None:
        if self._pos >= len(self._rows):
            return None
        row = self._rows[self._pos]
        self._pos += 1
        return Record(self._keys, row)

    def fetchall(self) -> list[Record]:
        out = [Record(self._keys, r) for r in self._rows[self._pos:]]
        self._pos = len(self._rows)
        return out

    def __iter__(self):
        return iter(self.fetchall())


_INSERT_TABLE = re.compile(r"^\s*INSERT\s+(?:OR\s+\w+\s+)?INTO\s+\"?(\w+)\"?", re.IGNORECASE)
_HAS_RETURNING = re.compile(r"\bRETURNING\b", re.IGNORECASE)
_TABLES_WITH_ID = {t.name for t in m.metadata.tables.values() if "id" in t.c}


def qmark_to_format(sql: str) -> str:
    """Rewrite `?` placeholders as `%s` for psycopg, leaving `?` inside quoted
    strings, quoted identifiers and comments alone, and escaping literal `%`."""
    out: list[str] = []
    i, n = 0, len(sql)
    while i < n:
        c = sql[i]
        if c in ("'", '"'):
            j = i + 1
            while j < n:
                if sql[j] == c:
                    if j + 1 < n and sql[j + 1] == c:  # doubled quote inside the literal
                        j += 2
                        continue
                    break
                j += 1
            out.append(sql[i:j + 1].replace("%", "%%"))
            i = j + 1
        elif c == "-" and sql.startswith("--", i):
            j = sql.find("\n", i)
            j = n if j == -1 else j
            out.append(sql[i:j].replace("%", "%%"))
            i = j
        elif c == "/" and sql.startswith("/*", i):
            j = sql.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append(sql[i:j].replace("%", "%%"))
            i = j
        elif c == "?":
            out.append("%s")
            i += 1
        elif c == "%":
            out.append("%%")
            i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


class DBConnection:
    """One transaction. `execute` takes `?`-style SQL on every database; the
    SQLAlchemy connection is available as `.sa` for Core queries."""

    def __init__(self, sa: Connection):
        self.sa = sa
        self.dialect = sa.dialect.name

    def _sql(self, sql: str) -> str:
        return qmark_to_format(sql) if self.dialect == "postgresql" else sql

    def execute(self, sql: str, params: Sequence[Any] | None = None) -> Result:
        params = tuple(params or ())
        lastrowid = None
        want_id = False
        ins = _INSERT_TABLE.match(sql)
        if self.dialect == "postgresql" and ins and ins.group(1).lower() in _TABLES_WITH_ID and not _HAS_RETURNING.search(sql):
            sql = sql.rstrip().rstrip(";") + "\nRETURNING id"  # newline: ends any trailing -- comment
            want_id = True
        res = self.sa.exec_driver_sql(self._sql(sql), params)
        if res.returns_rows:
            keys = list(res.keys())
            rows = [tuple(r) for r in res.fetchall()]
        else:
            keys, rows = [], []
        if want_id:
            lastrowid = rows[0][0] if rows else None  # e.g. ON CONFLICT DO NOTHING skipped the row
            keys, rows = [], []
        elif ins and self.dialect == "sqlite":
            lastrowid = res.lastrowid
        return Result(keys, rows, res.rowcount, lastrowid)

    def executemany(self, sql: str, seq: Iterable[Sequence[Any]]) -> Result:
        batch = [tuple(p) for p in seq]
        if not batch:
            return Result([], [], 0, None)
        res = self.sa.exec_driver_sql(self._sql(sql), batch)
        return Result([], [], res.rowcount, None)


def _sqlite_file(url: URL) -> Path | None:
    db = url.database
    if url.get_backend_name() != "sqlite" or not db or db == ":memory:" or db.startswith("file:"):
        return None
    return Path(db)


# Indexes the pre-Alembic code created with IF NOT EXISTS on every start. Files
# from the first release lack some of them.
_LEGACY_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_login_attempts_key ON login_attempts(key, at)",
    "CREATE INDEX IF NOT EXISTS idx_patients_org ON patients(org_id)",
    "CREATE INDEX IF NOT EXISTS idx_documents_patient ON documents(org_id, patient_id)",
    "CREATE INDEX IF NOT EXISTS idx_analyses_patient ON analyses(org_id, patient_id)",
    "CREATE INDEX IF NOT EXISTS idx_findings_org ON findings(org_id, rule_id)",
    "CREATE INDEX IF NOT EXISTS idx_analyses_latest ON analyses(org_id, patient_id, id)",
    "CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_log(org_id, id)",
]


def adopt_legacy_sqlite(conn: Connection) -> bool:
    """Bring a database made by the pre-Alembic code to the baseline schema and
    record it as revision 0001, so Alembic runs only later migrations on it.
    Runs inside the caller's transaction; does nothing on any other database.
    Never run `alembic revision --autogenerate` against an adopted file: its
    constraints are unnamed, so the diff would be noise. Use a fresh one."""
    if conn.dialect.name != "sqlite":
        return False
    tables = set(inspect(conn).get_table_names())
    if "alembic_version" in tables or "orgs" not in tables:
        return False
    for table, column, ddl in _LEGACY_COLUMNS:
        cols = {c["name"] for c in inspect(conn).get_columns(table)} if table in tables else set()
        if cols and column not in cols:
            conn.exec_driver_sql(ddl)
    for ddl in _LEGACY_INDEXES:
        conn.exec_driver_sql(ddl)
    conn.exec_driver_sql("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL, "
                         "CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num))")
    conn.exec_driver_sql("INSERT INTO alembic_version (version_num) VALUES (?)"
                         if conn.dialect.name == "sqlite" else "INSERT INTO alembic_version (version_num) VALUES (%s)",
                         (BASELINE_REVISION,))
    return True


def sqlite_fk_off(conn: Connection) -> None:
    """Turn SQLite foreign keys off on this connection, outside any transaction.
    Batch migrations rebuild a table by dropping it, which would otherwise
    cascade-delete its child rows."""
    conn.connection.dbapi_connection.execute("PRAGMA foreign_keys = OFF")


def sqlite_fk_on(conn: Connection) -> None:
    conn.connection.dbapi_connection.execute("PRAGMA foreign_keys = ON")


def sqlite_fk_check(conn: Connection) -> None:
    """Inside the migration transaction: refuse to commit dangling references."""
    if conn.dialect.name == "sqlite":
        bad = conn.exec_driver_sql("PRAGMA foreign_key_check").fetchall()
        if bad:
            raise RuntimeError(f"Migration left {len(bad)} rows with broken foreign keys; rolled back.")


class Database:
    def __init__(self, url: str | Path, *, migrate: bool = True, echo: bool = False):
        if isinstance(url, str) and "://" not in url:
            url = Path(url)  # a bare file path, including a Windows one such as C:\data\app.db
        self.url = normalize_url(url)
        self.path = _sqlite_file(self.url)  # None on Postgres
        self.engine = self._make_engine(echo)
        if migrate:
            self.migrate()

    # ---- engine ----

    def _make_engine(self, echo: bool) -> Engine:
        if self.url.get_backend_name() == "sqlite":
            if self.path is not None:
                self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                if not self.path.exists():
                    # Create the file owner-only before SQLite opens it: it holds password
                    # hashes, labels and the audit log even though clinical text is encrypted.
                    os.close(os.open(self.path, os.O_CREAT | os.O_WRONLY, 0o600))
            wal = self.path is not None
            # A connection per checkout, as the original code did: SQLite files
            # are cheap to open and this never shares a handle across threads.
            engine = create_engine(self.url, echo=echo, poolclass=NullPool, hide_parameters=True,
                                   connect_args={"timeout": 10, "check_same_thread": False})

            @event.listens_for(engine, "connect")
            def _sqlite_pragmas(dbapi_conn, _record):
                # Let SQLAlchemy own transactions (pysqlite's own handling is off).
                dbapi_conn.isolation_level = None
                cur = dbapi_conn.cursor()
                cur.execute("PRAGMA foreign_keys = ON")
                cur.execute("PRAGMA busy_timeout = 10000")
                if wal:
                    cur.execute("PRAGMA journal_mode = WAL")
                cur.close()

            @event.listens_for(engine, "begin")
            def _sqlite_begin(conn):
                # IMMEDIATE takes the write lock up front. A deferred BEGIN that
                # reads first and writes later fails at once with "database is
                # locked" when another request committed in between, and nearly
                # every request here reads and then writes an audit row.
                conn.exec_driver_sql("BEGIN IMMEDIATE")

            return engine
        connect_args: dict[str, Any] = {"connect_timeout": int(os.environ.get("DATABASE_CONNECT_TIMEOUT", "10"))}
        if os.environ.get("DATABASE_PGBOUNCER", "0") == "1":
            # Transaction-mode poolers (PgBouncer, Supabase/Neon "pooler" URLs)
            # break psycopg's automatic prepared statements.
            connect_args["prepare_threshold"] = None
        return create_engine(
            self.url, echo=echo,
            hide_parameters=True,  # errors and logs never carry patient data or hashes
            pool_pre_ping=True,  # drop connections a proxy or failover closed
            # Sized for uvicorn's default 40 worker threads per process.
            pool_size=int(os.environ.get("DATABASE_POOL_SIZE", "10")),
            max_overflow=int(os.environ.get("DATABASE_MAX_OVERFLOW", "30")),
            pool_timeout=10,
            pool_recycle=1800,
            connect_args=connect_args,
        )

    @contextmanager
    def connect(self) -> Iterator[DBConnection]:
        with self.engine.begin() as sa:
            yield DBConnection(sa)

    def dispose(self) -> None:
        self.engine.dispose()

    # ---- migrations ----

    def alembic_config(self):
        from alembic.config import Config
        cfg = Config()
        cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
        cfg.set_main_option("sqlalchemy.url", self.url.render_as_string(hide_password=False).replace("%", "%%"))
        return cfg

    def migrate(self, revision: str = "head") -> None:
        """Bring the schema to `revision`. A SQLite file made before Alembic is
        adopted first: it gets the columns the old code added, then is stamped
        at the baseline so only later migrations run on it."""
        cfg = self.alembic_config()
        with self.engine.connect() as outer:
            sqlite = outer.dialect.name == "sqlite"
            if sqlite:
                sqlite_fk_off(outer)  # the pragma only changes outside a transaction
            try:
                self._migrate(outer, cfg, revision)
            finally:
                if sqlite:
                    sqlite_fk_on(outer)

    def _migrate(self, outer: Connection, cfg, revision: str) -> None:
        from alembic import command

        with outer.begin():
            conn = outer
            if conn.dialect.name == "postgresql":
                conn.exec_driver_sql(f"SELECT pg_advisory_xact_lock({_MIGRATION_LOCK_ID})")
            cfg.attributes["connection"] = conn
            adopt_legacy_sqlite(conn)
            command.upgrade(cfg, revision)
            sqlite_fk_check(conn)

    def current_revision(self) -> str | None:
        from alembic.runtime.migration import MigrationContext
        with self.engine.connect() as conn:
            return MigrationContext.configure(conn).get_current_revision()

    # ---- org-scoped helpers: the only way routes read patient data ----

    @staticmethod
    def _one(conn: DBConnection, stmt) -> Record | None:
        res = conn.sa.execute(stmt)
        row = res.fetchone()
        return None if row is None else Record(list(res.keys()), tuple(row))

    @staticmethod
    def _all(conn: DBConnection, stmt) -> list[Record]:
        res = conn.sa.execute(stmt)
        keys = list(res.keys())
        return [Record(keys, tuple(r)) for r in res.fetchall()]

    def patient(self, conn: DBConnection, org_id: int, patient_id: int):
        p = m.patients
        return self._one(conn, select(p).where(p.c.id == patient_id, p.c.org_id == org_id))

    def patients(self, conn: DBConnection, org_id: int):
        p, a, d = m.patients, m.analyses, m.documents

        def latest(col):
            return (select(col).where(a.c.patient_id == p.c.id, a.c.org_id == p.c.org_id)
                    .order_by(a.c.id.desc()).limit(1).scalar_subquery())

        doc_count = (select(func.count()).select_from(d)
                     .where(d.c.patient_id == p.c.id, d.c.org_id == p.c.org_id, d.c.deleted_at.is_(None))
                     .scalar_subquery())
        stmt = (select(p, latest(a.c.failed).label("last_failed"), latest(a.c.unclear).label("last_unclear"),
                       latest(a.c.passed).label("last_passed"), doc_count.label("doc_count"))
                .where(p.c.org_id == org_id)
                .order_by(p.c.discharge_date.desc(), p.c.id.desc()))
        return self._all(conn, stmt)

    def documents(self, conn: DBConnection, org_id: int, patient_id: int):
        d = m.documents
        return self._all(conn, select(d).where(d.c.org_id == org_id, d.c.patient_id == patient_id,
                                               d.c.deleted_at.is_(None)).order_by(d.c.id))

    def document(self, conn: DBConnection, org_id: int, patient_id: int, doc_id: int):
        d = m.documents
        return self._one(conn, select(d).where(d.c.id == doc_id, d.c.patient_id == patient_id,
                                               d.c.org_id == org_id, d.c.deleted_at.is_(None)))

    def latest_analysis(self, conn: DBConnection, org_id: int, patient_id: int):
        a = m.analyses
        return self._one(conn, select(a).where(a.c.org_id == org_id, a.c.patient_id == patient_id)
                         .order_by(a.c.id.desc()).limit(1))

    def audit(self, conn: DBConnection, org_id, user_id, action: str, target: str = "", ip: str = ""):
        conn.sa.execute(m.audit_log.insert().values(org_id=org_id, user_id=user_id, action=action,
                                                    target=target, ip=ip))


__all__ = ["Database", "DBConnection", "Record", "normalize_url", "qmark_to_format", "redact", "utcnow_text"]
