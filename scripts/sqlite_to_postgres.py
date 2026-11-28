"""Copy every row of a SQLite database file into an empty Postgres database.

Usage (any OS, from the repository folder, with the virtual environment active):
    python -m scripts.sqlite_to_postgres --from data/app.db --to postgresql://user:pw@host/db
    python -m scripts.sqlite_to_postgres --dry-run         # counts only, writes nothing

--from defaults to DATABASE_PATH (data/app.db), --to to DATABASE_URL.

The copy is byte-for-byte: encrypted columns are moved as stored and never
decrypted, so the app on Postgres must keep the same DATA_KEY (and the same
SESSION_PEPPER, or everyone signs in again). Primary keys are preserved, and
the Postgres id sequences are moved past the copied rows.

Stop the app before copying, so nothing writes to the SQLite file meanwhile.
Row contents are never printed, and passwords in URLs are masked.
"""
from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from alembic.util import CommandError
from sqlalchemy import Table, func, inspect, select
from sqlalchemy.engine import URL
from sqlalchemy.exc import ArgumentError, DBAPIError, SQLAlchemyError

from app import models as m
from app.config import sqlite_path
from app.db import Database, normalize_url, redact, set_rls_context

DEFAULT_BATCH = 1000
KEY_NOTE = ("Encrypted columns are copied byte-for-byte and never decrypted: run the app on "
            "Postgres with the same DATA_KEY (and SESSION_PEPPER) as the SQLite install.")


class CopyError(Exception):
    """A failure whose message is safe to print (no row contents, no secrets)."""


@dataclass
class Report:
    source_counts: dict[str, int] = field(default_factory=dict)
    target_counts: dict[str, int | None] = field(default_factory=dict)
    sequences: dict[str, int | None] = field(default_factory=dict)  # table -> next id


def tables() -> list[Table]:
    """Every app table, parents before children, so foreign keys hold at each insert."""
    return list(m.metadata.sorted_tables)


def _id_column(t: Table):
    return t.c.id if "id" in t.c and t.c.id.primary_key else None


def _count(conn, t: Table) -> int:
    return conn.execute(select(func.count()).select_from(t)).scalar_one()


def _counts(conn, only_existing: bool = False) -> dict[str, int | None]:
    present = set(inspect(conn).get_table_names()) if only_existing else None
    return {t.name: (None if present is not None and t.name not in present else _count(conn, t)) for t in tables()}


def _safe_error(exc: BaseException, where: str = "") -> CopyError:
    """Describe a database error without its SQL parameters or DETAIL line,
    either of which can hold row contents."""
    where = f" while copying {where}" if where else ""
    if isinstance(exc, DBAPIError) and exc.orig is not None:
        orig = exc.orig
        state = getattr(orig, "sqlstate", None) or getattr(getattr(orig, "diag", None), "sqlstate", None)
        kind = type(orig).__name__
        if not where and kind in ("OperationalError", "InterfaceError"):
            # Connection failures: the driver's first line names host and user, never the password.
            first = str(orig).strip().splitlines()[0] if str(orig).strip() else kind
            return CopyError(f"Database error ({kind}){where}: {first}")
        return CopyError(f"Database error ({kind}{', SQLSTATE ' + state if state else ''}){where}. "
                         "Row contents are not shown. Nothing was written to the target.")
    return CopyError(f"Database error ({type(exc).__name__}){where}. Nothing was written to the target.")


def _source_path(value: str | None) -> Path:
    path = Path(value) if value else sqlite_path()
    if not path.is_absolute():
        path = Path.cwd() / path
    if not path.is_file():
        # Database() would create an empty file here; refuse instead.
        raise CopyError(f"Source SQLite file not found: {path}")
    return path


def _target_url(value: str | None) -> URL:
    raw = (value or os.environ.get("DATABASE_URL", "")).strip()
    if not raw:
        raise CopyError("No target: pass --to postgresql://... or set DATABASE_URL.")
    try:
        url = normalize_url(raw)
    except (ArgumentError, ValueError):
        raise CopyError("--to is not a valid database URL.") from None
    if url.get_backend_name() != "postgresql":
        raise CopyError(f"The target must be a Postgres URL, got {redact(url)}")
    return url


def _print_table(report: Report, dry_run: bool) -> None:
    head = ("table", "sqlite rows", "target rows" if dry_run else "postgres rows", "")
    rows = []
    for t in tables():
        src = report.source_counts.get(t.name)
        dst = report.target_counts.get(t.name)
        if dry_run:
            status = "" if dst in (None, 0) else "NOT EMPTY"
        else:
            status = "ok" if src == dst else "MISMATCH"
        rows.append((t.name, "-" if src is None else str(src), "-" if dst is None else str(dst), status))
    widths = [max(len(r[i]) for r in [head, *rows]) for i in range(4)]
    line = lambda r: "  ".join(c.ljust(w) if i == 0 else c.rjust(w) for i, (c, w) in enumerate(zip(r, widths)))
    print(line(head).rstrip())
    print("  ".join("-" * w for w in widths if w))
    for r in rows:
        print(line(r).rstrip())


def _check_revisions(source: Database, target: Database) -> str:
    from alembic.script import ScriptDirectory
    head = ScriptDirectory.from_config(source.alembic_config()).get_current_head()
    src, dst = source.current_revision(), target.current_revision()
    if src != dst or src != head:
        raise CopyError(f"Schema revisions differ (sqlite {src}, postgres {dst}, code {head}). "
                        "Both must be at the same Alembic revision.")
    return src


def _copy(source: Database, target: Database, batch: int, report: Report, log=print) -> None:
    names = [t.name for t in tables()]
    # One read transaction on the source (a consistent snapshot) and one write
    # transaction on the target: either every table is copied or none is.
    with source.engine.connect() as src, target.engine.begin() as dst:
        set_rls_context(dst, None)  # the copy writes every organization's rows
        # Block other writers on the target until the copy commits.
        dst.exec_driver_sql("LOCK TABLE " + ", ".join(f'"{n}"' for n in names) + " IN EXCLUSIVE MODE")
        busy = [n for n, c in _counts(dst).items() if c]
        if busy:
            raise CopyError("The target database is not empty (rows in: " + ", ".join(busy) + "). "
                            "Refusing to copy into it; point --to at a new, empty database.")
        for t in tables():
            report.source_counts[t.name] = _count(src, t)
        for t in tables():
            copied = 0
            stmt = select(t).order_by(*t.primary_key.columns).execution_options(yield_per=batch)
            try:
                result = src.execute(stmt)
                for part in result.mappings().partitions(batch):
                    rows = [dict(r) for r in part]
                    for row in rows:  # drivers may hand blobs back as memoryview
                        for k, v in row.items():
                            if isinstance(v, memoryview):
                                row[k] = bytes(v)
                    dst.execute(t.insert(), rows)
                    copied += len(rows)
            except SQLAlchemyError as exc:
                raise _safe_error(exc, t.name) from None
            if copied != report.source_counts[t.name]:
                raise CopyError(f"{t.name}: read {copied} rows, expected {report.source_counts[t.name]}. Nothing was written.")
            log(f"  {t.name}: {copied} rows")
        for t in tables():
            col = _id_column(t)
            if col is None:
                continue
            seq = dst.exec_driver_sql("SELECT pg_get_serial_sequence(%s, 'id')", (f'"{t.name}"',)).scalar()
            if seq is None:
                report.sequences[t.name] = None
                continue
            top = dst.execute(select(func.max(col))).scalar()
            if top is None:
                dst.exec_driver_sql("SELECT setval(%s, 1, false)", (seq,))
                report.sequences[t.name] = 1
            else:
                dst.exec_driver_sql("SELECT setval(%s, %s, true)", (seq, int(top)))
                report.sequences[t.name] = int(top) + 1


def run(source_path: Path, target_url: URL, *, batch: int = DEFAULT_BATCH, dry_run: bool = False, log=print) -> Report:
    """Copy (or with dry_run, only count). Raises CopyError with a printable
    message on refusal or failure."""
    if batch < 1:
        raise CopyError("--batch-size must be at least 1.")
    report = Report()
    log(f"Source: {source_path}")
    log(f"Target: {redact(target_url)}")
    log(KEY_NOTE)
    source = target = None
    try:
        try:
            # A dry run applies no migrations to either side.
            source = Database(source_path, migrate=not dry_run)
            target = Database(target_url, migrate=not dry_run)
        except SQLAlchemyError as exc:
            raise _safe_error(exc) from None
        except CommandError as exc:
            raise CopyError(f"Migration failed: {exc}") from None
        try:
            if dry_run:
                with source.engine.connect() as c:
                    report.source_counts = _counts(c, only_existing=True)
                with target.engine.connect() as c:
                    set_rls_context(c, None)
                    report.target_counts = _counts(c, only_existing=True)
                log(f"Revisions: sqlite {source.current_revision() or 'none (legacy or empty)'}, "
                    f"postgres {target.current_revision() or 'none (schema not created yet)'}")
                log("")
                _print_table(report, dry_run=True)
                busy = [n for n, c in report.target_counts.items() if c]
                log("")
                log("Dry run: nothing was migrated or written. "
                    + ("The target is NOT empty, so a real copy would be refused." if busy
                       else "The target is empty; a real copy would proceed."))
                return report
            rev = _check_revisions(source, target)
            log(f"Both databases are at revision {rev}. Copying in batches of {batch}...")
            _copy(source, target, batch, report, log)
            with target.engine.connect() as c:
                set_rls_context(c, None)
                report.target_counts = _counts(c)
        except SQLAlchemyError as exc:
            raise _safe_error(exc) from None
    finally:
        for db in (source, target):
            if db is not None:
                db.dispose()
    log("")
    _print_table(report, dry_run=False)
    bad = [t for t, n in report.source_counts.items() if report.target_counts.get(t) != n]
    if bad:
        raise CopyError("Row counts differ after the copy for: " + ", ".join(bad))
    log("")
    log("Done. Every row count matches; id sequences were moved past the copied rows.")
    log("Set DATABASE_URL to the target and start the app with the SAME DATA_KEY.")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m scripts.sqlite_to_postgres",
        description="Copy every row of the app's SQLite file into an empty Postgres database, "
                    "in one transaction, keeping ids and encrypted data byte-for-byte. " + KEY_NOTE
                    + " Stop the app first.",
    )
    parser.add_argument("--from", dest="source", metavar="PATH",
                        help="SQLite file to copy (default: DATABASE_PATH, i.e. data/app.db). "
                             "It is migrated to the current schema first.")
    parser.add_argument("--to", dest="target", metavar="URL",
                        help="Postgres URL, e.g. postgresql://user:password@host/dbname (default: DATABASE_URL). "
                             "The database must be empty.")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH, metavar="N",
                        help=f"rows per insert batch (default {DEFAULT_BATCH})")
    parser.add_argument("--dry-run", action="store_true",
                        help="only print row counts of both sides; migrate and write nothing")
    args = parser.parse_args(argv)
    try:
        run(_source_path(args.source), _target_url(args.target), batch=args.batch_size, dry_run=args.dry_run)
    except CopyError as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
