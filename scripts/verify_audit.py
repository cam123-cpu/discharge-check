"""Verifies the access log's hash chain.

Usage:
  python -m scripts.verify_audit          check every row; exit 0 if intact, 1 if not
  python -m scripts.verify_audit --head   print the newest row's id and hash as JSON
  python -m scripts.verify_audit --export-key
                                          print the current key as hex:..., to keep in
                                          AUDIT_KEY_PREVIOUS before it changes (a secret)

Ship the --head output on a schedule to a write-once store (for example S3
with Object Lock). The chain alone cannot show that the newest rows were cut
off; comparing against an anchored head can. Opens the database read-only."""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import audit  # noqa: E402
from app.config import load_settings  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify the access log's hash chain.")
    parser.add_argument("--head", action="store_true", help="print the chain head as JSON and exit")
    parser.add_argument("--export-key", action="store_true",
                        help="print the current access-log key as hex:..., for AUDIT_KEY_PREVIOUS (it is a secret)")
    args = parser.parse_args(argv)
    settings = load_settings()
    if args.export_key:
        print(audit.export_key(settings.audit_keyring().current))
        return 0
    if not settings.database_path.is_file():
        print(f"No database at {settings.database_path}", file=sys.stderr)
        return 1
    conn = sqlite3.connect(f"file:{settings.database_path}?mode=ro", uri=True)
    try:
        if args.head:
            print(json.dumps(audit.head(conn)))
            return 0
        result = audit.verify(conn, settings.audit_keyring())
    finally:
        conn.close()
    if result.ok:
        print(f"OK: {result.checked} events verified. Head: id {result.head_id}, {result.head_hash}")
        return 0
    print(f"BROKEN at event {result.broken_id}: {result.reason} ({result.checked} events before it verified)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
