"""Re-encrypts stored clinical text with the current DATA_KEY.

Rotation steps (see docs/key-rotation.md):
  1. Generate a new key, move the old one into DATA_KEY_PREVIOUS, put the new
     one in DATA_KEY, and restart the app. It reads old and new rows from then on.
  2. Run `python -m scripts.rotate_data_key`. It re-encrypts every row that only
     an old key can read, in batches, and records the result in the access log.
  3. Run `python -m scripts.rotate_data_key --check`. When it reports 0 rows
     left, remove the old key from DATA_KEY_PREVIOUS and restart.

Safe to stop and run again: rows already on the current key are skipped.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.config import Settings, load_settings  # noqa: E402
from app.db import Database  # noqa: E402
from app.security import Cipher  # noqa: E402

# Every encrypted column in the database: (table, column).
ENCRYPTED = (("documents", "body_enc"), ("analyses", "result_enc"))
BATCH = 500


def pending(db: Database, cipher: Cipher) -> dict[str, int]:
    """How many rows per table still need the current key."""
    out = {}
    with db.connect() as conn:
        for table, col in ENCRYPTED:
            rows = conn.execute(f"SELECT {col} FROM {table}")  # nosec B608 - names from the constant ENCRYPTED
            out[table] = sum(1 for (blob,) in rows if not cipher.is_current(blob))
    return out


def rotate(settings: Settings) -> dict[str, int]:
    db = Database(settings.database_path, settings.audit_keyring())
    cipher = Cipher(settings.data_key, settings.data_key_previous)
    done = {}
    for table, col in ENCRYPTED:
        done[table], last_id = 0, 0
        while True:
            # One short transaction per batch so the app keeps working meanwhile.
            with db.connect() as conn:
                rows = conn.execute(f"SELECT id, {col} FROM {table} WHERE id > ? ORDER BY id LIMIT ?",  # nosec B608
                                    (last_id, BATCH)).fetchall()
                if not rows:
                    break
                for row_id, blob in rows:
                    if not cipher.is_current(blob):
                        conn.execute(f"UPDATE {table} SET {col} = ? WHERE id = ?",  # nosec B608
                                     (cipher.rotate(blob), row_id))
                        done[table] += 1
                last_id = rows[-1][0]
    with db.connect() as conn:
        db.audit(conn, None, None, "data_key_rotated", ",".join(f"{t}:{n}" for t, n in done.items()))
    return done


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Re-encrypt stored records with the current DATA_KEY.")
    parser.add_argument("--check", action="store_true", help="only report how many rows still need the current key")
    args = parser.parse_args(argv)
    settings = load_settings()
    if not settings.database_path.is_file():
        print(f"No database at {settings.database_path}", file=sys.stderr)
        return 1
    if args.check:
        left = pending(Database(settings.database_path), Cipher(settings.data_key, settings.data_key_previous))
        print("Rows still on an old key: " + ", ".join(f"{t} {n}" for t, n in left.items()))
        return 0 if not any(left.values()) else 1
    done = rotate(settings)
    print("Re-encrypted with the current key: " + ", ".join(f"{t} {n}" for t, n in done.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
