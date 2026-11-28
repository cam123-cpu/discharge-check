"""Tamper-evident access log: an HMAC hash chain over audit_log.

Every row carries prev_hash (the row_hash of the row before it) and
row_hash = HMAC-SHA256(audit_key, canonical(id, at, org_id, user_id, action,
target, ip, prev_hash)). The first row's prev_hash is GENESIS. Changing,
inserting or removing any row breaks the chain from that row on, and nobody
without the key can recompute it.

There is one global chain for the whole database, not one per organization:
it is simpler, and a single head value covers every tenant. Rows are still
filtered by org_id when shown.

Key rotation: every row also records key_id, a short fingerprint of the
key that sealed it (part of the hashed fields). To rotate, move the old key
to AUDIT_KEY_PREVIOUS and set a new AUDIT_KEY. On the next start the app
writes an `audit_key_rotated` row sealed with the new key, and every later
row uses it. Verification looks each row's key up by fingerprint, so old
keys must stay configured for as long as their rows are kept. A key switch
is only accepted on an `audit_key_rotated` row, and a retired key may never
come back, so a leaked old key cannot be used to append forged rows.

Limits: removing the newest N rows leaves a shorter chain that is still
valid. Ship the head (last id + row_hash) to a write-once store, such as S3
with Object Lock, on a schedule (`python -m scripts.verify_audit --head`) and
compare against it to catch truncation.

All chain logic lives here so the storage layer can change (Postgres) without
touching it. In SQLite, appends are one INSERT ... SELECT statement that reads
the previous row and computes the hash while holding the write lock, so
concurrent threads and processes cannot fork the chain.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import sqlite3
from dataclasses import asdict, dataclass

log = logging.getLogger(__name__)

GENESIS = "0" * 64
KEY_CONTEXT = b"discharge-check audit chain v1"
SQL_FN = "audit_row_hash"
FIELDS = ("id", "at", "org_id", "user_id", "action", "target", "ip", "prev_hash", "key_id")
ROTATED = "audit_key_rotated"
_ID_CONTEXT = b"discharge-check audit key id"

# Appends one row. The new id, the timestamp and the previous hash are read
# inside the same statement that writes, so SQLite's write lock covers them.
INSERT_SQL = f"""
INSERT INTO audit_log (id, at, org_id, user_id, action, target, ip, prev_hash, key_id, row_hash)
SELECT n.id, n.at, :org_id, :user_id, :action, :target, :ip, n.prev, :key_id,
       {SQL_FN}(n.id, n.at, :org_id, :user_id, :action, :target, :ip, n.prev, :key_id)
FROM (SELECT COALESCE((SELECT MAX(id) FROM audit_log), 0) + 1 AS id,
             datetime('now') AS at,
             COALESCE((SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1), '{GENESIS}') AS prev) AS n
"""

# Append-only inside the database. These are guard rails for mistakes and
# casual edits; someone with file access can drop them, which the chain catches.
TRIGGERS = """
CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_log_sealed_insert BEFORE INSERT ON audit_log
WHEN NEW.row_hash IS NULL OR NEW.row_hash = ''
BEGIN SELECT RAISE(ABORT, 'audit_log rows must be sealed'); END;
"""


def derive_key(audit_key: str, data_key: str) -> bytes:
    """AUDIT_KEY if set; otherwise a key derived from DATA_KEY, so the
    prototype works without a new secret. Production should set its own."""
    if audit_key:
        return audit_key.encode()
    return hmac.new(data_key.encode(), KEY_CONTEXT, hashlib.sha256).digest()


def key_id(key: bytes) -> str:
    """A fingerprint that names a key without revealing it."""
    return hmac.new(key, _ID_CONTEXT, hashlib.sha256).hexdigest()[:16]


@dataclass(frozen=True)
class KeyRing:
    """The key new rows are sealed with, plus earlier keys kept for verifying
    older rows."""
    current: bytes
    previous: tuple[bytes, ...] = ()

    @property
    def current_id(self) -> str:
        return key_id(self.current)

    def by_id(self) -> dict[str, bytes]:
        keys = {key_id(k): k for k in self.previous}
        keys[self.current_id] = self.current
        return keys


def parse_key(text: str) -> bytes:
    """An AUDIT_KEY_PREVIOUS entry: a secret string, or `hex:<64 hex digits>`
    for a raw key such as one exported with `verify_audit --export-key`."""
    return bytes.fromhex(text[4:]) if text.startswith("hex:") else text.encode()


def export_key(key: bytes) -> str:
    return "hex:" + key.hex()


def as_ring(keys) -> KeyRing:
    return keys if isinstance(keys, KeyRing) else KeyRing(keys)


def keyring_from(audit_key: str, data_key: str, audit_key_previous=(), data_key_previous=()) -> KeyRing:
    """The current key, and every key that may have sealed older rows: listed
    previous audit keys, and keys derived from the current and previous data
    keys (used while AUDIT_KEY was unset)."""
    current = derive_key(audit_key, data_key)
    older = [parse_key(k) for k in audit_key_previous]
    older += [derive_key("", dk) for dk in (data_key, *data_key_previous)]
    return KeyRing(current, tuple(k for k in dict.fromkeys(older) if k != current))


def canonical(id, at, org_id, user_id, action, target, ip, prev_hash, key_id) -> bytes:
    """A JSON array: typed and unambiguous (no field can bleed into the next)."""
    return json.dumps([id, at, org_id, user_id, action, target, ip, prev_hash, key_id],
                      separators=(",", ":"), ensure_ascii=False).encode()


def row_hash(key: bytes, *values) -> str:
    return hmac.new(key, canonical(*values), hashlib.sha256).hexdigest()


def register(conn: sqlite3.Connection, keys) -> None:
    key = as_ring(keys).current
    conn.create_function(SQL_FN, len(FIELDS), lambda *v: row_hash(key, *v), deterministic=True)


def append(conn: sqlite3.Connection, keys, org_id, user_id, action: str, target: str = "", ip: str = "") -> None:
    """The connection must have had register() called on it with the same keys."""
    conn.execute(INSERT_SQL, {
        "key_id": as_ring(keys).current_id,
        # Normalize types so the hash sees exactly what the columns store.
        "org_id": None if org_id is None else int(org_id),
        "user_id": None if user_id is None else int(user_id),
        "action": str(action), "target": str(target or ""), "ip": str(ip or ""),
    })


def seal_legacy(conn: sqlite3.Connection, keys) -> int:
    """Chain rows written before hashing existed, once, in id order. Runs
    before the triggers exist. Returns how many rows were sealed."""
    unsealed = conn.execute("SELECT COUNT(*) FROM audit_log WHERE row_hash = '' OR row_hash IS NULL").fetchone()[0]
    if not unsealed:
        return 0
    ring = as_ring(keys)
    prev = GENESIS
    # Column names come from the constant FIELDS, never from input.
    rows = conn.execute(f"SELECT {', '.join(FIELDS[:7])} FROM audit_log ORDER BY id").fetchall()  # nosec B608
    for r in rows:
        h = row_hash(ring.current, *tuple(r)[:7], prev, ring.current_id)
        conn.execute("UPDATE audit_log SET prev_hash = ?, key_id = ?, row_hash = ? WHERE id = ?",
                     (prev, ring.current_id, h, r[0]))
        prev = h
    log.warning("Sealed %d earlier access-log rows into the hash chain (%d rows in total).", unsealed, len(rows))
    return unsealed


def install_triggers(conn: sqlite3.Connection) -> None:
    conn.executescript(TRIGGERS)


def note_rotation(conn: sqlite3.Connection, keys) -> str | None:
    """If the newest row was sealed with another key, append the rotation
    row that hands the chain to the current key. Returns the old key id."""
    ring = as_ring(keys)
    row = conn.execute("SELECT key_id FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    if row is None or row[0] == ring.current_id:
        return None
    if conn.execute("SELECT 1 FROM audit_log WHERE key_id = ? LIMIT 1", (ring.current_id,)).fetchone():
        raise RuntimeError("AUDIT_KEY is a key the access log already retired. Keys cannot be reused: "
                           "restore the most recent AUDIT_KEY, or generate a new one.")
    append(conn, ring, None, None, ROTATED, f"key:{row[0]}->{ring.current_id}")
    log.warning("Access-log key changed from %s to %s; recorded in the chain.", row[0], ring.current_id)
    return row[0]


@dataclass
class Result:
    ok: bool
    checked: int
    broken_id: int | None = None
    reason: str = ""
    head_id: int | None = None
    head_hash: str = GENESIS
    partial: bool = False  # only the newest rows were checked

    def as_dict(self) -> dict:
        return asdict(self)


def verify(conn: sqlite3.Connection, keys, last: int | None = None) -> Result:
    """Walk the chain in id order. With `last`, check only the newest `last`
    rows (their links and hashes; the first of them is trusted as a start).

    Gaps in ids alone are not an error (a sealed legacy log may have them);
    a removed row shows up as a broken link at the row after it."""
    known = as_ring(keys).by_id()
    start_id = None
    if last is not None:
        row = conn.execute("SELECT id FROM audit_log ORDER BY id DESC LIMIT 1 OFFSET ?", (max(last, 1) - 1,)).fetchone()
        start_id = row[0] if row else None
    q = f"SELECT {', '.join(FIELDS)}, row_hash FROM audit_log"
    cur = conn.execute(q + (" WHERE id >= ?" if start_id else "") + " ORDER BY id", (start_id,) if start_id else ())
    partial = bool(start_id) and conn.execute("SELECT 1 FROM audit_log WHERE id < ? LIMIT 1", (start_id,)).fetchone() is not None
    checked, prev_id, prev, prev_key, retired = 0, None, None, None, set()
    for r in cur:
        values = tuple(r)
        rid, action, stored_prev, kid, stored = values[0], values[4], values[7], values[8], values[9]

        def broken(reason: str) -> Result:
            return Result(False, checked, rid, reason, prev_id, prev or GENESIS, partial)

        if not stored:
            return broken("row was never sealed (written without a hash)")
        if prev is None:
            if not partial and stored_prev != GENESIS:
                return broken("first row does not start from the genesis value (earlier rows removed?)")
        elif stored_prev != prev:
            if rid != prev_id + 1:
                return broken(f"link to the previous row is broken; rows {prev_id + 1} to {rid - 1} are missing")
            return broken("link to the previous row is broken (previous row changed, or a row was inserted)")
        key = known.get(kid)
        if key is None:
            return broken(f"sealed with key {kid or '(none)'}, which is not configured (add it to AUDIT_KEY_PREVIOUS)")
        if prev_key is not None and kid != prev_key:
            if kid in retired:
                return broken(f"sealed with retired key {kid}")
            if action != ROTATED:
                return broken("key changed without a key rotation entry")
            retired.add(prev_key)
        if not hmac.compare_digest(stored, row_hash(key, *values[:9])):
            return broken("row hash does not match its contents (row changed)")
        checked += 1
        prev_id, prev, prev_key = rid, stored, kid
    return Result(True, checked, None, "", prev_id, prev or GENESIS, partial)


def head(conn: sqlite3.Connection) -> dict:
    """The newest row, for anchoring outside the database."""
    r = conn.execute("SELECT id, at, row_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    return {"id": r[0], "at": r[1], "row_hash": r[2]} if r else {"id": 0, "at": None, "row_hash": GENESIS}
