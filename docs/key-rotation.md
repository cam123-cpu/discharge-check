# Rotating keys

Three secrets protect stored data. Each can be rotated without downtime and
without losing records. In AWS, every key below lives in Secrets Manager (see
[deploy-aws.md](deploy-aws.md)); "restart" means deploying a new task with the
updated secrets.

| Secret | When to rotate | Effect on users |
| --- | --- | --- |
| `DATA_KEY` | On a schedule (for example yearly), and at once if it may have leaked | None |
| `AUDIT_KEY` | On a schedule, and at once if it may have leaked | None |
| `SESSION_PEPPER` | Any time | Everyone is signed out |

## DATA_KEY (encryption of document text and check results)

1. Generate a new key:
   `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
2. Set `DATA_KEY_PREVIOUS` to the current key, set `DATA_KEY` to the new key,
   and restart. New data is encrypted with the new key, and old rows stay
   readable through the previous key.
3. Re-encrypt the old rows: `python -m scripts.rotate_data_key`. It works in
   small batches, so the app keeps serving meanwhile. It is safe to stop and
   run again, and it records a "Encryption key rotated" entry in the access log.
4. Confirm: `python -m scripts.rotate_data_key --check` exits 0 and reports
   0 rows left.
5. Remove the old key from `DATA_KEY_PREVIOUS` and restart. Destroy the old
   key only after database backups taken before step 3 have expired, because
   those backups can only be read with it.

`DATA_KEY_PREVIOUS` takes several keys separated by commas, newest first.

**If `AUDIT_KEY` is not set**, the access-log key is derived from `DATA_KEY`,
so it changes in step 2 (the app records the switch in the log). Before step 5,
keep the old access-log key so older log rows stay verifiable:

```bash
# Run with the OLD DATA_KEY as DATA_KEY, before you change anything:
python -m scripts.verify_audit --export-key      # prints hex:..., a secret
```

Add that value to `AUDIT_KEY_PREVIOUS`. Simpler: set a separate `AUDIT_KEY`
in production from the start, and this step never comes up.

## AUDIT_KEY (the access log's hash chain)

Each access-log row records which key sealed it (a fingerprint, never the key).

1. Generate a new key: `python -c "import secrets; print(secrets.token_urlsafe(48))"`
2. Add the current key to `AUDIT_KEY_PREVIOUS` (comma-separated), set
   `AUDIT_KEY` to the new key, and restart. The app writes an "Access log key
   rotated" row sealed with the new key, and every later row uses it.
3. Check: `python -m scripts.verify_audit` exits 0.

Keep every previous key for as long as the rows it sealed are retained (6
years for HIPAA documentation), or those rows can no longer be verified. The
chain refuses two things on purpose:

- A key switch anywhere except on a rotation row.
- A retired key coming back. The app will not start with an `AUDIT_KEY` the
  log has already retired, and verification fails on any row a retired key
  sealed after its retirement. A leaked old key therefore cannot be used to
  add forged rows.

## SESSION_PEPPER

Replace it and restart. All sessions end and everyone signs in again. There
is nothing to migrate.
