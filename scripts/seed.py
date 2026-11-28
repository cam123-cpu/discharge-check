"""Creates a demo organization, users and the synthetic discharges.

Usage: python -m scripts.seed
Prints the generated passwords once. Nothing is hard-coded."""
from __future__ import annotations

import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.config import load_settings  # noqa: E402
from app.db import Database  # noqa: E402
from app.ingest import parse_upload  # noqa: E402
from app.security import Cipher, hash_password  # noqa: E402

USERS = [
    ("compliance@demo.test", "Jordan Ellis", "compliance"),
    ("physician@demo.test", "Dr. Amelia Rivera", "physician"),
    ("nurse@demo.test", "Sam Whitaker, RN", "nurse"),
    ("cm@demo.test", "Priya Natarajan, RN CM", "case_manager"),
    ("admin@demo.test", "Site Admin", "admin"),
]
SAMPLES = ROOT / "samples"
PATIENTS = [
    ("SYN-0001", "4 West Medicine", "Dr. Amelia Rivera", "2026-11-14", "Home",
     [("syn-0001-summary.txt", "discharge_summary"), ("syn-0001-nursing.txt", "nursing_instructions")]),
    ("SYN-0002", "5 East Medicine", "Dr. Marcus Chen", "2026-11-09", "Skilled nursing facility (SNF)",
     [("syn-0002-summary.txt", "discharge_summary"), ("syn-0002-nursing.txt", "nursing_instructions"), ("syn-0002-casemgmt.txt", "case_management")]),
    ("SYN-0003", "5 East Medicine", "Dr. Samuel Brooks", "2026-10-10", "Home with home health services",
     [("syn-0003-summary.txt", "discharge_summary"), ("syn-0003-casemgmt.txt", "case_management")]),
    ("SYN-0004", "Orthopedics", "Dr. Felix Grant", "2026-11-19", "Inpatient rehabilitation facility (IRF)",
     [("syn-0004-bundle.json", "discharge_summary")]),
    ("SYN-0005", "Cardiac Step-Down", "Dr. Nadia Petrov", "2026-11-21", "Home",
     [("syn-0005-summary.txt", "discharge_summary")]),
]


def main() -> None:
    s = load_settings()
    db = Database(s.database_path)
    cipher = Cipher(s.data_key)
    with db.connect() as conn:
        if conn.execute("SELECT COUNT(*) FROM orgs").fetchone()[0]:
            print("Demo data already exists. To get new passwords run: python -m scripts.setup --new-passwords")
            print("To start over, delete", s.database_path, "and run python -m scripts.setup again.")
            return
        org_id = conn.execute("INSERT INTO orgs (name) VALUES (?)", ("Demo General Hospital",)).lastrowid
        conn.execute("INSERT INTO orgs (name) VALUES (?)", ("Other Hospital",))
        print("Demo accounts (save these; they are not shown again):")
        for email, name, role in USERS:
            pw = secrets.token_urlsafe(12)
            conn.execute("INSERT INTO users (org_id, email, display_name, role, password_hash) VALUES (?, ?, ?, ?, ?)",
                         (org_id, email, name, role, hash_password(pw)))
            print(f"  {role:13} {email:24} {pw}")
        for label, unit, attending, dc, dispo, files in PATIENTS:
            pid = conn.execute(
                "INSERT INTO patients (org_id, label, unit, attending, discharge_date, disposition) VALUES (?, ?, ?, ?, ?, ?)",
                (org_id, label, unit, attending, dc, dispo)).lastrowid
            for fname, kind in files:
                doc = parse_upload((SAMPLES / fname).read_bytes(), fname, kind, s.max_upload_bytes)
                conn.execute("INSERT INTO documents (org_id, patient_id, kind, filename, author, body_enc) VALUES (?, ?, ?, ?, ?, ?)",
                             (org_id, pid, doc.kind, doc.filename, doc.author, cipher.encrypt(doc.text)))
    print("Seeded 5 synthetic discharges. Open each one and press Run check.")


if __name__ == "__main__":
    main()
