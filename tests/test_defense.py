"""Defensive checks against this app. They assert rejection or escaping.

They do not include exploit procedures, payloads meant to be reused, or
steps for attacking any other system.
"""
import re

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import clock_for, create_app
from app.security import Cipher

PASSWORD = "correct horse battery staple"


def login(client: TestClient, email: str, password: str = PASSWORD):
    page = client.get("/login")
    pre = re.search(r'name="pre" value="([^"]+)"', page.text).group(1)
    return client.post("/login", data={"email": email, "password": password, "pre": pre}, follow_redirects=False)


def csrf_of(client: TestClient, path: str = "/patients") -> str:
    return re.search(r'name="csrf" value="([^"]+)"', client.get(path).text).group(1)


def test_query_text_is_not_written_onto_the_page(client, app):
    login(client, "cm@a.test")
    with app.state.db.connect() as conn:
        pid = conn.execute("SELECT id FROM patients WHERE label = 'A-1'").fetchone()[0]
    crafted = "<script>alert(1)</script>"
    page = client.get(f"/patients/{pid}?notice={crafted}&warn={crafted}")
    assert crafted not in page.text
    assert "alert(1)" not in page.text
    added = client.get(f"/patients/{pid}?notice=added&warn=phone")
    assert "Document added" in added.text
    assert "phone number" in added.text
    login_page = client.get("/login?error=<script>alert(1)</script>")
    assert "<script>" not in login_page.text
    shown = client.get("/login?error=bad")
    assert "incorrect" in shown.text
    assert "<script>" not in shown.text


def test_login_goes_to_the_queue_even_if_a_next_field_is_posted(client):
    page = client.get("/login")
    pre = re.search(r'name="pre" value="([^"]+)"', page.text).group(1)
    r = client.post(
        "/login",
        data={"email": "cm@a.test", "password": PASSWORD, "pre": pre, "next": "https://evil.example/phish"},
        follow_redirects=False,
    )
    assert r.headers["location"] == "/patients"
    assert "evil" not in r.headers["location"]


def test_a_document_cannot_be_read_through_another_patient_or_org(client, app):
    login(client, "cm@a.test")
    token = csrf_of(client)
    created = client.post(
        "/patients",
        data={"csrf": token, "label": "SYN-A", "discharge_date": "2026-11-14", "disposition": "Home"},
        follow_redirects=False,
    )
    other = client.post(
        "/patients",
        data={"csrf": token, "label": "SYN-B", "discharge_date": "2026-11-14", "disposition": "Home"},
        follow_redirects=False,
    )
    pid = int(created.headers["location"].rsplit("/", 1)[1])
    other_id = int(other.headers["location"].rsplit("/", 1)[1])
    token = csrf_of(client, f"/patients/{pid}")
    uploaded = client.post(
        f"/patients/{pid}/documents",
        data={"csrf": token, "kind": "other", "confirm": "yes"},
        files={"file": ("note.txt", b"Author: Casey\nA short synthetic note.\n", "text/plain")},
        follow_redirects=False,
    )
    assert "notice=added" in uploaded.headers["location"]
    with app.state.db.connect() as conn:
        doc_id = conn.execute("SELECT id FROM documents WHERE patient_id = ?", (pid,)).fetchone()[0]
        foreign = conn.execute("SELECT id FROM patients WHERE label = 'B-1'").fetchone()[0]
    assert client.get(f"/patients/{other_id}/documents/{doc_id}").status_code == 404
    assert client.get(f"/patients/{foreign}/documents/{doc_id}").status_code == 404
    token = csrf_of(client, f"/patients/{other_id}")
    deleted = client.post(f"/patients/{other_id}/documents/{doc_id}/delete", data={"csrf": token}, follow_redirects=False)
    assert deleted.status_code == 404
    with app.state.db.connect() as conn:
        assert conn.execute("SELECT id FROM documents WHERE id = ?", (doc_id,)).fetchone() is not None
    login(client, "doc@b.test")
    assert client.get(f"/patients/{pid}").status_code == 404
    assert client.get(f"/patients/{pid}/documents/{doc_id}").status_code == 404


def test_author_markup_is_escaped(client):
    login(client, "cm@a.test")
    token = csrf_of(client)
    created = client.post(
        "/patients",
        data={"csrf": token, "label": "SYN-X", "discharge_date": "2026-11-14", "disposition": "Home"},
        follow_redirects=False,
    )
    pid = created.headers["location"].rsplit("/", 1)[1]
    token = csrf_of(client, f"/patients/{pid}")
    body = b"Author: <script>alert(1)</script>\nDischarge Diagnosis:\n- Pneumonia\n"
    client.post(
        f"/patients/{pid}/documents",
        data={"csrf": token, "kind": "discharge_summary", "confirm": "yes"},
        files={"file": ("summary.txt", body, "text/plain")},
        follow_redirects=True,
    )
    page = client.get(f"/patients/{pid}")
    assert "<script>" not in page.text
    assert "&lt;script&gt;" in page.text


def test_sql_metacharacters_in_a_label_do_not_drop_the_table(client):
    login(client, "cm@a.test")
    token = csrf_of(client)
    r = client.post("/patients", data={"csrf": token, "label": "A'; DROP TABLE patients;--"})
    assert r.status_code == 400
    assert "A-1" in client.get("/patients").text


def test_deleting_a_document_marks_the_saved_check_out_of_date(client):
    login(client, "cm@a.test")
    token = csrf_of(client)
    created = client.post(
        "/patients",
        data={"csrf": token, "label": "SYN-S", "discharge_date": "2026-11-14", "disposition": "Home"},
        follow_redirects=False,
    )
    pid = created.headers["location"].rsplit("/", 1)[1]
    token = csrf_of(client, f"/patients/{pid}")
    summary = open("samples/syn-0001-summary.txt", "rb").read()
    nursing = open("samples/syn-0001-nursing.txt", "rb").read()
    client.post(
        f"/patients/{pid}/documents",
        data={"csrf": token, "kind": "discharge_summary", "confirm": "yes"},
        files={"file": ("summary.txt", summary, "text/plain")},
    )
    token = csrf_of(client, f"/patients/{pid}")
    client.post(
        f"/patients/{pid}/documents",
        data={"csrf": token, "kind": "nursing_instructions", "confirm": "yes"},
        files={"file": ("nursing.txt", nursing, "text/plain")},
    )
    token = csrf_of(client, f"/patients/{pid}")
    checked = client.post(f"/patients/{pid}/check", data={"csrf": token}, follow_redirects=True)
    assert "All shown" in client.get("/patients").text or "shown in the text" in checked.text
    assert "Out of date" not in checked.text
    token = csrf_of(client, f"/patients/{pid}")
    # The document id is on the page as a link.
    doc_id = re.search(rf"/patients/{pid}/documents/(\d+)", checked.text).group(1)
    client.post(f"/patients/{pid}/documents/{doc_id}/delete", data={"csrf": token}, follow_redirects=True)
    queue = client.get("/patients").text
    chart = client.get(f"/patients/{pid}").text
    assert "Out of date" in queue
    assert "record changed after this check" in chart
    # The stale chart must not be described as finished.
    row = queue[queue.find("SYN-S"):queue.find("SYN-S") + 800]
    assert "All shown" not in row


def test_signed_on_time_requires_a_complete_signature():
    from datetime import date
    assert clock_for("2026-11-01", "pass", date(2026, 11, 27), "")["label"] != "Signed on time"
    assert clock_for("2026-11-01", "pass", date(2026, 11, 27), "fail")["label"] != "Signed on time"
    assert clock_for("2026-11-01", "pass", date(2026, 11, 27), "pass")["label"] == "Signed on time"


def test_legacy_plaintext_is_sealed_on_startup(tmp_path):
    settings = Settings(
        data_key=Fernet.generate_key().decode(),
        session_pepper="pepper-for-the-legacy-test-value",
        anthropic_api_key=None,
        force_https=False,
        database_path=tmp_path / "legacy.db",
    )
    app = create_app(settings)
    with app.state.db.connect() as conn:
        org = conn.execute("INSERT INTO orgs (name) VALUES ('Legacy')").lastrowid
        pid = conn.execute(
            "INSERT INTO patients (org_id, label, attending) VALUES (?, 'LEG-1', 'Dr Plain')",
            (org,),
        ).lastrowid
        conn.execute(
            "INSERT INTO documents (org_id, patient_id, kind, filename, body_enc, author) VALUES (?, ?, 'other', 'a.txt', ?, 'Nurse Plain')",
            (org, pid, b"sealed-body"),
        )
    create_app(settings)
    cipher = Cipher(settings.data_key)
    with app.state.db.connect() as conn:
        row = conn.execute("SELECT label, attending FROM patients WHERE id = ?", (pid,)).fetchone()
        author = conn.execute("SELECT author FROM documents WHERE patient_id = ?", (pid,)).fetchone()[0]
    assert str(row["label"]).startswith("enc:v1:")
    assert cipher.decrypt_field(row["label"]) == "LEG-1"
    assert cipher.decrypt_field(row["attending"]) == "Dr Plain"
    assert str(author).startswith("enc:v1:")
    assert cipher.decrypt_field(author) == "Nurse Plain"
