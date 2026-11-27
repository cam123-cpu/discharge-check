import re
import secrets
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402
from app.security import hash_password  # noqa: E402

PASSWORD = "correct horse battery staple"


@pytest.fixture
def settings(tmp_path):
    return Settings(
        data_key=Fernet.generate_key().decode(),
        session_pepper=secrets.token_urlsafe(32),
        anthropic_api_key=None,
        force_https=False,
        database_path=tmp_path / "test.db",
    )


@pytest.fixture
def app(settings):
    app = create_app(settings)
    with app.state.db.connect() as conn:
        a = conn.execute("INSERT INTO orgs (name) VALUES ('Org A')").lastrowid
        b = conn.execute("INSERT INTO orgs (name) VALUES ('Org B')").lastrowid
        for email, org, role in [("cm@a.test", a, "compliance"), ("rn@a.test", a, "nurse"), ("doc@b.test", b, "physician")]:
            conn.execute("INSERT INTO users (org_id, email, display_name, role, password_hash) VALUES (?, ?, ?, ?, ?)",
                         (org, email, email.split("@")[0], role, hash_password(PASSWORD)))
        conn.execute("INSERT INTO patients (org_id, label, discharge_date, disposition) VALUES (?, 'A-1', '2026-11-14', 'Home')", (a,))
        conn.execute("INSERT INTO patients (org_id, label) VALUES (?, 'B-1')", (b,))
    return app


def login(client: TestClient, email: str, password: str = PASSWORD):
    page = client.get("/login")
    pre = re.search(r'name="pre" value="([^"]+)"', page.text).group(1)
    return client.post("/login", data={"email": email, "password": password, "pre": pre}, follow_redirects=False)


def csrf_of(client: TestClient, path: str = "/patients") -> str:
    return re.search(r'name="csrf" value="([^"]+)"', client.get(path).text).group(1)


@pytest.fixture
def client(app):
    return TestClient(app)
