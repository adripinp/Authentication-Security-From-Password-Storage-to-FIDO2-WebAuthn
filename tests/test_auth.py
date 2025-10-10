# tests/test_auth.py
import uuid
import pytest
from app.api import app
from app.db import init_db, DB_FILE

# -------------------------------
# Setup test client and isolated DB
# -------------------------------
@pytest.fixture(autouse=True)
def temp_db(tmp_path):
    # Override DB_FILE to a temporary file
    test_db = tmp_path / "users.db"
    DB_FILE = str(test_db)  # override module variable
    init_db()  # create tables in the temp DB
    yield

@pytest.fixture
def client():
    app.testing = True
    return app.test_client()

# -------------------------------
# Test registration and login
# -------------------------------
def test_register_and_login(client):
    # Use a unique username to avoid collisions
    username = "alice_" + uuid.uuid4().hex
    password = "secret123"

    # Register user
    resp = client.post("/register", json={
        "username": username,
        "password": password,
        "algo": "argon2"  # secure default
    })
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["status"] == "registered"

    # Login with correct password
    resp = client.post("/login", json={
        "username": username,
        "password": password
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "ok"

    # Login with wrong password
    resp = client.post("/login", json={
        "username": username,
        "password": "wrongpassword"
    })
    assert resp.status_code == 401
    data = resp.get_json()
    assert "error" in data
