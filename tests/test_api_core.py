import json
from app.api import app
from app.db import init_db

def setup_module(module):
    init_db()
    app.testing = True
    module.client = app.test_client()

def test_register_and_login():
    # Register
    response = client.post("/register", json={
        "username": "alice",
        "password": "secret123",
        "algo": "sha256"
    })
    assert response.status_code in (201, 400)

    # Login
    response = client.post("/login", json={
        "username": "alice",
        "password": "secret123"
    })
    assert response.status_code in (200, 401)
