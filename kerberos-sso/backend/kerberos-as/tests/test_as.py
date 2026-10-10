"""
Unit and integration tests for Kerberos AS — Group 3 (Bhumika)
Tests /health and /as/authenticate.
"""

import base64
import importlib.util
import json
import os
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.security import crypto_utils

AS_DIR = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("as_main", AS_DIR / "main.py")
as_main = importlib.util.module_from_spec(_spec)
sys.modules["as_main"] = as_main
_spec.loader.exec_module(as_main)

app = as_main.app


@pytest.fixture
def raw_test_key():
    return crypto_utils.generate_key()


@pytest.fixture
def client(raw_test_key, monkeypatch):
    b64_key = base64.b64encode(raw_test_key).decode("utf-8")
    monkeypatch.setenv("AS_TGS_SHARED_KEY", b64_key)
    monkeypatch.setenv("TGT_LIFETIME_SECONDS", "3600")
    as_main.reset_user_store()
    return TestClient(app)


# ---------------------------------------------------------------------------
# Health Check Tests
# ---------------------------------------------------------------------------
def test_as_health_returns_200(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "kerberos-as"
    assert data["key_configured"] is True


def test_as_health_fails_without_key(monkeypatch):
    monkeypatch.delenv("AS_TGS_SHARED_KEY", raising=False)
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 500
    assert "AS_TGS_SHARED_KEY environment variable is not configured" in response.json()["detail"]


def test_as_health_fails_with_invalid_key_length(monkeypatch):
    short_key = base64.b64encode(b"too_short_key").decode("utf-8")
    monkeypatch.setenv("AS_TGS_SHARED_KEY", short_key)
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 500
    assert "must be exactly 32 bytes" in response.json()["detail"]


# ---------------------------------------------------------------------------
# /as/authenticate Tests
# ---------------------------------------------------------------------------
def test_authenticate_success_with_password(client, raw_test_key):
    """Test successful authentication with username + plaintext password."""
    response = client.post("/as/authenticate", json={
        "username": "alice",
        "password": "password123"
    })
    assert response.status_code == 200
    data = response.json()

    assert data["client_id"] == "alice"
    assert "tgt" in data
    assert "session_key" in data
    assert data["tgt_expiry"] > int(time.time())

    # Verify session key is 32-byte Base64
    session_key_bytes = base64.b64decode(data["session_key"])
    assert len(session_key_bytes) == 32

    # Decrypt and verify TGT payload using the shared key
    tgt_ciphertext = base64.b64decode(data["tgt"])
    decrypted_bytes = crypto_utils.decrypt(tgt_ciphertext, raw_test_key)
    tgt_payload = json.loads(decrypted_bytes.decode("utf-8"))

    assert tgt_payload["client_id"] == "alice"
    assert tgt_payload["tgs_id"] == "kerberos-tgs"
    assert tgt_payload["session_key"] == data["session_key"]
    assert tgt_payload["expiry"] == data["tgt_expiry"]
    assert tgt_payload["expiry"] > tgt_payload["issued_at"]


def test_authenticate_success_with_password_hash(client, raw_test_key):
    """Test successful authentication when caller supplies matching password_hash."""
    user = as_main.lookup_user("bob")
    assert user is not None

    response = client.post("/as/authenticate", json={
        "username": "bob",
        "password_hash": user["password_hash"]
    })
    assert response.status_code == 200
    data = response.json()
    assert data["client_id"] == "bob"
    assert "tgt" in data


def test_authenticate_fails_with_wrong_password(client):
    """Test that invalid password returns 401 Unauthorized."""
    response = client.post("/as/authenticate", json={
        "username": "alice",
        "password": "wrongpassword"
    })
    assert response.status_code == 401
    assert "Invalid username or password" in response.json()["detail"]


def test_authenticate_fails_with_nonexistent_user(client):
    """Test that non-existent username returns 401 Unauthorized."""
    response = client.post("/as/authenticate", json={
        "username": "nonexistent_user",
        "password": "password123"
    })
    assert response.status_code == 401
    assert "Invalid username or password" in response.json()["detail"]


def test_authenticate_fails_missing_password_and_hash(client):
    """Test that missing credentials return 400 Bad Request."""
    response = client.post("/as/authenticate", json={
        "username": "alice"
    })
    assert response.status_code == 400
    assert "Either 'password' or 'password_hash' must be provided" in response.json()["detail"]


def test_authenticate_fails_empty_username(client):
    """Test that empty username returns 400 Bad Request."""
    response = client.post("/as/authenticate", json={
        "username": "  ",
        "password": "password123"
    })
    assert response.status_code == 400
    assert "Username cannot be empty" in response.json()["detail"]


def test_authenticate_fails_when_as_key_missing(monkeypatch):
    """Test that server returns 500 when AS_TGS_SHARED_KEY is not configured."""
    monkeypatch.delenv("AS_TGS_SHARED_KEY", raising=False)
    client = TestClient(app)
    response = client.post("/as/authenticate", json={
        "username": "alice",
        "password": "password123"
    })
    assert response.status_code == 500
    assert "AS_TGS_SHARED_KEY environment variable is not configured" in response.json()["detail"]
