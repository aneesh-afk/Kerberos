"""
Unit tests for Kerberos Service Server — Group 4 (Sanket)
backend/service-server/main.py
"""

import base64
import importlib.util
import json
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Ensure kerberos-sso project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.security.crypto_utils import encrypt, generate_key

# Dynamically import backend/service-server/main.py to handle hyphenated directory name
SERVICE_SERVER_DIR = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("service_server_main", SERVICE_SERVER_DIR / "main.py")
service_server_main = importlib.util.module_from_spec(_spec)
sys.modules["service_server_main"] = service_server_main
_spec.loader.exec_module(service_server_main)

app = service_server_main.app


@pytest.fixture
def test_key():
    """Generates an isolated 32-byte test key."""
    return generate_key()


@pytest.fixture
def client(test_key, monkeypatch):
    """Provides a TestClient with an isolated test environment."""
    b64_key = base64.b64encode(test_key).decode("utf-8")
    monkeypatch.setenv("TGS_SERVICE_SHARED_KEY", b64_key)
    monkeypatch.setenv("KERBEROS_CLOCK_SKEW_SECONDS", "300")
    monkeypatch.setenv("SERVICE_ID", "service-server")
    return TestClient(app)


def build_ticket_payload(
    client_id: str = "user123",
    service_id: str = "service-server",
    session_key: str = None,
    issued_at: int = None,
    expiry: int = None,
) -> dict:
    """Helper to construct ticket dictionary."""
    now = int(time.time())
    if session_key is None:
        session_key = base64.b64encode(generate_key()).decode("utf-8")
    if issued_at is None:
        issued_at = now - 10
    if expiry is None:
        expiry = now + 3600

    return {
        "client_id": client_id,
        "service_id": service_id,
        "session_key": session_key,
        "issued_at": issued_at,
        "expiry": expiry,
    }


def encrypt_ticket(payload: dict, key: bytes) -> str:
    """Helper to serialize, encrypt, and base64-encode a ticket."""
    plaintext = json.dumps(payload).encode("utf-8")
    ciphertext = encrypt(plaintext, key)
    return base64.b64encode(ciphertext).decode("utf-8")


# ---------------------------------------------------------------------------
# Health Check Tests
# ---------------------------------------------------------------------------

def test_health_returns_200(client):
    """Test 1: /health returns HTTP 200."""
    response = client.get("/health")
    assert response.status_code == 200


def test_health_returns_healthy_status(client):
    """Test 2: /health returns healthy status and service identifier."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data.get("status") in ("healthy", "ok")
    assert data.get("service") == "kerberos-service-server"


# ---------------------------------------------------------------------------
# Ticket Access Tests
# ---------------------------------------------------------------------------

def test_valid_service_ticket_access_granted(client, test_key):
    """Test 3: A valid encrypted Service Ticket receives access granted."""
    payload = build_ticket_payload(client_id="student_akshay")
    encrypted_ticket = encrypt_ticket(payload, test_key)

    response = client.post("/service/access", json={"service_ticket": encrypted_ticket})
    assert response.status_code == 200
    data = response.json()
    assert data.get("granted") is True
    assert data.get("client_id") == "student_akshay"
    assert data.get("resource") is not None
    assert data.get("session_key") == payload["session_key"]


def test_valid_service_ticket_with_request_timestamp(client, test_key):
    """A valid ticket with fresh request timestamp is accepted."""
    payload = build_ticket_payload()
    encrypted_ticket = encrypt_ticket(payload, test_key)
    now = int(time.time())

    response = client.post(
        "/service/access",
        json={"service_ticket": encrypted_ticket, "timestamp": now},
    )
    assert response.status_code == 200
    assert response.json().get("granted") is True


def test_expired_ticket_rejected_with_401(client, test_key):
    """Test 4: An expired ticket is rejected with HTTP 401."""
    now = int(time.time())
    # Expiry was 600 seconds ago, beyond the 300s clock skew
    payload = build_ticket_payload(issued_at=now - 3600, expiry=now - 600)
    encrypted_ticket = encrypt_ticket(payload, test_key)

    response = client.post("/service/access", json={"service_ticket": encrypted_ticket})
    assert response.status_code == 401
    assert "expired" in response.json().get("detail", "").lower()


def test_tampered_ticket_rejected_with_401(client, test_key):
    """Test 5: An invalid/tampered ticket is rejected with HTTP 401."""
    payload = build_ticket_payload()
    raw_ciphertext = encrypt(json.dumps(payload).encode("utf-8"), test_key)

    # Tamper with the raw ciphertext
    tampered_bytes = bytearray(raw_ciphertext)
    tampered_bytes[-1] ^= 0xAA
    tampered_ticket = base64.b64encode(tampered_bytes).decode("utf-8")

    response = client.post("/service/access", json={"service_ticket": tampered_ticket})
    assert response.status_code == 401


def test_ticket_encrypted_with_wrong_key_rejected_with_401(client):
    """Ticket encrypted with an untrusted/different key is rejected with HTTP 401."""
    wrong_key = generate_key()
    payload = build_ticket_payload()
    encrypted_ticket = encrypt_ticket(payload, wrong_key)

    response = client.post("/service/access", json={"service_ticket": encrypted_ticket})
    assert response.status_code == 401


def test_missing_required_ticket_fields_rejected(client, test_key):
    """Test 6: Missing required ticket fields are rejected with HTTP 401."""
    required_keys = ["client_id", "service_id", "session_key", "issued_at", "expiry"]

    for field in required_keys:
        payload = build_ticket_payload()
        del payload[field]
        encrypted_ticket = encrypt_ticket(payload, test_key)

        response = client.post("/service/access", json={"service_ticket": encrypted_ticket})
        assert response.status_code == 401, f"Expected 401 when field '{field}' is missing"


def test_invalid_ticket_timestamps_rejected(client, test_key):
    """Test 7: Invalid ticket timestamps are rejected with HTTP 401."""
    now = int(time.time())

    # Case A: expiry <= issued_at
    payload_invalid_lifetime = build_ticket_payload(issued_at=now, expiry=now - 10)
    enc_invalid_lifetime = encrypt_ticket(payload_invalid_lifetime, test_key)
    res_a = client.post("/service/access", json={"service_ticket": enc_invalid_lifetime})
    assert res_a.status_code == 401

    # Case B: Ticket issued too far in the future (> 300s skew)
    payload_future = build_ticket_payload(issued_at=now + 1000, expiry=now + 4000)
    enc_future = encrypt_ticket(payload_future, test_key)
    res_b = client.post("/service/access", json={"service_ticket": enc_future})
    assert res_b.status_code == 401


def test_wrong_service_id_rejected(client, test_key):
    """Ticket intended for a different service is rejected with HTTP 401."""
    payload = build_ticket_payload(service_id="other-service")
    encrypted_ticket = encrypt_ticket(payload, test_key)

    response = client.post("/service/access", json={"service_ticket": encrypted_ticket})
    assert response.status_code == 401


def test_missing_server_key_configuration(monkeypatch):
    """Missing TGS_SERVICE_SHARED_KEY causes HTTP 500 error."""
    monkeypatch.delenv("TGS_SERVICE_SHARED_KEY", raising=False)
    test_client = TestClient(app)
    response = test_client.post("/service/access", json={"service_ticket": "dummy"})
    assert response.status_code == 500
