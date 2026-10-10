"""
Unit and integration tests for Kerberos TGS — Group 3 (Sahil)
Tests /health and /tgs/service-ticket.
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

TGS_DIR = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("tgs_main", TGS_DIR / "main.py")
tgs_main = importlib.util.module_from_spec(_spec)
sys.modules["tgs_main"] = tgs_main
_spec.loader.exec_module(tgs_main)

app = tgs_main.app


@pytest.fixture
def raw_as_tgs_key():
    return crypto_utils.generate_key()


@pytest.fixture
def raw_tgs_service_key():
    return crypto_utils.generate_key()


@pytest.fixture
def client(raw_as_tgs_key, raw_tgs_service_key, monkeypatch):
    b64_as_tgs = base64.b64encode(raw_as_tgs_key).decode("utf-8")
    b64_tgs_svc = base64.b64encode(raw_tgs_service_key).decode("utf-8")
    monkeypatch.setenv("AS_TGS_SHARED_KEY", b64_as_tgs)
    monkeypatch.setenv("TGS_SERVICE_SHARED_KEY", b64_tgs_svc)
    monkeypatch.setenv("KERBEROS_CLOCK_SKEW_SECONDS", "300")
    monkeypatch.setenv("SERVICE_TICKET_LIFETIME_SECONDS", "600")
    monkeypatch.setenv("SERVICE_ID", "service-server")
    return TestClient(app)


def build_and_encrypt_tgt(
    key: bytes,
    client_id: str = "alice",
    session_key: str = None,
    issued_at: int = None,
    expiry: int = None,
) -> str:
    now = int(time.time())
    if session_key is None:
        session_key = base64.b64encode(crypto_utils.generate_key()).decode("utf-8")
    if issued_at is None:
        issued_at = now - 5
    if expiry is None:
        expiry = now + 3600

    payload = {
        "client_id": client_id,
        "tgs_id": "kerberos-tgs",
        "session_key": session_key,
        "issued_at": issued_at,
        "expiry": expiry,
    }
    raw_ct = crypto_utils.encrypt(json.dumps(payload).encode("utf-8"), key)
    return base64.b64encode(raw_ct).decode("utf-8")


# ---------------------------------------------------------------------------
# Health Check Tests
# ---------------------------------------------------------------------------
def test_tgs_health_returns_200(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "kerberos-tgs"
    assert data["keys_configured"] is True


def test_tgs_health_fails_without_as_tgs_key(monkeypatch, raw_tgs_service_key):
    k_tgs_svc = base64.b64encode(raw_tgs_service_key).decode("utf-8")
    monkeypatch.delenv("AS_TGS_SHARED_KEY", raising=False)
    monkeypatch.setenv("TGS_SERVICE_SHARED_KEY", k_tgs_svc)
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 500
    assert "AS_TGS_SHARED_KEY environment variable is not configured" in response.json()["detail"]


def test_tgs_health_fails_without_tgs_service_key(monkeypatch, raw_as_tgs_key):
    k_as_tgs = base64.b64encode(raw_as_tgs_key).decode("utf-8")
    monkeypatch.setenv("AS_TGS_SHARED_KEY", k_as_tgs)
    monkeypatch.delenv("TGS_SERVICE_SHARED_KEY", raising=False)
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 500
    assert "TGS_SERVICE_SHARED_KEY environment variable is not configured" in response.json()["detail"]


# ---------------------------------------------------------------------------
# /tgs/service-ticket Tests
# ---------------------------------------------------------------------------
def test_service_ticket_success_with_valid_tgt(client, raw_as_tgs_key, raw_tgs_service_key):
    """Test successful Service Ticket issuance with fresh TGT."""
    tgt_b64 = build_and_encrypt_tgt(raw_as_tgs_key, client_id="alice")

    response = client.post("/tgs/service-ticket", json={
        "tgt": tgt_b64,
        "service_id": "service-server"
    })
    assert response.status_code == 200
    data = response.json()

    assert "service_ticket" in data
    assert data["service_id"] == "service-server"
    assert data["expiry"] > int(time.time())

    # Verify session key length
    sess_bytes = base64.b64decode(data["session_key"])
    assert len(sess_bytes) == 32

    # Verify Service Ticket can be decrypted using TGS_SERVICE_SHARED_KEY (Group 4 contract)
    st_raw = base64.b64decode(data["service_ticket"])
    decrypted_st = crypto_utils.decrypt(st_raw, raw_tgs_service_key)
    st_payload = json.loads(decrypted_st.decode("utf-8"))

    assert st_payload["client_id"] == "alice"
    assert st_payload["service_id"] == "service-server"
    assert st_payload["session_key"] == data["session_key"]
    assert st_payload["expiry"] == data["expiry"]
    assert st_payload["expiry"] > st_payload["issued_at"]


def test_service_ticket_success_with_fresh_request_timestamp(client, raw_as_tgs_key):
    """Test that request timestamp within clock skew is accepted."""
    tgt_b64 = build_and_encrypt_tgt(raw_as_tgs_key, client_id="bob")
    now = int(time.time())

    response = client.post("/tgs/service-ticket", json={
        "tgt": tgt_b64,
        "service_id": "service-server",
        "timestamp": now - 10
    })
    assert response.status_code == 200
    assert "service_ticket" in response.json()


def test_service_ticket_fails_tampered_tgt(client, raw_as_tgs_key):
    """Test that tampered TGT ciphertext fails with 401 Unauthorized."""
    tgt_b64 = build_and_encrypt_tgt(raw_as_tgs_key, client_id="alice")
    raw_ct = bytearray(base64.b64decode(tgt_b64))
    # Flip bytes in ciphertext
    raw_ct[15] ^= 0xFF
    tampered_b64 = base64.b64encode(raw_ct).decode("utf-8")

    response = client.post("/tgs/service-ticket", json={
        "tgt": tampered_b64,
        "service_id": "service-server"
    })
    assert response.status_code == 401
    assert "Invalid or tampered TGT" in response.json()["detail"]


def test_service_ticket_fails_wrong_as_key(client):
    """Test that TGT encrypted with an unknown key fails with 401."""
    foreign_key = crypto_utils.generate_key()
    tgt_b64 = build_and_encrypt_tgt(foreign_key, client_id="attacker")

    response = client.post("/tgs/service-ticket", json={
        "tgt": tgt_b64,
        "service_id": "service-server"
    })
    assert response.status_code == 401
    assert "Invalid or tampered TGT" in response.json()["detail"]


def test_service_ticket_fails_expired_tgt(client, raw_as_tgs_key):
    """Test that an expired TGT is rejected with 401."""
    now = int(time.time())
    tgt_b64 = build_and_encrypt_tgt(
        raw_as_tgs_key,
        client_id="alice",
        issued_at=now - 7200,
        expiry=now - 3600
    )

    response = client.post("/tgs/service-ticket", json={
        "tgt": tgt_b64,
        "service_id": "service-server"
    })
    assert response.status_code == 401
    assert "TGT has expired" in response.json()["detail"]


def test_service_ticket_fails_future_tgt(client, raw_as_tgs_key):
    """Test that a TGT issued too far in the future is rejected with 401."""
    now = int(time.time())
    tgt_b64 = build_and_encrypt_tgt(
        raw_as_tgs_key,
        client_id="alice",
        issued_at=now + 1000,
        expiry=now + 4000
    )

    response = client.post("/tgs/service-ticket", json={
        "tgt": tgt_b64,
        "service_id": "service-server"
    })
    assert response.status_code == 401
    assert "TGT is not yet valid" in response.json()["detail"]


def test_service_ticket_fails_stale_request_timestamp(client, raw_as_tgs_key):
    """Test that a stale client request timestamp (replay) is rejected with 401."""
    tgt_b64 = build_and_encrypt_tgt(raw_as_tgs_key, client_id="alice")
    now = int(time.time())

    response = client.post("/tgs/service-ticket", json={
        "tgt": tgt_b64,
        "service_id": "service-server",
        "timestamp": now - 600  # Outside default 300s clock skew
    })
    assert response.status_code == 401
    assert "Request timestamp outside allowed clock skew" in response.json()["detail"]


def test_service_ticket_fails_unrecognized_service(client, raw_as_tgs_key):
    """Test that requesting an unknown service returns 400 Bad Request."""
    tgt_b64 = build_and_encrypt_tgt(raw_as_tgs_key, client_id="alice")

    response = client.post("/tgs/service-ticket", json={
        "tgt": tgt_b64,
        "service_id": "nonexistent-banking-service"
    })
    assert response.status_code == 400
    assert "Unrecognized service_id" in response.json()["detail"]
