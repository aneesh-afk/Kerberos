"""
End-to-End Integration Test: Kerberos Core (Group 3) + Service Server (Group 4)

Simulates the complete Kerberos SSO flow:
1. Authenticate with AS (Bhumika) -> get TGT
2. Exchange TGT with TGS (Sahil) -> get Service Ticket
3. Present Service Ticket to Service Server (Sanket) -> access granted!
"""

import base64
import importlib.util
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

# Import AS
AS_DIR = Path(__file__).resolve().parents[1]
_spec_as = importlib.util.spec_from_file_location("as_main_e2e", AS_DIR / "main.py")
as_mod = importlib.util.module_from_spec(_spec_as)
sys.modules["as_main_e2e"] = as_mod
_spec_as.loader.exec_module(as_mod)

# Import TGS
TGS_DIR = PROJECT_ROOT / "backend" / "kerberos-tgs"
_spec_tgs = importlib.util.spec_from_file_location("tgs_main_e2e", TGS_DIR / "main.py")
tgs_mod = importlib.util.module_from_spec(_spec_tgs)
sys.modules["tgs_main_e2e"] = tgs_mod
_spec_tgs.loader.exec_module(tgs_mod)

# Import Service Server
SS_DIR = PROJECT_ROOT / "backend" / "service-server"
_spec_ss = importlib.util.spec_from_file_location("ss_main_e2e", SS_DIR / "main.py")
ss_mod = importlib.util.module_from_spec(_spec_ss)
sys.modules["ss_main_e2e"] = ss_mod
_spec_ss.loader.exec_module(ss_mod)


@pytest.fixture
def e2e_env(monkeypatch):
    k_as_tgs = crypto_utils.generate_key()
    k_tgs_svc = crypto_utils.generate_key()

    b64_as_tgs = base64.b64encode(k_as_tgs).decode("utf-8")
    b64_tgs_svc = base64.b64encode(k_tgs_svc).decode("utf-8")

    monkeypatch.setenv("AS_TGS_SHARED_KEY", b64_as_tgs)
    monkeypatch.setenv("TGS_SERVICE_SHARED_KEY", b64_tgs_svc)
    monkeypatch.setenv("KERBEROS_CLOCK_SKEW_SECONDS", "300")
    monkeypatch.setenv("TGT_LIFETIME_SECONDS", "3600")
    monkeypatch.setenv("SERVICE_TICKET_LIFETIME_SECONDS", "600")
    monkeypatch.setenv("SERVICE_ID", "service-server")

    as_mod.reset_user_store()

    return {
        "as_client": TestClient(as_mod.app),
        "tgs_client": TestClient(tgs_mod.app),
        "ss_client": TestClient(ss_mod.app),
    }


def test_complete_kerberos_sso_happy_path(e2e_env):
    """
    Validates complete end-to-end user login to protected service access:
    Client -> AS -> TGS -> Service Server
    """
    as_client = e2e_env["as_client"]
    tgs_client = e2e_env["tgs_client"]
    ss_client = e2e_env["ss_client"]

    # Step 1: User authenticates with AS
    as_resp = as_client.post("/as/authenticate", json={
        "username": "alice",
        "password": "password123"
    })
    assert as_resp.status_code == 200, as_resp.text
    as_data = as_resp.json()
    tgt = as_data["tgt"]
    assert "session_key" in as_data

    # Step 2: User presents TGT to TGS to request access to "service-server"
    now = int(time.time())
    tgs_resp = tgs_client.post("/tgs/service-ticket", json={
        "tgt": tgt,
        "service_id": "service-server",
        "timestamp": now
    })
    assert tgs_resp.status_code == 200, tgs_resp.text
    tgs_data = tgs_resp.json()
    service_ticket = tgs_data["service_ticket"]

    # Step 3: User presents Service Ticket to Service Server (Group 4)
    ss_resp = ss_client.post("/service/access", json={
        "service_ticket": service_ticket,
        "timestamp": now
    })
    assert ss_resp.status_code == 200, ss_resp.text
    ss_data = ss_resp.json()

    assert ss_data["granted"] is True
    assert ss_data["client_id"] == "alice"
    assert ss_data["service"] == "service-server"
    assert "Protected resource data" in ss_data["resource"]


def test_e2e_tampered_tgt_fails_at_tgs(e2e_env):
    """Tampering with TGT stops flow at TGS stage."""
    as_client = e2e_env["as_client"]
    tgs_client = e2e_env["tgs_client"]

    # Get valid TGT
    as_resp = as_client.post("/as/authenticate", json={
        "username": "alice",
        "password": "password123"
    })
    tgt = as_resp.json()["tgt"]

    # Tamper with TGT
    raw_ct = bytearray(base64.b64decode(tgt))
    raw_ct[10] ^= 0xFF
    tampered_tgt = base64.b64encode(raw_ct).decode("utf-8")

    # Present to TGS -> must be rejected
    tgs_resp = tgs_client.post("/tgs/service-ticket", json={
        "tgt": tampered_tgt,
        "service_id": "service-server"
    })
    assert tgs_resp.status_code == 401


def test_e2e_tampered_service_ticket_fails_at_service_server(e2e_env):
    """Tampering with Service Ticket stops access at Service Server stage."""
    as_client = e2e_env["as_client"]
    tgs_client = e2e_env["tgs_client"]
    ss_client = e2e_env["ss_client"]

    # Get valid TGT
    as_resp = as_client.post("/as/authenticate", json={
        "username": "bob",
        "password": "secret456"
    })
    tgt = as_resp.json()["tgt"]

    # Get valid Service Ticket
    tgs_resp = tgs_client.post("/tgs/service-ticket", json={
        "tgt": tgt,
        "service_id": "service-server"
    })
    service_ticket = tgs_resp.json()["service_ticket"]

    # Tamper with Service Ticket
    raw_st = bytearray(base64.b64decode(service_ticket))
    raw_st[12] ^= 0xFF
    tampered_st = base64.b64encode(raw_st).decode("utf-8")

    # Present to Service Server -> must be rejected
    ss_resp = ss_client.post("/service/access", json={
        "service_ticket": tampered_st
    })
    assert ss_resp.status_code == 401
