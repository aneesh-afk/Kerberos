"""
Kerberos Ticket Granting Server (TGS) — Group 3 (Sahil)

Validates an incoming TGT (Ticket Granting Ticket) from the client,
enforces replay and expiration rules, and issues a Service Ticket encrypted
with the TGS<->Service shared key, plus a fresh session key for that service.
Import crypto primitives from backend.security.crypto_utils.

Run: uvicorn main:app --reload --port 8002
"""

import base64
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

# Ensure project root is in sys.path so backend modules can be imported cleanly
_project_root = Path(__file__).resolve().parents[2]
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

load_dotenv(_project_root / ".env")

from backend.security import crypto_utils
from backend.security.crypto_utils import DecryptionError

logger = logging.getLogger("kerberos_tgs")
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="Kerberos TGS")


# ---------------------------------------------------------------------------
# Key and Configuration Helpers
# ---------------------------------------------------------------------------
def get_as_tgs_shared_key() -> bytes:
    """Reads and decodes the AS-TGS shared key from the environment."""
    key_b64 = os.getenv("AS_TGS_SHARED_KEY")
    if not key_b64:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="AS_TGS_SHARED_KEY environment variable is not configured.",
        )
    try:
        key_bytes = base64.b64decode(key_b64.strip())
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to decode Base64 AS_TGS_SHARED_KEY.",
        ) from exc

    if len(key_bytes) != 32:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Decoded AS_TGS_SHARED_KEY must be exactly 32 bytes, got {len(key_bytes)}.",
        )

    return key_bytes


def get_tgs_service_shared_key() -> bytes:
    """Reads and decodes the TGS-Service shared key from the environment."""
    key_b64 = os.getenv("TGS_SERVICE_SHARED_KEY")
    if not key_b64:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="TGS_SERVICE_SHARED_KEY environment variable is not configured.",
        )
    try:
        key_bytes = base64.b64decode(key_b64.strip())
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to decode Base64 TGS_SERVICE_SHARED_KEY.",
        ) from exc

    if len(key_bytes) != 32:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Decoded TGS_SERVICE_SHARED_KEY must be exactly 32 bytes, got {len(key_bytes)}.",
        )

    return key_bytes


def get_clock_skew_seconds() -> int:
    """Retrieves clock skew tolerance in seconds (default 300s / 5 minutes)."""
    try:
        return int(os.getenv("KERBEROS_CLOCK_SKEW_SECONDS", 300))
    except ValueError:
        return 300


def get_service_ticket_lifetime_seconds() -> int:
    """Retrieves Service Ticket validity lifetime in seconds (default 600s / 10 minutes)."""
    try:
        return int(os.getenv("SERVICE_TICKET_LIFETIME_SECONDS", 600))
    except ValueError:
        return 600


# ---------------------------------------------------------------------------
# Request and Response Schemas
# ---------------------------------------------------------------------------
class ServiceTicketRequest(BaseModel):
    tgt: str = Field(..., description="Base64-encoded encrypted TGT issued by AS")
    service_id: str = Field(..., description="Target service identifier (e.g. 'service-server')")
    timestamp: Optional[int] = Field(None, description="Optional request timestamp for replay protection")


class ServiceTicketResponse(BaseModel):
    service_ticket: str = Field(..., description="Base64-encoded encrypted Service Ticket")
    expiry: int = Field(..., description="Unix epoch timestamp when Service Ticket expires")
    session_key: str = Field(..., description="Base64-encoded 32-byte Client-Service session key")
    service_id: str = Field(..., description="Target service identifier")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/health")
def health():
    """Health check endpoint confirming service status and keys availability."""
    k_as_tgs = get_as_tgs_shared_key()
    k_tgs_svc = get_tgs_service_shared_key()
    return {
        "status": "ok",
        "service": "kerberos-tgs",
        "keys_configured": bool(k_as_tgs and k_tgs_svc),
    }


@app.post("/tgs/service-ticket", response_model=ServiceTicketResponse)
def service_ticket(req: ServiceTicketRequest):
    """
    Validate an incoming TGT and issue an encrypted Kerberos Service Ticket.

    Flow:
    1. Base64-decode the incoming TGT ciphertext.
    2. Decrypt the TGT payload using AS_TGS_SHARED_KEY (catches tampering/wrong key).
    3. Parse the JSON payload and ensure required fields (client_id, session_key, issued_at, expiry).
    4. Enforce expiration and lifetime bounds including clock skew tolerance.
    5. Enforce request timestamp freshness (replay attack prevention).
    6. Validate requested service_id.
    7. Generate a fresh Client<->Service session key.
    8. Build and encrypt the Service Ticket under TGS_SERVICE_SHARED_KEY per Group 4 contract.
    9. Return the Base64 Service Ticket, expiry, and session key.
    """
    if not req.tgt or not req.tgt.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="TGT parameter is required.",
        )

    if not req.service_id or not req.service_id.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="service_id parameter is required.",
        )

    as_tgs_key = get_as_tgs_shared_key()
    tgs_service_key = get_tgs_service_shared_key()
    clock_skew = get_clock_skew_seconds()
    now = int(time.time())

    # 1. Base64-decode TGT
    try:
        tgt_ciphertext = base64.b64decode(req.tgt.strip())
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid base64 encoding for TGT.",
        )

    # 2. Decrypt TGT using AS_TGS_SHARED_KEY
    try:
        decrypted_bytes = crypto_utils.decrypt(tgt_ciphertext, as_tgs_key)
    except DecryptionError:
        logger.warning("TGS rejection: TGT decryption failed (tampered or invalid key).")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or tampered TGT.",
        )

    # 3. Parse JSON payload
    try:
        tgt_data = json.loads(decrypted_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed TGT JSON payload.",
        )

    if not isinstance(tgt_data, dict):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="TGT payload must be a JSON object.",
        )

    # 4. Validate required TGT fields
    required_fields = ["client_id", "session_key", "issued_at", "expiry"]
    for field in required_fields:
        if field not in tgt_data or tgt_data[field] is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Missing required TGT field: '{field}'.",
            )

    client_id = tgt_data["client_id"]
    tgt_session_key = tgt_data["session_key"]
    issued_at = tgt_data["issued_at"]
    expiry = tgt_data["expiry"]

    if not isinstance(client_id, str) or not client_id.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client_id in TGT.",
        )

    if not isinstance(issued_at, (int, float)) or not isinstance(expiry, (int, float)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="TGT timestamps must be numeric.",
        )

    # 5. Enforce lifetime and clock-skew bounds
    if expiry <= issued_at:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid TGT lifetime: expiry must be greater than issued_at.",
        )

    if now < (issued_at - clock_skew):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="TGT is not yet valid outside allowed clock skew.",
        )

    if now > (expiry + clock_skew):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="TGT has expired.",
        )

    # 6. Replay protection: Validate request timestamp freshness if provided
    if req.timestamp is not None:
        if abs(now - req.timestamp) > clock_skew:
            logger.warning("TGS rejection: request timestamp outside allowed clock skew.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Request timestamp outside allowed clock skew.",
            )

    # 7. Validate target service_id
    target_service = req.service_id.strip()
    configured_service = os.getenv("SERVICE_ID", "service-server")
    # Allow known service or configured service_id
    allowed_services = {configured_service, "service-server", "demo-service"}
    if target_service not in allowed_services:
        logger.warning("TGS rejection: unrecognized service_id '%s'.", target_service)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unrecognized service_id '{target_service}'.",
        )

    # 8. Mint fresh Client<->Service session key (32 bytes Base64-encoded)
    service_session_key_bytes = crypto_utils.generate_key()
    service_session_key = base64.b64encode(service_session_key_bytes).decode("utf-8")

    # 9. Build Service Ticket payload conforming to Group 4 contract
    st_lifetime = get_service_ticket_lifetime_seconds()
    st_expiry = now + st_lifetime

    service_ticket_payload = {
        "client_id": client_id,
        "service_id": target_service,
        "session_key": service_session_key,
        "issued_at": now,
        "expiry": st_expiry,
    }

    # 10. Encrypt Service Ticket under TGS_SERVICE_SHARED_KEY using AES-256-GCM
    st_payload_bytes = json.dumps(service_ticket_payload).encode("utf-8")
    st_ciphertext = crypto_utils.encrypt(st_payload_bytes, tgs_service_key)
    service_ticket_b64 = base64.b64encode(st_ciphertext).decode("utf-8")

    logger.info("Issued Service Ticket for client '%s' to service '%s'.", client_id, target_service)

    return ServiceTicketResponse(
        service_ticket=service_ticket_b64,
        expiry=st_expiry,
        session_key=service_session_key,
        service_id=target_service,
    )
