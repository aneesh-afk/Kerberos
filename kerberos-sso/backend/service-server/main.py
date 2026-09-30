"""
Service Server — Group 4 (Sanket)

Validates Service Tickets and grants access to a protected resource.

Run: uvicorn main:app --reload --port 8003
"""

import base64
import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel

# Ensure project root is in sys.path so backend.security can be imported cleanly
_project_root = Path(__file__).resolve().parents[2]
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from backend.security import crypto_utils
from backend.security.crypto_utils import DecryptionError

app = FastAPI(title="Service Server")


class AccessRequest(BaseModel):
    service_ticket: str
    timestamp: Optional[int] = None


def get_tgs_service_key() -> bytes:
    """
    Reads and decodes the TGS-Service shared key from the environment.
    Expected format: Base64-encoded 32-byte AES-256 key.

    Returns:
        bytes: Decoded 32-byte symmetric key.

    Raises:
        HTTPException(500): If key is missing, invalid base64, or not 32 bytes.
    """
    key_b64 = os.getenv("TGS_SERVICE_SHARED_KEY")
    if not key_b64:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="TGS_SERVICE_SHARED_KEY environment variable is not configured on the service server.",
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
    """
    Retrieves the clock skew tolerance in seconds from environment.
    Defaults to 300 seconds (5 minutes) for development.
    """
    try:
        return int(os.getenv("KERBEROS_CLOCK_SKEW_SECONDS", 300))
    except ValueError:
        return 300


@app.get("/health")
def health():
    """Health check endpoint confirming service status."""
    return {
        "status": "healthy",
        "service": "kerberos-service-server",
    }


@app.post("/service/access")
def access(req: AccessRequest):
    """
    Validate encrypted Kerberos Service Ticket and grant access to protected resource.

    Expects:
        req.service_ticket: Base64-encoded ciphertext produced by crypto_utils.encrypt()
                            encrypting the JSON Service Ticket payload.
        req.timestamp: (Optional) Request timestamp for client replay detection.

    Returns:
        JSON object granting access with protected resource payload.
    """
    # 1. Read and validate configured server key
    key = get_tgs_service_key()

    # 2. Decode incoming Base64 ciphertext
    try:
        ticket_ciphertext = base64.b64decode(req.service_ticket.strip())
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid base64 encoding for service_ticket.",
        )

    # 3. Decrypt ticket using Group 4 crypto_utils
    try:
        decrypted_bytes = crypto_utils.decrypt(ticket_ciphertext, key)
    except DecryptionError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or tampered service ticket.",
        )

    # 4. Parse decrypted JSON ticket
    try:
        ticket_data = json.loads(decrypted_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed ticket JSON payload.",
        )

    if not isinstance(ticket_data, dict):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Ticket payload must be a JSON object.",
        )

    # 5. Validate required ticket fields
    required_fields = ["client_id", "service_id", "session_key", "issued_at", "expiry"]
    for field in required_fields:
        if field not in ticket_data or ticket_data[field] is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Missing required ticket field: '{field}'.",
            )

    client_id = ticket_data["client_id"]
    service_id = ticket_data["service_id"]
    session_key = ticket_data["session_key"]
    issued_at = ticket_data["issued_at"]
    expiry = ticket_data["expiry"]

    # Validate field types
    if not isinstance(client_id, str) or not client_id.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client_id field in ticket.",
        )
    if not isinstance(service_id, str) or not service_id.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid service_id field in ticket.",
        )
    if not isinstance(session_key, str) or not session_key.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid session_key field in ticket.",
        )
    if not isinstance(issued_at, (int, float)) or not isinstance(expiry, (int, float)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Ticket timestamps must be numeric.",
        )

    # Validate target service_id matches this service
    expected_service_id = os.getenv("SERVICE_ID", "service-server")
    if service_id != expected_service_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Ticket issued for '{service_id}', not '{expected_service_id}'.",
        )

    # 6. Validate ticket lifetime & clock skew
    now = int(time.time())
    clock_skew = get_clock_skew_seconds()

    if expiry <= issued_at:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid ticket lifetime: expiry must be greater than issued_at.",
        )

    # Reject if ticket is not yet valid (issued too far in the future)
    if now < (issued_at - clock_skew):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Ticket is not yet valid outside allowed clock skew.",
        )

    # Reject if ticket has expired
    if now > (expiry + clock_skew):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Ticket has expired.",
        )

    # 7. Validate request timestamp if provided (authenticator freshness)
    if req.timestamp is not None:
        if abs(now - req.timestamp) > clock_skew:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Request timestamp outside allowed clock skew.",
            )

    # 8. Grant access to protected resource
    return {
        "granted": True,
        "service": service_id,
        "client_id": client_id,
        "resource": "Protected resource data: access granted to confidential service.",
        "session_key": session_key,
    }
