"""
Kerberos Authentication Server (AS) — Group 3 (Bhumika)

Verifies user credentials (via database or user store) and issues a TGT
(Ticket Granting Ticket) encrypted with the AS<->TGS shared key.
Imports crypto primitives from backend.security.crypto_utils.

Run: uvicorn main:app --reload --port 8001
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

logger = logging.getLogger("kerberos_as")
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="Kerberos AS")

# ---------------------------------------------------------------------------
# Default in-memory user repository (decouples AS from Group 1's DB delivery)
# ---------------------------------------------------------------------------
# Pre-computed Argon2id hashes for standard demo users:
# alice -> "password123", bob -> "secret456"
_DEFAULT_USERS = {
    "alice": {
        "username": "alice",
        "password_hash": crypto_utils.hash_password("password123"),
    },
    "bob": {
        "username": "bob",
        "password_hash": crypto_utils.hash_password("secret456"),
    },
}
_user_store = dict(_DEFAULT_USERS)


def reset_user_store():
    """Resets user store to default state (useful for unit tests)."""
    global _user_store
    _user_store = dict(_DEFAULT_USERS)


def register_user(username: str, password_hash: str):
    """Allows adding/updating users in the AS store."""
    _user_store[username] = {
        "username": username,
        "password_hash": password_hash,
    }


def lookup_user(username: str) -> Optional[dict]:
    """
    Look up user credentials. First attempts to query Group 1's database
    if available, otherwise falls back to local user store.
    """
    try:
        from backend.database import schema as db_schema  # type: ignore
        if hasattr(db_schema, "get_user_by_username"):
            user = db_schema.get_user_by_username(username)
            if user:
                return {
                    "username": getattr(user, "username", username),
                    "password_hash": getattr(user, "password_hash", None),
                }
    except Exception as exc:
        logger.debug("Database lookup skipped/failed (%s), using local store", exc)

    return _user_store.get(username)


# ---------------------------------------------------------------------------
# Environment and Configuration Helpers
# ---------------------------------------------------------------------------
def get_as_tgs_shared_key() -> bytes:
    """
    Reads and decodes the AS-TGS shared key from the environment.
    Expected format: Base64-encoded 32-byte AES-256 key.
    """
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


def get_tgt_lifetime_seconds() -> int:
    """Returns TGT validity lifetime in seconds (default: 3600s / 1 hour)."""
    try:
        return int(os.getenv("TGT_LIFETIME_SECONDS", 3600))
    except ValueError:
        return 3600


# ---------------------------------------------------------------------------
# Request and Response Schemas
# ---------------------------------------------------------------------------
class AuthenticateRequest(BaseModel):
    username: str = Field(..., description="Username requesting authentication")
    password: Optional[str] = Field(None, description="Plaintext password to verify against stored hash")
    password_hash: Optional[str] = Field(None, description="Pre-hashed password (if verified externally)")


class AuthenticateResponse(BaseModel):
    tgt: str = Field(..., description="Base64-encoded encrypted Ticket Granting Ticket")
    tgt_expiry: int = Field(..., description="Unix epoch timestamp when TGT expires")
    session_key: str = Field(..., description="Base64-encoded 32-byte Client-TGS session key")
    client_id: str = Field(..., description="Authenticated client identifier")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/health")
def health():
    """Health check endpoint confirming service status and key availability."""
    key = get_as_tgs_shared_key()
    return {
        "status": "ok",
        "service": "kerberos-as",
        "key_configured": bool(key),
    }


@app.post("/as/authenticate", response_model=AuthenticateResponse)
def authenticate(req: AuthenticateRequest):
    """
    Authenticate a user and issue a Kerberos Ticket Granting Ticket (TGT).

    Flow:
    1. Validate input (must provide password or password_hash).
    2. Retrieve user record from database/store.
    3. Verify credentials via Argon2id (constant-time verification).
    4. Generate a fresh 32-byte symmetric Client<->TGS session key.
    5. Construct TGT payload and encrypt under AS_TGS_SHARED_KEY using AES-256-GCM.
    6. Return Base64-encoded TGT, expiration, and session key.
    """
    if not req.username or not req.username.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username cannot be empty.",
        )

    if not req.password and not req.password_hash:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either 'password' or 'password_hash' must be provided.",
        )

    # 1. Lookup user
    user = lookup_user(req.username.strip())
    if not user:
        # Avoid giving attacker specific feedback whether username exists
        logger.warning("Authentication failed: user '%s' not found.", req.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    stored_hash = user.get("password_hash")
    if not stored_hash:
        logger.error("User '%s' has no stored password hash.", req.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    # 2. Verify credentials
    is_valid = False
    if req.password is not None:
        is_valid = crypto_utils.verify_password(req.password, stored_hash)
    elif req.password_hash is not None:
        # Direct hash matching if caller already computed hash
        is_valid = (req.password_hash == stored_hash)

    if not is_valid:
        logger.warning("Authentication failed: invalid credentials for user '%s'.", req.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    # 3. Read AS-TGS shared key
    as_tgs_key = get_as_tgs_shared_key()

    # 4. Generate fresh 32-byte Client-TGS session key
    session_key_bytes = crypto_utils.generate_key()
    session_key_b64 = base64.b64encode(session_key_bytes).decode("utf-8")

    # 5. Build TGT payload
    now = int(time.time())
    lifetime = get_tgt_lifetime_seconds()
    expiry = now + lifetime

    tgt_payload = {
        "client_id": req.username.strip(),
        "tgs_id": "kerberos-tgs",
        "session_key": session_key_b64,
        "issued_at": now,
        "expiry": expiry,
    }

    # 6. Encrypt TGT with AES-256-GCM using AS_TGS_SHARED_KEY
    payload_bytes = json.dumps(tgt_payload).encode("utf-8")
    ciphertext = crypto_utils.encrypt(payload_bytes, as_tgs_key)
    tgt_b64 = base64.b64encode(ciphertext).decode("utf-8")

    logger.info("Authentication succeeded: issued TGT for user '%s'.", req.username)

    return AuthenticateResponse(
        tgt=tgt_b64,
        tgt_expiry=expiry,
        session_key=session_key_b64,
        client_id=req.username.strip(),
    )
