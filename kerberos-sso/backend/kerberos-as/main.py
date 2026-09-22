"""
Kerberos Authentication Server (AS) — Group 3 (Sahil)

Verifies user credentials and issues a TGT (Ticket Granting Ticket) encrypted with the
AS<->TGS shared key. Import crypto primitives from backend.security.crypto_utils — do not
write your own encryption here.

Run: uvicorn main:app --reload --port 8001
"""
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Kerberos AS")


class AuthenticateRequest(BaseModel):
    username: str
    password_hash: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/as/authenticate")
def authenticate(req: AuthenticateRequest):
    # TODO:
    # 1. Look up user (via backend/database)
    # 2. Verify password_hash with crypto_utils.verify_password
    # 3. Build TGT payload {client_id, issued_at, expiry} per docs/crypto-interface.md
    # 4. Encrypt with crypto_utils.encrypt(payload, AS_TGS_SHARED_KEY)
    return {"tgt": "TODO", "tgt_expiry": "TODO"}
