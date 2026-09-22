"""
Kerberos Ticket Granting Server (TGS) — Group 3 (Bhumika)

Validates an incoming TGT and issues a Service Ticket encrypted with the TGS<->Service
shared key, plus a fresh session key. Import crypto primitives from
backend.security.crypto_utils.

Run: uvicorn main:app --reload --port 8002
"""
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Kerberos TGS")


class ServiceTicketRequest(BaseModel):
    tgt: str
    service_id: str
    timestamp: int


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/tgs/service-ticket")
def service_ticket(req: ServiceTicketRequest):
    # TODO:
    # 1. Decrypt req.tgt with crypto_utils.decrypt(tgt, AS_TGS_SHARED_KEY)
    # 2. Check expiry + timestamp (replay protection — see docs/crypto-interface.md)
    # 3. Build Service Ticket payload, encrypt with TGS_SERVICE_SHARED_KEY
    return {"service_ticket": "TODO", "expiry": "TODO"}
