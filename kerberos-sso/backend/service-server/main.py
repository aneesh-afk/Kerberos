"""
Service Server — Group 4 (Sanket)

Validates Service Tickets and grants access to a protected resource.

Run: uvicorn main:app --reload --port 8003
"""
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Service Server")


class AccessRequest(BaseModel):
    service_ticket: str
    timestamp: int


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/service/access")
def access(req: AccessRequest):
    # TODO: Decrypt and validate ticket using crypto_utils
    return {"granted": False, "resource": None}
