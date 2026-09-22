"""
Core API — Group 1 (Swayam, Mayur, Saish)

Owns: user registration/login/logout, session issuance, listing available services.
Delegates actual credential verification to the Kerberos AS (Group 3).

Run: uvicorn main:app --reload --port 8000
"""
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Core API")


class RegisterRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/auth/register")
def register(req: RegisterRequest):
    # TODO: hash password with backend.security.crypto_utils.hash_password
    # TODO: insert into users table (backend/database)
    return {"user_id": "TODO"}


@app.post("/auth/login")
def login(req: LoginRequest):
    # TODO: call Kerberos AS's /as/authenticate, turn the TGT into a session
    return {"session_token": "TODO"}


@app.post("/auth/logout")
def logout():
    # TODO: invalidate session
    return {"status": "logged out"}


@app.get("/services")
def list_services():
    # TODO: return real services from the database
    return [{"service_id": "demo-service", "name": "Demo Service", "description": "placeholder"}]
