# Kerberos AS (Group 3 — Bhumika)

**Port:** 8001  
**Owned by:** Bhumika  

The **Authentication Server (AS)** verifies user credentials and issues an encrypted **Ticket Granting Ticket (TGT)** plus a Client↔TGS session key.

---

## Quickstart

```powershell
# From kerberos-sso root
uvicorn backend.kerberos-as.main:app --reload --port 8001
```

---

## API Endpoints

### 1. Health Check
`GET /health`
```json
{
  "status": "ok",
  "service": "kerberos-as",
  "key_configured": true
}
```

### 2. Authenticate
`POST /as/authenticate`

**Request:**
```json
{
  "username": "alice",
  "password": "password123"
}
```
*(Or pass `"password_hash": "..."` if already hashed).*

**Response (HTTP 200):**
```json
{
  "tgt": "base64_encoded_encrypted_tgt",
  "tgt_expiry": 1790003600,
  "session_key": "base64_encoded_client_tgs_key",
  "client_id": "alice"
}
```

---

## Running Tests

```powershell
pytest backend/kerberos-as/tests/test_as.py -v
```
