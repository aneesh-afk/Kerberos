# Kerberos TGS (Group 3 — Sahil)

**Port:** 8002  
**Owned by:** Sahil  

The **Ticket Granting Server (TGS)** validates incoming TGTs, verifies replay prevention and expiration windows, and issues encrypted **Service Tickets** compatible with Group 4's Service Server.

---

## Quickstart

```powershell
# From kerberos-sso root
uvicorn backend.kerberos-tgs.main:app --reload --port 8002
```

---

## API Endpoints

### 1. Health Check
`GET /health`
```json
{
  "status": "ok",
  "service": "kerberos-tgs",
  "keys_configured": true
}
```

### 2. Request Service Ticket
`POST /tgs/service-ticket`

**Request:**
```json
{
  "tgt": "base64_encoded_encrypted_tgt",
  "service_id": "service-server",
  "timestamp": 1790000000
}
```

**Response (HTTP 200):**
```json
{
  "service_ticket": "base64_encoded_encrypted_service_ticket",
  "expiry": 1790000600,
  "session_key": "base64_encoded_client_service_key",
  "service_id": "service-server"
}
```

---

## Running Tests

```powershell
pytest backend/kerberos-tgs/tests/test_tgs.py -v
```
