# Group 3 — Kerberos Core (Phase 1)

Members: Sahil, Bhumika  
Folders owned: `backend/kerberos-as/`, `backend/kerberos-tgs/`

Status: **Implemented & Verified** (51 automated tests passing across system)

---

## What is Built

- **Bhumika — Authentication Server (AS — Port 8001):**
  - Endpoint: `POST /as/authenticate`
  - Verifies credentials using Argon2id (`crypto_utils.verify_password`).
  - Supports fallback user store (`alice`, `bob`) and integrates dynamically with Group 1's database once delivered.
  - Generates 32-byte Client↔TGS session key.
  - Generates and encrypts TGT with `AS_TGS_SHARED_KEY` (AES-256-GCM).
  - Returns `{tgt, tgt_expiry, session_key, client_id}`.

- **Sahil — Ticket Granting Server (TGS — Port 8002):**
  - Endpoint: `POST /tgs/service-ticket`
  - Base64-decodes and decrypts incoming TGT with `AS_TGS_SHARED_KEY`.
  - Rejects tampered, corrupt, or foreign-keyed TGTs with HTTP 401 (`DecryptionError`).
  - Validates ticket expiration, clock skew window ($\pm 300\text{s}$), and client request freshness timestamp (replay defense).
  - Issues 32-byte Client↔Service session key.
  - Generates Service Ticket matching Group 4 contract, encrypted with `TGS_SERVICE_SHARED_KEY` (AES-256-GCM).
  - Returns `{service_ticket, expiry, session_key, service_id}`.

---

## Wire Contracts & Ticket Formats

### 1. TGT Payload (Encrypted with `AS_TGS_SHARED_KEY`):
```json
{
  "client_id": "alice",
  "tgs_id": "kerberos-tgs",
  "session_key": "base64_encoded_32_byte_key",
  "issued_at": 1790000000,
  "expiry": 1790003600
}
```

### 2. Service Ticket Payload (Encrypted with `TGS_SERVICE_SHARED_KEY`):
```json
{
  "client_id": "alice",
  "service_id": "service-server",
  "session_key": "base64_encoded_32_byte_key",
  "issued_at": 1790000000,
  "expiry": 1790000600
}
```

---

## How to Run & Test

```powershell
# 1. Run all tests (AS, TGS, Service Server, E2E)
pytest backend/ -v

# 2. Run standalone demonstration script
python scripts/verify_kerberos_pipeline.py

# 3. Launch live servers
# Terminal 1:
python -m uvicorn main:app --app-dir backend/kerberos-as --reload --port 8001
# Terminal 2:
python -m uvicorn main:app --app-dir backend/kerberos-tgs --reload --port 8002
# Terminal 3:
python -m uvicorn main:app --app-dir backend/service-server --reload --port 8003
```
