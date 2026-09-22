# API Contracts (Phase 1)

These are the endpoints each service should expose so other groups can start integrating
against them immediately, even before your internal logic is finished (return mock/dummy JSON
first if needed).

## Core API (Group 1) — backend/core-api, port 8000

| Method | Path | Body | Returns |
|---|---|---|---|
| POST | /auth/register | {username, password} | {user_id} |
| POST | /auth/login | {username, password} | {session_token} (internally calls AS) |
| POST | /auth/logout | — (session token in header) | 204 |
| GET | /health | — | {status: "ok"} |

*Note: /services endpoint is deferred to Phase 2.*

## Kerberos AS (Group 3) — backend/kerberos-as, port 8001

| Method | Path | Body | Returns |
|---|---|---|---|
| POST | /as/authenticate | {username, password_hash} | {tgt, tgt_expiry} (TGT encrypted per crypto-interface.md) |
| GET | /health | — | {status: "ok"} |

## Phase 2 Endpoints (Do Not Implement Yet)

- Kerberos TGS: /tgs/service-ticket
- Service Server: /service/access

## Notes

- Every endpoint should return proper HTTP status codes (401 for bad credentials, 403 for
  invalid/expired ticket, 429 if you add rate limiting for anomaly detection, etc.) — not a
  200 with an error message buried in the body.
- Add a /health endpoint to every service first — it's the fastest way for teammates to
  confirm your service is up before wiring anything else.
