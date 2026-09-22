# API Contracts (initial — adjust as you build, but announce changes to the group)

These are the endpoints each service should expose so other groups can start integrating
against them immediately, even before your internal logic is finished (return mock/dummy JSON
first if needed).

## Core API (Group 1) — backend/core-api, port 8000

| Method | Path | Body | Returns |
|---|---|---|---|
| POST | /auth/register | {username, password} | {user_id} |
| POST | /auth/login | {username, password} | {session_token} (internally calls AS) |
| POST | /auth/logout | — (session token in header) | 204 |
| GET | /services | — | [{service_id, name, description}] (list of services user can request tickets for) |
| GET | /health | — | {status: "ok"} |

## Kerberos AS (Group 3) — backend/kerberos-as, port 8001

| Method | Path | Body | Returns |
|---|---|---|---|
| POST | /as/authenticate | {username, password_hash} | {tgt, tgt_expiry} (TGT encrypted per crypto-interface.md) |
| GET | /health | — | {status: "ok"} |

## Kerberos TGS (Group 3) — backend/kerberos-tgs, port 8002

| Method | Path | Body | Returns |
|---|---|---|---|
| POST | /tgs/service-ticket | {tgt, service_id, timestamp} | {service_ticket, expiry} |
| GET | /health | — | {status: "ok"} |

## Service Server (Group 4) — backend/service-server, port 8003

| Method | Path | Body | Returns |
|---|---|---|---|
| POST | /service/access | {service_ticket, timestamp} | {granted: true/false, resource?} |
| GET | /health | — | {status: "ok"} |

## Notes

- Every endpoint should return proper HTTP status codes (401 for bad credentials, 403 for
  invalid/expired ticket, 429 if you add rate limiting for anomaly detection, etc.) — not a
  200 with an error message buried in the body.
- Add a /health endpoint to every service first — it's the fastest way for teammates to
  confirm your service is up before wiring anything else.
- If you need to change a contract (add a field, rename something), post it in the group chat
  and update this file in the same PR.
