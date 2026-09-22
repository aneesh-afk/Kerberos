# Architecture & Request Flow (Phase 1)

## Services and ports (local dev, running with uvicorn directly)

| Service | Folder | Port | Owner |
|---|---|---|---|
| Core API | backend/core-api | 8000 | Group 1 |
| Kerberos AS | backend/kerberos-as | 8001 | Group 3 |
| React client | frontend/client | 3000 | Group 2 |

*Note: TGS and Service Server are deferred to Phase 2.*

Inside Docker Compose, services reach each other by container name on internal port 8000
(e.g. http://kerberos-as:8000) — the host ports above (8001) are only for you to
curl a service directly while developing.

## End-to-end flow

1. User logs in (React auth pages → Core API /auth/login).
2. Core API → AS: forwards credentials (or a hash) to the AS's /as/authenticate endpoint.
3. AS verifies the user (via backend/database), generates a TGT encrypted with the
   AS↔TGS shared key, and returns it to Core API, which relays it to the client/session.

*Note: Steps 4-7 (TGS and Service Ticket validation) are deferred to Phase 2.*

## Diagram

        ┌────────────┐        1. login            ┌──────────────┐
        │  React app │ ─────────────────────────▶ │   Core API   │
        └─────┬──────┘                            └──────┬───────┘
              │ 3. TGT (via Core API/session)              │ 2. authenticate
              │                                            ▼
              │                                   ┌──────────────┐
              │                                   │  Kerberos AS │
              │                                   └──────┬───────┘
              │                                          │ (shares DB / user store)
                                                         ▼
                                                  ┌──────────────┐
                                                  │   Database   │
                                                  └──────────────┘
