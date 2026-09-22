# Architecture & Request Flow

## Services and ports (local dev, running with uvicorn directly)

| Service | Folder | Port | Owner |
|---|---|---|---|
| Core API | backend/core-api | 8000 | Group 1 |
| Kerberos AS | backend/kerberos-as | 8001 | Group 3 |
| Kerberos TGS | backend/kerberos-tgs | 8002 | Group 3 |
| Service Server | backend/service-server | 8003 | Group 4 |
| React client | frontend/client | 3000 | Group 2 |

Inside Docker Compose, services reach each other by container name on internal port 8000
(e.g. http://kerberos-as:8000) — the host ports above (8001/8002/8003) are only for you to
curl a service directly while developing.

## End-to-end flow

1. User logs in (React auth pages → Core API /auth/login).
2. Core API → AS: forwards credentials (or a hash) to the AS's /as/authenticate endpoint.
3. AS verifies the user (via backend/database), generates a TGT encrypted with the
   AS↔TGS shared key, and returns it to Core API, which relays it to the client/session.
4. Client wants a service → Core API (or client directly) calls TGS /tgs/service-ticket
   with the TGT + requested service name.
5. TGS validates the TGT (decrypt, check expiry, check timestamp for replay), issues a
   Service Ticket encrypted with the TGS↔Service shared key.
6. Client presents the Service Ticket to the target Service Server's /service/access.
7. Service Server validates the ticket (decrypt, check expiry/timestamp/HMAC) and
   grants/denies access.
8. Every AS/TGS/Service Server decision (success or failure) is logged. Group 1's Core API (or
   a dedicated logging table) records failed attempts for the anomaly detection piece.

## Anomaly detection hook

Failed-login and unusual-access data lives wherever Group 1 logs auth events (a login_events
table is the simplest start — see backend/database/README.md). Whoever builds anomaly
detection (flag repeated failures, odd timing/IP patterns) reads from that table — agree on its
schema early so it isn't a blocker later.

## Diagram

        ┌────────────┐        1. login            ┌──────────────┐
        │  React app │ ─────────────────────────▶ │   Core API   │
        └─────┬──────┘                            └──────┬───────┘
              │ 3. TGT (via Core API/session)              │ 2. authenticate
              │                                            ▼
              │                                   ┌──────────────┐
              │                                   │  Kerberos AS │
              │                                   └──────┬───────┘
              │ 4. request service ticket                │ (shares DB / user store)
              ▼                                            ▼
        ┌──────────────┐   5. service ticket      ┌──────────────┐
        │ Kerberos TGS │ ◀────────────────────────▶ │   Database   │
        └──────┬───────┘                          └──────────────┘
               │ 6. present service ticket
               ▼
        ┌────────────────┐
        │ Service Server │  7. grant/deny access
        └────────────────┘
