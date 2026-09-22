# Group 1 — System Architecture, Backend & Database

Members: Swayam, Mayur, Saish
Folders you own: backend/core-api/, backend/database/

## What you're building

The backbone the rest of the app plugs into:

- System Architecture & Backend Foundation — the Core API service itself: project
  structure, config loading (.env), routing, error handling conventions, health checks.
- User Authentication Backend — /auth/register, /auth/login, /auth/logout in Core
  API. /auth/login doesn't check passwords itself — it forwards to the Kerberos AS
  (Group 3) and turns the result into a session for the frontend to use.
- Database & Key Management — schema for users, sessions, principals' long-term keys, and
  a login_events table (timestamp, user, success/failure, IP) that the anomaly detection
  work will read from later.

## Suggested split (adjust as you like)

- One person: Core API skeleton + /health, /auth/register, /auth/login/logout routes
- One person: Database schema (users, sessions, keys, login_events) + connection/session layer
- One person: Wiring Core API ↔ AS (the actual HTTP call to /as/authenticate) + session
  token issuance/validation for the frontend

## First tasks

1. Stand up backend/core-api (uvicorn main:app --reload --port 8000), confirm /health works.
2. Design and create the schema in backend/database — at minimum: users, sessions,
   login_events. Share the schema in the group chat before anyone else builds against it.
3. Wire /auth/login to call Group 3's AS /as/authenticate (mock its response until AS is
   ready — see docs/api-contracts.md).

## Depends on

- Group 4's hash_password/verify_password from backend/security for storing credentials.
- Group 3's AS endpoint contract (already in docs/api-contracts.md) — you can build against
  the mock response shape without waiting for AS to be finished.

## Others depend on you for

- The users/login_events schema — Groups 3 and whoever builds anomaly detection need this
  early. Post it as soon as it's stable, even before it's final.
