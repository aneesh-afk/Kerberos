# Group 2 — Frontend Development (Phase 1)

Members: Harsh, Videsh
Folder you own: frontend/client/

This is one React app shared by both of you (not two separate apps) — split it by page area.

## What you're building

- Authentication UI (src/pages/auth/): login, registration, logout screens.
  Calls Core API's /auth/login, /auth/register, /auth/logout.

*Note: Dashboard & Services UI are deferred to Phase 2.*

## First tasks

1. cd frontend/client && npm install && npm run dev — confirm the starter app runs.
2. Set up client-side routing: /login, /register.
3. Point API calls at VITE_CORE_API_URL (from .env) — never hardcode localhost:8000
   in components, so this still works once deployed.
4. Build against the contracts in docs/api-contracts.md using mock responses first — you
   don't need to wait for Core API to be finished to build the UI.

## Depends on

- Core API's /auth/* endpoints (Group 1) — contract is already written, so
  start against a mock and swap in the real calls once Group 1's routes are live.

## Suggested libraries

- react-router-dom for routing
- axios or fetch for API calls
