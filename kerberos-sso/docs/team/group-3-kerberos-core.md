# Group 3 — Kerberos Core (Phase 1)

Members: Sahil, Bhumika
Folders you own: backend/kerberos-as/

This is the heart of the "Kerberos" part of the project. Read docs/crypto-interface.md
fully before starting — you build tickets using Group 4's encrypt/decrypt/etc., not your
own crypto code.

## What you're building

- Authentication Server (AS): /as/authenticate — verifies the user (via
  Group 1's database/user store), generates a TGT (encrypted JSON payload — see
  crypto-interface.md for the exact shape), returns it with an expiry.

*Note: Ticket Granting Server (TGS) is deferred to Phase 2.*

## First tasks

1. Stand up AS service (backend/kerberos-as port 8001), confirm /health.
2. Agree on the exact TGT JSON fields with each other and with Group 4
   (the shape in crypto-interface.md is a starting point, not final).
3. Build /as/authenticate against Group 1's user table (ask Group 1 for read access /
   the schema).

## Depends on

- Group 4's crypto_utils.py (encrypt, decrypt, generate_key) — this blocks real ticket
  generation, so coordinate early; build your endpoint skeletons and request/response shapes
  in parallel while waiting.
- Group 1's user table/schema for AS to check credentials against.
- The AS↔TGS shared key, defined in .env (AS_TGS_SHARED_KEY).

## Others depend on you for

- Group 1 (Core API) needs your AS response shape to finish /auth/login.
