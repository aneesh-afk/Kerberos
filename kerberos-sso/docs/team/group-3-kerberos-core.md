# Group 3 — Kerberos Core

Members: Sahil, Bhumika
Folders you own: backend/kerberos-as/, backend/kerberos-tgs/

This is the heart of the "Kerberos" part of the project. Read docs/crypto-interface.md
fully before starting — you build tickets using Group 4's encrypt/decrypt/etc., not your
own crypto code.

## What you're building

- Sahil — Authentication Server (AS): /as/authenticate — verifies the user (via
  Group 1's database/user store), generates a TGT (encrypted JSON payload — see
  crypto-interface.md for the exact shape), returns it with an expiry.
- Bhumika — Ticket Granting Server (TGS): /tgs/service-ticket — decrypts and validates
  an incoming TGT (checks expiry, checks it hasn't been tampered with), then issues a
  Service Ticket encrypted under the TGS↔Service shared key, plus a fresh session key
  for the client to use with that service.

## First tasks

1. Stand up both services (backend/kerberos-as port 8001, backend/kerberos-tgs port 8002),
   confirm /health on each.
2. Agree on the exact TGT and Service Ticket JSON fields with each other and with Group 4
   (the shape in crypto-interface.md is a starting point, not final).
3. AS: build /as/authenticate against Group 1's user table (ask Group 1 for read access /
   the schema).
4. TGS: build /tgs/service-ticket, including expiry + timestamp validation for replay
   protection.

## Depends on

- Group 4's crypto_utils.py (encrypt, decrypt, generate_key) — this blocks real ticket
  generation, so coordinate early; build your endpoint skeletons and request/response shapes
  in parallel while waiting.
- Group 1's user table/schema for AS to check credentials against.
- The AS↔TGS shared key and TGS↔Service shared key, defined in .env (AS_TGS_SHARED_KEY,
  TGS_SERVICE_SHARED_KEY).

## Others depend on you for

- Group 1 (Core API) needs your AS response shape to finish /auth/login.
- Group 4 (Service Server) needs your Service Ticket shape to validate it.
