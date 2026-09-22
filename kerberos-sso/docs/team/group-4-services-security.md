# Group 4 — Services & Security (Phase 1)

Members: Sanket, Akshay
Folders you own: backend/service-server/, backend/security/

You own the crypto contract everyone else builds on — ship backend/security first, even in
a rough form, so Group 1 and 3 aren't blocked.

## What you're building

- Cryptography module (backend/security/crypto_utils.py): implement Phase 1
  functions listed in docs/crypto-interface.md — generate_key, encrypt, decrypt,
  hash_password, verify_password. Write a small unit test per function.
- Service Server Skeleton (backend/service-server/): Stand up the basic FastAPI
  app with a /health endpoint.

*Note: HMAC, Replay protection, and the actual /service/access ticket validation are deferred to Phase 2.*

## First tasks

1. Akshay: implement and commit crypto_utils.py Phase 1 functions first — this is the project's single
   biggest bottleneck if it's late. Post in the group chat the moment it's usable, even before
   every function is polished.
2. Sanket: stand up backend/service-server (port 8003) with /health.

## Depends on

- Group 3's TGT Ticket shape (what fields are inside, what key encrypts it) for testing.

## Others depend on you for

- Everyone (Groups 1, 2 indirectly, 3) needs crypto_utils.py before their tickets/passwords
  actually work end-to-end. This is the module to prioritize.
