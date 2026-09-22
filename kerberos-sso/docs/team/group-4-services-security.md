# Group 4 — Services & Security

Members: Sanket, Akshay
Folders you own: backend/service-server/, backend/security/

You own the crypto contract everyone else builds on — ship backend/security first, even in
a rough form, so Groups 1 and 3 aren't blocked.

## What you're building

- Akshay — Cryptography module (backend/security/crypto_utils.py): implement every
  function listed in docs/crypto-interface.md — generate_key, encrypt, decrypt,
  generate_hmac, verify_hmac, hash_password, verify_password. Write a small unit test
  per function so others can trust it without reading the implementation.
- Sanket — Service Server & Security enforcement (backend/service-server/):
  /service/access — decrypts and validates an incoming Service Ticket using
  crypto_utils, checks expiry/timestamp (replay protection), and grants/denies access to a
  (dummy, for demo purposes) protected resource.

## First tasks

1. Akshay: implement and commit crypto_utils.py first — this is the project's single
   biggest bottleneck if it's late. Post in the group chat the moment it's usable, even before
   every function is polished.
2. Sanket: stand up backend/service-server (port 8003) with /health, then build
   /service/access against a mock Service Ticket shape while waiting for the real
   crypto_utils and Group 3's actual ticket format.
3. Together: write down the exact replay-protection rule you're using (expiry window, clock
   skew tolerance) in docs/crypto-interface.md so Group 3 implements the same rule on the
   issuing side.

## Depends on

- Group 3's Service Ticket shape (what fields are inside, what key encrypts it).

## Others depend on you for

- Everyone (Groups 1, 2 indirectly, 3) needs crypto_utils.py before their tickets/passwords
  actually work end-to-end. This is the module to prioritize in week 1.
