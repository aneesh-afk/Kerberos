# Crypto Interface Contract (owned by Group 4 — Sanket, Akshay)

Read this before writing any AS, Core API, or Service Server code that touches
encryption, hashing, or tickets. Everyone imports these functions from
backend/security instead of writing their own crypto.

## Required functions (Phase 1) (backend/security/crypto_utils.py)

def generate_key() -> bytes:
    """Generate a new symmetric key (AES-256). Used for long-term principal keys
    and short-term session keys embedded in tickets."""

def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES encryption (e.g. AES-GCM) of plaintext under key. Return format should
    embed whatever nonce/IV is needed to decrypt (e.g. nonce + ciphertext + tag)."""

def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Inverse of encrypt(). Raise a clear exception (e.g. DecryptionError) on
    tamper/failure — don't return garbage bytes silently."""

def hash_password(password: str) -> str:
    """Password hashing for storage (e.g. bcrypt/argon2) — NOT for tickets."""

def verify_password(password: str, password_hash: str) -> bool:
    """Verify a plaintext password against a stored hash."""

## Ticket structure (what AS actually encrypts)

Agree on a concrete JSON shape before coding, e.g.:

{
  "client_id": "string",
  "issued_at": "unix_timestamp",
  "expiry": "unix_timestamp"
}

Serialize to bytes (e.g. json.dumps(...).encode()), then encrypt() that with the
appropriate shared key.

## Phase 2 Features (Do Not Implement Yet)

- HMAC generation and verification (generate_hmac, verify_hmac)
- Replay & tamper protection (Clock skew tolerance, Authenticators)
- Service Ticket decryption by Service Server

## Deliverable order

1. Group 4 implements and shares crypto_utils.py Phase 1 functions with unit tests — as early
   as possible, even before the full security module is done.
2. Groups 1, 3, 4 import it and build tickets on top.
3. Any change to a function's signature after others depend on it → flag in the group chat
   immediately.
