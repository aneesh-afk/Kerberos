# Crypto Interface Contract (owned by Group 4 — Sanket, Akshay)

Read this before writing any AS, TGS, Core API, or Service Server code that touches
encryption, hashing, or tickets. Everyone imports these functions from
backend/security instead of writing their own crypto. This is the #1 way this kind of
project breaks at integration time — don't let it happen here.

## Required functions (backend/security/crypto_utils.py)

def generate_key() -> bytes:
    """Generate a new symmetric key (AES-256). Used for long-term principal keys
    and short-term session keys embedded in tickets."""

def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES encryption (e.g. AES-GCM) of plaintext under key. Return format should
    embed whatever nonce/IV is needed to decrypt (e.g. nonce + ciphertext + tag)."""

def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Inverse of encrypt(). Raise a clear exception (e.g. DecryptionError) on
    tamper/failure — don't return garbage bytes silently."""

def generate_hmac(message: bytes, key: bytes) -> bytes:
    """HMAC-SHA256 of message under key, for integrity checks separate from
    encryption where needed."""

def verify_hmac(message: bytes, key: bytes, mac: bytes) -> bool:
    """Constant-time HMAC verification."""

def hash_password(password: str) -> str:
    """Password hashing for storage (e.g. bcrypt/argon2) — NOT for tickets."""

def verify_password(password: str, password_hash: str) -> bool:
    """Verify a plaintext password against a stored hash."""

## Ticket structure (what AS/TGS actually encrypt)

Agree on a concrete JSON shape before coding, e.g.:

{
  "client_id": "string",
  "service_id": "string",
  "session_key": "base64",
  "issued_at": "unix_timestamp",
  "expiry": "unix_timestamp"
}

Serialize to bytes (e.g. json.dumps(...).encode()), then encrypt() that with the
appropriate shared key. Whoever decrypts it (TGS for the TGT, Service Server for the Service
Ticket) parses the JSON back out and checks expiry and issued_at (for replay/clock-skew
tolerance — see below).

## Replay & tamper protection (also Group 4, but used everywhere)

- Every ticket carries issued_at and expiry — reject if now > expiry or if issued_at
  is too far in the future/past (clock skew tolerance, e.g. ±5 minutes).
- Consider an authenticator: client sends a fresh timestamp encrypted with the session key
  alongside the ticket, so a captured ticket+authenticator pair can't be replayed after the
  authenticator's short validity window (a minute or two) even if the ticket itself is still
  "valid".
- Use verify_hmac (or authenticated encryption like AES-GCM, which gives you this for free)
  so a tampered ciphertext fails to decrypt/verify rather than silently producing wrong data.

## Deliverable order

1. Group 4 implements and shares crypto_utils.py with unit tests for each function — as early
   as possible, even before the full security module is done.
2. Groups 1, 3, 4 (AS, TGS, Core API, Service Server) import it and build tickets on top.
3. Any change to a function's signature after others depend on it → flag in the group chat
   immediately.
