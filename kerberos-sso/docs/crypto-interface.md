# Crypto Interface Contract (owned by Group 4 — Sanket, Akshay)

Read this before writing any AS, TGS, Core API, or Service Server code that touches
encryption, hashing, or tickets. Everyone imports these functions from
`backend.security` (`crypto_utils.py`) instead of writing their own crypto. This is the #1 way this kind of
project breaks at integration time — don't let it happen here.

---

## 1. Cryptographic Primitives Overview

| Operation | Algorithm | Standard / Parameters | Output Format |
|---|---|---|---|
| **Symmetric Encryption** | AES-256-GCM | 256-bit key (32 bytes), 96-bit random nonce (12 bytes), 128-bit authentication tag (16 bytes) | `bytes`: `nonce (12B) + ciphertext + tag (16B)` |
| **Message Authentication** | HMAC-SHA256 | SHA-256 digest, constant-time verification | `bytes`: 32-byte raw digest |
| **Password Storage** | Argon2id | `argon2-cffi` (`Type.ID`), memory-hard, GPU/ASIC resistant | `str`: encoded Argon2id hash |

---

## 2. API Reference (`backend/security/crypto_utils.py`)

### `generate_key() -> bytes`
Generates a cryptographically secure 32-byte (256-bit) symmetric key using `os.urandom(32)`.
Used for long-term shared keys (`AS_TGS_SHARED_KEY`, `TGS_SERVICE_SHARED_KEY`) and short-term session keys embedded in tickets.

- **Returns**: `bytes` (exactly 32 bytes).

### `encrypt(plaintext: bytes, key: bytes) -> bytes`
Encrypts plaintext using **AES-256-GCM**.
Generates a fresh, unique 12-byte random nonce on every invocation to prevent nonce-reuse attacks.

- **Parameters**:
  - `plaintext`: Raw message bytes (`bytes`).
  - `key`: 32-byte AES-256 key (`bytes`).
- **Returns**: `bytes` with layout `nonce (12 bytes) + ciphertext + auth_tag (16 bytes)`.
- **Raises**:
  - `TypeError`: If `plaintext` or `key` is not `bytes`.
  - `ValueError`: If `key` length is not exactly 32 bytes.

### `decrypt(ciphertext: bytes, key: bytes) -> bytes`
Decrypts an AES-256-GCM payload previously produced by `encrypt()`.
Extracts the leading 12-byte nonce and verifies the 16-byte authentication tag in constant time.

- **Parameters**:
  - `ciphertext`: Encrypted payload (`nonce + ciphertext + tag`).
  - `key`: 32-byte AES-256 key (`bytes`).
- **Returns**: Decrypted plaintext (`bytes`).
- **Raises**:
  - `DecryptionError`: Raised when the ciphertext is not bytes, is shorter than 28 bytes, or when authentication fails due to tampering or wrong key.
  - `TypeError` / `ValueError`: If `key` is invalid or not 32 bytes.

### `generate_hmac(message: bytes, key: bytes) -> bytes`
Computes an HMAC-SHA256 message authentication code.

- **Parameters**:
  - `message`: Payload bytes (`bytes`).
  - `key`: Secret HMAC key (`bytes`).
- **Returns**: `bytes` (32-byte raw SHA-256 digest).
- **Raises**: `TypeError` if inputs are not bytes.

### `verify_hmac(message: bytes, key: bytes, mac: bytes) -> bool`
Constant-time verification of HMAC-SHA256 against timing attacks using `hmac.compare_digest()`.

- **Parameters**:
  - `message`: Original message bytes.
  - `key`: Secret HMAC key bytes.
  - `mac`: Expected MAC bytes.
- **Returns**: `bool` (`True` if valid, `False` on mismatch or invalid input).

### `hash_password(password: str) -> str`
Hashes a user password for secure storage in Group 1's database using the **Argon2id** algorithm.
**Never use this for tickets or session tokens.**

- **Parameters**:
  - `password`: Plaintext password string (`str`).
- **Returns**: Formatted Argon2id hash string (`$argon2id$...`).
- **Raises**: `TypeError` if `password` is not a string.

### `verify_password(password: str, password_hash: str) -> bool`
Verifies a candidate password against an existing Argon2 hash in constant time. Suppresses internal exception details to avoid leaking timing or verification errors.

- **Parameters**:
  - `password`: Plaintext candidate string.
  - `password_hash`: Encoded Argon2 hash string.
- **Returns**: `bool` (`True` if password matches, `False` otherwise).

---

## 3. Service Ticket Structure & Contract

The Service Ticket is issued by Group 3 (Kerberos TGS) and validated by Group 4 (Service Server).

### Concrete JSON Payload Shape:
```json
{
  "client_id": "user123",
  "service_id": "service-server",
  "session_key": "base64_encoded_32_byte_key",
  "issued_at": 1790000000,
  "expiry": 1790003600
}
```

### Required Fields:
1. `client_id` (`str`): The authenticated client's user identifier.
2. `service_id` (`str`): The identifier of the destination service (e.g. `"service-server"`).
3. `session_key` (`str`): Base64-encoded 32-byte session key for client-service secure communication.
4. `issued_at` (`int` / `float`): Unix epoch timestamp when ticket was generated.
5. `expiry` (`int` / `float`): Unix epoch timestamp after which ticket is invalid.

### Wire Format:
1. Serialize the dictionary to UTF-8 bytes: `payload_bytes = json.dumps(payload).encode("utf-8")`.
2. Encrypt using `crypto_utils.encrypt(payload_bytes, tgs_service_key)`.
3. Base64-encode the resulting ciphertext for transmission in JSON API requests: `base64.b64encode(ciphertext).decode("utf-8")`.

---

## 4. Service Server Validation & Clock Skew

The Service Server validates the incoming encrypted ticket on `POST /service/access`:

1. **Decryption**: Decrypts the Base64-decoded ciphertext using `crypto_utils.decrypt` with `TGS_SERVICE_SHARED_KEY`. Fails with HTTP 401 if tampered or invalid.
2. **Payload Parsing**: Ensures payload is valid JSON and contains all 5 required fields with proper types.
3. **Target Validation**: Ensures `service_id` matches the configured service identifier (`SERVICE_ID`, default `"service-server"`).
4. **Lifetime Validation**:
   - Rejects tickets where `expiry <= issued_at` (HTTP 401).
   - Rejects tickets where `current_time < issued_at - clock_skew` (not yet valid) (HTTP 401).
   - Rejects tickets where `current_time > expiry + clock_skew` (expired) (HTTP 401).
5. **Request Freshness**: If optional request `timestamp` is sent by the client, verifies `abs(current_time - req.timestamp) <= clock_skew`.

### Environment Configuration:
- `TGS_SERVICE_SHARED_KEY`: Base64-encoded 32-byte AES-256 key shared between TGS and Service Server.
- `KERBEROS_CLOCK_SKEW_SECONDS`: Clock skew tolerance in seconds. Default development value: `300` (5 minutes).
- `SERVICE_ID`: Service identifier. Default: `"service-server"`.

---

## 5. Security Rules

1. **Never store plaintext passwords**: All credentials in Group 1's database must be hashed with `hash_password()`.
2. **Never hard-code secret keys**: All symmetric keys (`AS_TGS_SHARED_KEY`, `TGS_SERVICE_SHARED_KEY`) must be loaded from environment variables.
3. **No Nonce Reuse**: AES-GCM generates a random 96-bit nonce per encryption. Never reuse nonces under the same key.
4. **No Custom Cryptography**: All primitives are based on standard audited implementations (`cryptography.hazmat.primitives.ciphers.aead.AESGCM`, `hashlib`, `hmac`, `argon2-cffi`).
5. **Zero Secret Leakage**: Exceptions, error messages, and logs must never output private keys, plaintext passwords, or raw cryptographic tokens.
