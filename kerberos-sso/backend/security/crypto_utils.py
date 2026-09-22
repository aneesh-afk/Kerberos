"""
Cryptography Module — Group 4 (Akshay)

Everyone imports functions from here instead of writing their own crypto.
See docs/crypto-interface.md for the full contract.
"""

def generate_key() -> bytes:
    """Generate a new symmetric key (AES-256)."""
    pass

def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES encryption (e.g. AES-GCM) of plaintext under key."""
    pass

def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Inverse of encrypt()."""
    pass

def generate_hmac(message: bytes, key: bytes) -> bytes:
    """HMAC-SHA256 of message under key."""
    pass

def verify_hmac(message: bytes, key: bytes, mac: bytes) -> bool:
    """Constant-time HMAC verification."""
    pass

def hash_password(password: str) -> str:
    """Password hashing for storage (e.g. bcrypt/argon2)."""
    pass

def verify_password(password: str, password_hash: str) -> bool:
    """Verify a plaintext password against a stored hash."""
    pass
