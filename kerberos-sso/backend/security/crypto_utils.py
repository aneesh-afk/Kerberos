"""
Cryptography Module — Group 4 (Akshay)

Everyone imports functions from here instead of writing their own crypto.
See docs/crypto-interface.md for the full contract.
"""

import hashlib
import hmac
import os
from typing import Union

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class DecryptionError(Exception):
    """Raised when decryption fails due to invalid key, tampered ciphertext, or corrupted data."""
    pass


# Global password hasher configured for Argon2id
_password_hasher = PasswordHasher(type=Type.ID)


def generate_key() -> bytes:
    """
    Generate a secure 32-byte AES-256 key.

    Returns:
        bytes: Cryptographically secure 32 random bytes.
    """
    return os.urandom(32)


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt plaintext using AES-256-GCM under key.

    A fresh 12-byte nonce is generated for every encryption call.
    The returned byte sequence embeds the nonce, ciphertext, and 16-byte authentication tag:
    nonce (12 bytes) + ciphertext + authentication tag (16 bytes).

    Args:
        plaintext: The data to encrypt as bytes.
        key: The 32-byte AES-256 key.

    Returns:
        bytes: nonce + ciphertext + authentication tag.

    Raises:
        TypeError: If plaintext or key are not bytes.
        ValueError: If key is not exactly 32 bytes.
    """
    if not isinstance(plaintext, bytes):
        raise TypeError("Plaintext must be bytes")
    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes")
    if len(key) != 32:
        raise ValueError(f"Key must be exactly 32 bytes for AES-256, got {len(key)}")

    # AES-GCM recommended standard nonce size is 12 bytes (96 bits)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    # AESGCM.encrypt appends the 16-byte authentication tag to the ciphertext
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    return nonce + ct_with_tag


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt AES-256-GCM encrypted data under key.

    Extracts the first 12 bytes as the nonce, and uses the remaining bytes
    as ciphertext + authentication tag.

    Args:
        ciphertext: The encrypted payload (nonce + ciphertext + tag).
        key: The 32-byte AES-256 key.

    Returns:
        bytes: The decrypted plaintext.

    Raises:
        TypeError: If key is not bytes.
        ValueError: If key is not exactly 32 bytes.
        DecryptionError: If ciphertext is not bytes, is too short (< 28 bytes),
                         or has been tampered with or corrupted.
    """
    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes")
    if len(key) != 32:
        raise ValueError(f"Key must be exactly 32 bytes for AES-256, got {len(key)}")

    if not isinstance(ciphertext, bytes):
        raise DecryptionError("Ciphertext must be bytes")

    # Minimum length: 12 bytes nonce + 16 bytes tag = 28 bytes
    if len(ciphertext) < 28:
        raise DecryptionError("Ciphertext is too short to contain a valid nonce and tag")

    nonce = ciphertext[:12]
    ct_with_tag = ciphertext[12:]

    try:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ct_with_tag, associated_data=None)
    except (InvalidTag, Exception) as exc:
        raise DecryptionError("Decryption failed: tampered ciphertext or invalid key") from exc


def generate_hmac(message: bytes, key: bytes) -> bytes:
    """
    Generate an HMAC-SHA256 digest of message under key.

    Args:
        message: The message to authenticate as bytes.
        key: The secret HMAC key as bytes.

    Returns:
        bytes: 32-byte HMAC-SHA256 digest.

    Raises:
        TypeError: If message or key are not bytes.
    """
    if not isinstance(message, bytes):
        raise TypeError("Message must be bytes")
    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes")

    return hmac.new(key, message, hashlib.sha256).digest()


def verify_hmac(message: bytes, key: bytes, mac: bytes) -> bool:
    """
    Verify an HMAC-SHA256 digest in constant time.

    Args:
        message: The message bytes to verify.
        key: The secret HMAC key as bytes.
        mac: The expected MAC bytes to compare against.

    Returns:
        bool: True if mac matches the expected HMAC for message, False otherwise.
    """
    if not isinstance(message, bytes) or not isinstance(key, bytes) or not isinstance(mac, bytes):
        return False

    expected_mac = generate_hmac(message, key)
    return hmac.compare_digest(expected_mac, mac)


def hash_password(password: str) -> str:
    """
    Hash a password for secure storage using Argon2id.

    Args:
        password: The plaintext password string.

    Returns:
        str: Encoded Argon2id hash string.

    Raises:
        TypeError: If password is not a string.
    """
    if not isinstance(password, str):
        raise TypeError("Password must be a string")

    return _password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """
    Verify a plaintext password against an Argon2 hash.

    Suppresses internal exception details to avoid leaking sensitive information.

    Args:
        password: The plaintext password candidate as a string.
        password_hash: The stored Argon2 hash string.

    Returns:
        bool: True if password matches the hash, False otherwise.
    """
    if not isinstance(password, str) or not isinstance(password_hash, str):
        return False

    try:
        return _password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    except Exception:
        return False
