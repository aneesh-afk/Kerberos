"""
Unit tests for Cryptography Module — Group 4 (Akshay)
backend/security/crypto_utils.py
"""

import sys
from pathlib import Path
import pytest

# Ensure kerberos-sso project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.security.crypto_utils import (
    DecryptionError,
    decrypt,
    encrypt,
    generate_hmac,
    generate_key,
    hash_password,
    verify_hmac,
    verify_password,
)


# ---------------------------------------------------------------------------
# Key Generation Tests
# ---------------------------------------------------------------------------

def test_generate_key_returns_bytes():
    """Test 1: generate_key returns bytes."""
    key = generate_key()
    assert isinstance(key, bytes)


def test_generate_key_length():
    """Test 2: generated key is exactly 32 bytes (256 bits)."""
    key = generate_key()
    assert len(key) == 32


def test_generate_key_randomness():
    """Test 3: two generated keys are different."""
    key1 = generate_key()
    key2 = generate_key()
    assert key1 != key2


# ---------------------------------------------------------------------------
# Encryption / Decryption Tests
# ---------------------------------------------------------------------------

def test_encrypt_decrypt_roundtrip():
    """Test 4: encrypt/decrypt round trip works."""
    key = generate_key()
    plaintext = b"Kerberos Service Ticket Payload: user123"
    ciphertext = encrypt(plaintext, key)
    decrypted = decrypt(ciphertext, key)
    assert decrypted == plaintext


def test_encrypt_fresh_nonce_different_ciphertext():
    """Test 5: encrypting the same plaintext twice produces different ciphertext because of a fresh nonce."""
    key = generate_key()
    plaintext = b"Secret message for session"
    ciphertext1 = encrypt(plaintext, key)
    ciphertext2 = encrypt(plaintext, key)
    assert ciphertext1 != ciphertext2
    # Verify both still decrypt to the original plaintext
    assert decrypt(ciphertext1, key) == plaintext
    assert decrypt(ciphertext2, key) == plaintext


def test_tampered_ciphertext_rejected():
    """Test 6: tampered ciphertext is rejected with DecryptionError."""
    key = generate_key()
    plaintext = b"Important authorization payload"
    ciphertext = bytearray(encrypt(plaintext, key))

    # Tamper with the last byte (part of authentication tag)
    ciphertext[-1] ^= 0xFF
    with pytest.raises(DecryptionError):
        decrypt(bytes(ciphertext), key)

    # Tamper with nonce (first 12 bytes)
    ciphertext2 = bytearray(encrypt(plaintext, key))
    ciphertext2[0] ^= 0x01
    with pytest.raises(DecryptionError):
        decrypt(bytes(ciphertext2), key)

    # Tamper with ciphertext payload body
    ciphertext3 = bytearray(encrypt(plaintext, key))
    ciphertext3[15] ^= 0x55
    with pytest.raises(DecryptionError):
        decrypt(bytes(ciphertext3), key)


def test_decrypt_with_wrong_key_rejected():
    """Decryption with a different key must raise DecryptionError."""
    key1 = generate_key()
    key2 = generate_key()
    plaintext = b"Confidential data"
    ciphertext = encrypt(plaintext, key1)
    with pytest.raises(DecryptionError):
        decrypt(ciphertext, key2)


def test_encrypt_decrypt_invalid_inputs():
    """Validate invalid types and key lengths for encrypt and decrypt."""
    key = generate_key()

    # Plaintext must be bytes
    with pytest.raises(TypeError):
        encrypt("not bytes", key)  # type: ignore

    # Key must be bytes
    with pytest.raises(TypeError):
        encrypt(b"data", "not bytes key")  # type: ignore

    # Key must be 32 bytes
    with pytest.raises(ValueError):
        encrypt(b"data", b"too_short_key_16b")

    with pytest.raises(ValueError):
        decrypt(b"dummy_ciphertext_28_bytes_minimum_here!!", b"short_key")

    # Ciphertext too short (< 28 bytes)
    with pytest.raises(DecryptionError):
        decrypt(b"too_short", key)

    # Ciphertext not bytes
    with pytest.raises(DecryptionError):
        decrypt("not bytes", key)  # type: ignore


# ---------------------------------------------------------------------------
# HMAC Tests
# ---------------------------------------------------------------------------

def test_generate_hmac_returns_32_bytes():
    """Test 7: generate_hmac returns a 32-byte SHA-256 HMAC."""
    key = generate_key()
    message = b"Authenticated ticket header"
    mac = generate_hmac(message, key)
    assert isinstance(mac, bytes)
    assert len(mac) == 32


def test_verify_hmac_valid():
    """Test 8: verify_hmac returns True for valid MAC."""
    key = generate_key()
    message = b"Unaltered transaction request"
    mac = generate_hmac(message, key)
    assert verify_hmac(message, key, mac) is True


def test_verify_hmac_modified_message():
    """Test 9: verify_hmac returns False for modified message."""
    key = generate_key()
    message = b"Original request"
    modified_message = b"Tampered request"
    mac = generate_hmac(message, key)
    assert verify_hmac(modified_message, key, mac) is False


def test_verify_hmac_tampered_mac_and_wrong_key():
    """verify_hmac returns False for altered MAC, wrong key, or wrong types."""
    key1 = generate_key()
    key2 = generate_key()
    message = b"Safe message"
    mac = generate_hmac(message, key1)

    # Wrong key
    assert verify_hmac(message, key2, mac) is False

    # Tampered MAC
    tampered_mac = bytearray(mac)
    tampered_mac[0] ^= 0xFF
    assert verify_hmac(message, key1, bytes(tampered_mac)) is False

    # Invalid input types
    assert verify_hmac("not bytes", key1, mac) is False  # type: ignore
    assert verify_hmac(message, "not bytes", mac) is False  # type: ignore
    assert verify_hmac(message, key1, "not bytes") is False  # type: ignore


# ---------------------------------------------------------------------------
# Password Hashing Tests
# ---------------------------------------------------------------------------

def test_password_hashing_not_equal_plaintext():
    """Test 10: password hashing does not equal plaintext and uses Argon2id."""
    password = "SuperSecretPassword123!"
    p_hash = hash_password(password)
    assert isinstance(p_hash, str)
    assert p_hash != password
    assert "$argon2id$" in p_hash


def test_verify_password_correct():
    """Test 11: correct password verifies successfully."""
    password = "CorrectHorseBatteryStaple"
    p_hash = hash_password(password)
    assert verify_password(password, p_hash) is True


def test_verify_password_wrong():
    """Test 12: wrong password fails verification."""
    password = "MyActualPassword"
    wrong_password = "WrongPasswordGuess"
    p_hash = hash_password(password)
    assert verify_password(wrong_password, p_hash) is False


def test_verify_password_invalid_hash_and_types():
    """verify_password returns False for malformed hashes and invalid types."""
    assert verify_password("password", "invalid$argon$hash") is False
    assert verify_password("password", "") is False
    assert verify_password(12345, "some_hash") is False  # type: ignore
    assert verify_password("password", None) is False  # type: ignore

    with pytest.raises(TypeError):
        hash_password(b"bytes_password")  # type: ignore
