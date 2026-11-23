"""Symmetric primitives for envelope encryption.

Every backup gets its own 32-byte data encryption key (DEK).  The backup
payload is encrypted with AES-256-GCM under the DEK.  The DEK itself is
wrapped (encrypted) under a 32-byte master key, the key-encryption key (KEK).

All GCM nonces are 12 random bytes and prepended to the ciphertext, so a
stored secret is always ``nonce || ciphertext || tag``.
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 32
NONCE_SIZE = 12


def generate_key() -> bytes:
    """Return a fresh random 256-bit key."""
    return os.urandom(KEY_SIZE)


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Encrypt with AES-256-GCM and return ``nonce || ciphertext``."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    return nonce + aesgcm.encrypt(nonce, plaintext, aad)


def decrypt(key: bytes, stored: bytes, aad: bytes) -> bytes:
    """Inverse of :func:`encrypt`; raises ``InvalidTag`` on tampering."""
    aesgcm = AESGCM(key)
    nonce, ciphertext = stored[:NONCE_SIZE], stored[NONCE_SIZE:]
    return aesgcm.decrypt(nonce, ciphertext, aad)


def _wrap_aad(backup_id: str, kek_id: str) -> bytes:
    # Bind a wrapped DEK to both its backup and the specific KEK so a wrapped
    # blob cannot be moved between rows and accepted elsewhere.
    return b"wrapped-dek:" + backup_id.encode("ascii") + b":" + kek_id.encode("ascii")


def file_aad(backup_id: str) -> bytes:
    return b"backup-blob:" + backup_id.encode("ascii")


def wrap_dek(kek: bytes, dek: bytes, backup_id: str, kek_id: str) -> bytes:
    return encrypt(kek, dek, _wrap_aad(backup_id, kek_id))


def unwrap_dek(kek: bytes, wrapped_dek: bytes, backup_id: str, kek_id: str) -> bytes:
    return decrypt(kek, wrapped_dek, _wrap_aad(backup_id, kek_id))
